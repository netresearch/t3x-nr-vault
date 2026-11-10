<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Hook;

use Netresearch\NrVault\Hook\DataHandlerHook;
use Netresearch\NrVault\Hook\FlexFormVaultHook;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Throwable;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * A hard delete of a record that holds a vault secret in a plain TCA field and
 * another in a FlexForm field, driven through a real DataHandler.
 *
 * The plain-field hook deletes its secrets before core runs the delete, the
 * FlexForm hook while core runs it. Every reference of the record therefore
 * has to pass the preflight before the first secret goes: otherwise a refused
 * FlexForm reference keeps the record, which then points at a plain secret
 * that is already gone (#471).
 */
#[CoversClass(DataHandlerHook::class)]
#[CoversClass(FlexFormVaultHook::class)]
final class RecordDeletePreflightTest extends AbstractVaultFunctionalTestCase
{
    private const TABLE = 'tx_nrvaulttest_mixed';

    /** @var list<string> */
    protected array $testExtensionsToLoad = ['netresearch/nr-vault', __DIR__ . '/../Fixtures/Extensions/nr_vault_test'];

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'securityProfile'      => 'hardened',
        'masterKeyProvider'    => 'file',
        'disableAdminOverride' => 1,
    ];

    #[Test]
    public function aRefusedFlexFormReferenceKeepsThePlainSecretAndTheRecord(): void
    {
        $this->grantDeleteOperation();
        $plain = $this->seedSecret(1);
        $flex  = $this->seedSecret(2);
        $uid   = $this->seedRecord($plain, $this->flexValue($flex));

        self::assertNull($this->runCoreDelete($uid));

        self::assertSame(
            ['plain' => 0, 'flex' => 0, 'record' => 1],
            [
                'plain'  => $this->secretDeletedFlag($plain),
                'flex'   => $this->secretDeletedFlag($flex),
                'record' => $this->recordCount($uid),
            ],
            'A refusal of any reference must leave every secret and the record in place.',
        );
        self::assertSame(1, $this->auditCount(['secret_identifier' => $flex, 'action' => 'access_denied', 'success' => 0]));
        self::assertSame(0, $this->auditCount(['action' => 'delete', 'success' => 1]));
    }

    /**
     * A FlexForm value whose vault positions cannot be located is a discovery
     * failure, which refuses the delete like a denied reference does.
     */
    #[Test]
    public function anUnlocatableFlexFormReferenceKeepsThePlainSecretAndTheRecord(): void
    {
        $this->grantDeleteOperation();
        $plain = $this->seedSecret(1);
        $flex  = $this->seedSecret(1);
        $uid   = $this->seedRecord($plain, '<T3FlexForms><data><broken ' . $flex);

        self::assertNull($this->runCoreDelete($uid));

        self::assertSame(
            ['plain' => 0, 'flex' => 0, 'record' => 1],
            [
                'plain'  => $this->secretDeletedFlag($plain),
                'flex'   => $this->secretDeletedFlag($flex),
                'record' => $this->recordCount($uid),
            ],
        );
        self::assertSame(0, $this->auditCount(['action' => 'delete', 'success' => 1]));
    }

    /**
     * The other direction of the same preflight: when every reference may be
     * deleted, both secrets go with the record.
     */
    #[Test]
    public function aPermittedDeleteRemovesBothSecretsAndTheRecord(): void
    {
        $this->grantDeleteOperation();
        $plain = $this->seedSecret(1);
        $flex  = $this->seedSecret(1);
        $uid   = $this->seedRecord($plain, $this->flexValue($flex));

        self::assertNull($this->runCoreDelete($uid));

        self::assertSame(
            ['plain' => 1, 'flex' => 1, 'record' => 0],
            [
                'plain'  => $this->secretDeletedFlag($plain),
                'flex'   => $this->secretDeletedFlag($flex),
                'record' => $this->recordCount($uid),
            ],
        );
        self::assertSame(2, $this->auditCount(['action' => 'delete', 'success' => 1]));
        self::assertSame(0, $this->auditCount(['action' => 'access_denied']));
    }

    /**
     * A refused plain reference already kept everything before; it still
     * must, now that the FlexForm references join the same preflight.
     */
    #[Test]
    public function aRefusedPlainReferenceKeepsTheFlexFormSecretAndTheRecord(): void
    {
        $this->grantDeleteOperation();
        $plain = $this->seedSecret(2);
        $flex  = $this->seedSecret(1);
        $uid   = $this->seedRecord($plain, $this->flexValue($flex));

        self::assertNull($this->runCoreDelete($uid));

        self::assertSame(
            ['plain' => 0, 'flex' => 0, 'record' => 1],
            [
                'plain'  => $this->secretDeletedFlag($plain),
                'flex'   => $this->secretDeletedFlag($flex),
                'record' => $this->recordCount($uid),
            ],
        );
        self::assertSame(1, $this->auditCount(['secret_identifier' => $plain, 'action' => 'access_denied', 'success' => 0]));
        self::assertSame(0, $this->auditCount(['action' => 'delete', 'success' => 1]));
    }

    private function flexValue(string $identifier): string
    {
        return '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF"><field index="apiKey"><value index="vDEF">'
            . $identifier
            . '</value></field></language></sheet></data></T3FlexForms>';
    }

    private function seedRecord(string $plainIdentifier, string $flexValue): int
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::TABLE);
        $connection->insert(
            self::TABLE,
            [
                'pid'      => 0,
                'title'    => 'Synthetic mixed record',
                'api_key'  => $plainIdentifier,
                'settings' => $flexValue,
            ],
        );

        return (int) $connection->lastInsertId();
    }

    private function seedSecret(int $owner): string
    {
        $id = $this->generateUuidV7();
        $this
            ->getConnectionPool()
            ->getConnectionForTable('tx_nrvault_secret')
            ->insert(
                'tx_nrvault_secret',
                [
                    'pid'        => 0,
                    'identifier' => $id,
                    'owner_uid'  => $owner,
                    'deleted'    => 0,
                ],
            );

        return $id;
    }

    private function grantDeleteOperation(): void
    {
        $pool = $this->getConnectionPool();
        $pool
            ->getConnectionForTable('be_groups')
            ->insert(
                'be_groups',
                [
                    'uid'            => 21,
                    'pid'            => 0,
                    'title'          => 'Synthetic vault deleters',
                    'custom_options' => 'tx_nrvault:secret.delete',
                ],
            );
        $pool
            ->getConnectionForTable('be_users')
            ->update('be_users', ['usergroup' => '21'], ['uid' => 1]);
        $this->setUpBackendUser(1);
    }

    private function runCoreDelete(int $uid): ?Throwable
    {
        $GLOBALS['LANG'] = $this
            ->get(LanguageServiceFactory::class)
            ->createFromUserPreferences(null);
        $handler = GeneralUtility::makeInstance(DataHandler::class);
        $handler->start([], [self::TABLE => [$uid => ['delete' => 1]]]);

        try {
            $handler->process_cmdmap();
        } catch (Throwable $failure) {
            return $failure;
        }

        return null;
    }

    private function recordCount(int $uid): int
    {
        return $this->getConnectionPool()->getConnectionForTable(self::TABLE)->count('*', self::TABLE, ['uid' => $uid]);
    }

    /**
     * @param array<string, int|string> $criteria
     */
    private function auditCount(array $criteria): int
    {
        return $this
            ->getConnectionPool()
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->count('*', 'tx_nrvault_audit_log', $criteria);
    }

    private function secretDeletedFlag(string $identifier): int
    {
        $value = $this
            ->getConnectionPool()
            ->getConnectionForTable('tx_nrvault_secret')
            ->fetchOne(
                'SELECT deleted FROM tx_nrvault_secret WHERE identifier = ?',
                [$identifier],
            );
        self::assertIsNumeric($value, 'Native row state must be observed without enable-field restrictions.');

        return (int) $value;
    }
}
