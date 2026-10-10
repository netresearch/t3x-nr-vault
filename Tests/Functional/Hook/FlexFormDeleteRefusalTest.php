<?php

/* Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Hook;

use Netresearch\NrVault\Hook\FlexFormVaultHook;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Throwable;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;
use TYPO3\CMS\Core\Utility\GeneralUtility;

#[CoversClass(FlexFormVaultHook::class)]
final class FlexFormDeleteRefusalTest extends AbstractVaultFunctionalTestCase
{
    /** @var list<string> */
    protected array $testExtensionsToLoad = ['netresearch/nr-vault', __DIR__ . '/../Fixtures/Extensions/nr_vault_test'];

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'securityProfile' => 'hardened',
        'masterKeyProvider' => 'file',
        'disableAdminOverride' => 1,
    ];

    #[Test]
    public function realCoreCannotRemoveARecordAfterItsFlexSecretDeleteIsDenied(): void
    {
        $identifier = $this->generateUuidV7();
        $pool = $this->getConnectionPool();
        $secretConnection = $pool->getConnectionForTable('tx_nrvault_secret');
        $secretConnection->insert(
            'tx_nrvault_secret',
            [
                'pid' => 0,
                'identifier' => $identifier,
                'owner_uid' => 2,
                'deleted' => 0,
            ],
        );
        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF">' . '<field index="apiKey"><value index="vDEF">' . $identifier . '</value></field></language></sheet></data></T3FlexForms>';
        $recordConnection = $pool->getConnectionForTable('tx_nrvaulttest_flex');
        $recordConnection->insert(
            'tx_nrvaulttest_flex',
            [
                'pid' => 0,
                'title' => 'Synthetic denied FlexForm record',
                'settings' => $xml,
            ],
        );
        $uid = (int) $recordConnection->lastInsertId();
        $GLOBALS['LANG'] = $this
            ->get(LanguageServiceFactory::class)
            ->createFromUserPreferences(null);
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [],
            ['tx_nrvaulttest_flex' => [$uid => ['delete' => 1]]],
        );
        $caught = null;

        try {
            $dataHandler->process_cmdmap();
        } catch (Throwable $failure) {
            $caught = $failure;
        }

        self::assertNull(
            $caught,
            'The editor must receive the refusal through the existing diagnostic channel.',
        );
        self::assertTrue(
            $this->get(VaultServiceInterface::class)->exists($identifier),
        );
        self::assertSame(
            1,
            $pool
                ->getConnectionForTable('tx_nrvault_audit_log')
                ->count(
                    '*',
                    'tx_nrvault_audit_log',
                    [
                        'secret_identifier' => $identifier,
                        'action' => 'access_denied',
                        'success' => 0,
                    ],
                ),
            'The real vault gate, rather than Core table permissions, must refuse this delete.',
        );
        self::assertSame(
            1,
            $recordConnection->count(
                '*',
                'tx_nrvaulttest_flex',
                ['uid' => $uid],
            ),
            'The real Core record must survive while its secret survives a denied delete.',
        );
    }

    #[Test]
    public function deniedSecondSecretDoesNotDeleteTheFirstPermittedSecret(): void
    {
        $this->grantDeleteOperation();
        $first = $this->seedSecret(1);
        $second = $this->seedSecret(2);
        $uid = $this->seedRecord([$first, $second]);
        self::assertNull($this->runCoreDelete($uid));
        self::assertTrue(
            $this->get(VaultServiceInterface::class)->exists($first),
        );
        self::assertTrue(
            $this->get(VaultServiceInterface::class)->exists($second),
        );
        self::assertSame(
            1,
            $this
                ->getConnectionPool()
                ->getConnectionForTable('tx_nrvaulttest_flex')
                ->count('*', 'tx_nrvaulttest_flex', ['uid' => $uid]),
        );
        self::assertSame(
            1,
            $this
                ->getConnectionPool()
                ->getConnectionForTable('tx_nrvault_audit_log')
                ->count(
                    '*',
                    'tx_nrvault_audit_log',
                    [
                        'secret_identifier' => $second,
                        'action' => 'access_denied',
                        'success' => 0,
                    ],
                ),
        );
        self::assertSame(
            0,
            $this
                ->getConnectionPool()
                ->getConnectionForTable('tx_nrvault_audit_log')
                ->count(
                    '*',
                    'tx_nrvault_audit_log',
                    ['action' => 'delete', 'success' => 1],
                ),
        );
    }

    #[Test]
    public function permittedCoreDeleteRemovesUniqueActiveSecretReferences(): void
    {
        $this->grantDeleteOperation();
        $first = $this->seedSecret(1);
        $second = $this->seedSecret(1);
        $uid = $this->seedRecord([$first, $second, $first]);
        self::assertNull($this->runCoreDelete($uid));
        self::assertFalse(
            $this->get(VaultServiceInterface::class)->exists($first),
        );
        self::assertSame(
            1,
            (int) $this
                ->getConnectionPool()
                ->getConnectionForTable('tx_nrvault_secret')
                ->fetchOne(
                    'SELECT deleted FROM tx_nrvault_secret WHERE identifier = ?',
                    [$second],
                ),
            'The second reference must actually be deleted in storage.',
        );
        self::assertSame(
            0,
            $this
                ->getConnectionPool()
                ->getConnectionForTable('tx_nrvaulttest_flex')
                ->count('*', 'tx_nrvaulttest_flex', ['uid' => $uid]),
        );
        self::assertSame(
            2,
            $this
                ->getConnectionPool()
                ->getConnectionForTable('tx_nrvault_audit_log')
                ->count(
                    '*',
                    'tx_nrvault_audit_log',
                    ['action' => 'delete', 'success' => 1],
                ),
        );
        self::assertSame(
            0,
            $this
                ->getConnectionPool()
                ->getConnectionForTable('tx_nrvault_audit_log')
                ->count('*', 'tx_nrvault_audit_log', ['action' => 'access_denied']),
        );
    }

    #[Test]
    public function sharedIdentitySurvivesWhenTheDeletingRecordRepeatsItInAnotherFlexColumn(): void
    {
        $this->grantDeleteOperation();
        $identifier = $this->seedSecret(1);
        $uid = $this->seedRecord([$identifier]);
        $otherUid = $this->seedRecord([$identifier]);
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvaulttest_flex');
        $xml = $connection->fetchOne(
            'SELECT settings FROM tx_nrvaulttest_flex WHERE uid = ?',
            [$uid],
        );
        self::assertIsString($xml);
        $connection->update(
            'tx_nrvaulttest_flex',
            ['settings_extra' => $xml],
            ['uid' => $uid],
        );
        self::assertNull($this->runCoreDelete($uid));
        self::assertSame(
            0,
            (int) $this
                ->getConnectionPool()
                ->getConnectionForTable('tx_nrvault_secret')
                ->fetchOne(
                    'SELECT deleted FROM tx_nrvault_secret WHERE identifier = ?',
                    [$identifier],
                ),
            'The native row must stay available to the other live record.',
        );
        self::assertSame(
            0,
            $connection->count('*', 'tx_nrvaulttest_flex', ['uid' => $uid]),
        );
        self::assertSame(
            1,
            $connection->count('*', 'tx_nrvaulttest_flex', ['uid' => $otherUid]),
        );
        self::assertTrue(
            $this->get(VaultServiceInterface::class)->exists($identifier),
        );
        self::assertSame(
            0,
            $this
                ->getConnectionPool()
                ->getConnectionForTable('tx_nrvault_audit_log')
                ->count(
                    '*',
                    'tx_nrvault_audit_log',
                    ['secret_identifier' => $identifier, 'action' => 'delete'],
                ),
        );
    }

    private function grantDeleteOperation(): void
    {
        $pool = $this->getConnectionPool();
        $pool
            ->getConnectionForTable('be_groups')
            ->insert(
                'be_groups',
                [
                    'uid' => 21,
                    'pid' => 0,
                    'title' => 'Synthetic vault deleters',
                    'custom_options' => 'tx_nrvault:secret.delete',
                ],
            );
        $pool
            ->getConnectionForTable('be_users')
            ->update('be_users', ['usergroup' => '21'], ['uid' => 1]);
        $this->setUpBackendUser(1);
    }

    private function seedSecret(int $owner, bool $disabled = false): string
    {
        $id = $this->generateUuidV7();
        $this
            ->getConnectionPool()
            ->getConnectionForTable('tx_nrvault_secret')
            ->insert(
                'tx_nrvault_secret',
                [
                    'pid' => 0,
                    'identifier' => $id,
                    'owner_uid' => $owner,
                    'deleted' => 0,
                    'hidden' => $disabled ? 1 : 0,
                ],
            );

        return $id;
    }

    /**
     * @param list<string> $identifiers
     */
    private function seedRecord(array $identifiers): int
    {
        $fields = '';
        foreach ($identifiers as $index => $identifier) {
            $fields .= '<field index="apiKey' . $index . '"><value index="vDEF">' . $identifier . '</value></field>';
        }

        $xml = '<T3FlexForms><data><sheet index="sDEF"><language index="lDEF">' . $fields . '</language></sheet></data></T3FlexForms>';
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvaulttest_flex');
        $connection->insert(
            'tx_nrvaulttest_flex',
            [
                'pid' => 0,
                'title' => 'Synthetic lifecycle record',
                'settings' => $xml,
            ],
        );

        return (int) $connection->lastInsertId();
    }

    private function runCoreDelete(int $uid): ?Throwable
    {
        $GLOBALS['LANG'] = $this
            ->get(LanguageServiceFactory::class)
            ->createFromUserPreferences(null);
        $handler = GeneralUtility::makeInstance(DataHandler::class);
        $handler->start(
            [],
            ['tx_nrvaulttest_flex' => [$uid => ['delete' => 1]]],
        );

        try {
            $handler->process_cmdmap();
        } catch (Throwable $failure) {
            return $failure;
        }

        return null;
    }
}
