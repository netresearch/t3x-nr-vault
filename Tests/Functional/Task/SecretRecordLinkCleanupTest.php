<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Task;

use Netresearch\NrVault\Command\VaultCleanupOrphansCommand;
use Netresearch\NrVault\Domain\Dto\SecretRecordLink;
use Netresearch\NrVault\Hook\DataHandlerHook;
use Netresearch\NrVault\Hook\FlexFormVaultHook;
use Netresearch\NrVault\Service\OrphanReferenceChecker;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Task\OrphanCleanupTask;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Utility\GeneralUtility;

use function json_decode;
use function json_encode;

/**
 * Orphan cleanup against secrets created the way production creates them:
 * through DataHandler and the vault field hooks, not through hand-written
 * `store()` options (#565).
 *
 * The orphan state is produced the way it arises in practice: the record row
 * disappears without DataHandler (a hard delete by SQL, a dropped extension
 * table, a published workspace version), so the hook that deletes a secret
 * together with its record never runs.
 */
#[CoversClass(OrphanCleanupTask::class)]
#[CoversClass(VaultCleanupOrphansCommand::class)]
#[CoversClass(OrphanReferenceChecker::class)]
#[CoversClass(DataHandlerHook::class)]
#[CoversClass(FlexFormVaultHook::class)]
final class SecretRecordLinkCleanupTest extends AbstractVaultFunctionalTestCase
{
    private const TABLE = 'tx_nrvaulttest_record';

    private const FLEX_TABLE = 'tx_nrvaulttest_flex';

    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/nr_vault_test',
    ];

    /** @var list<string> */
    protected array $coreExtensionsToLoad = ['backend', 'frontend', 'scheduler'];

    protected ?string $backendUserFixture = __DIR__ . '/../Hook/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    protected function setUp(): void
    {
        parent::setUp();

        $this->importCSVDataSet(__DIR__ . '/../Hook/Fixtures/pages.csv');
    }

    #[Test]
    public function aTcaFieldSecretStoresItsRecordLinkUnderMetadata(): void
    {
        $uid        = $this->createRecord('link-' . bin2hex(random_bytes(8)));
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        self::assertSame(
            ['source' => 'tca_field', 'table' => self::TABLE, 'field' => 'api_key', 'uid' => $uid],
            $this->storedMetadata($identifier),
        );
    }

    #[Test]
    public function theTaskDeletesATcaFieldSecretWhoseRecordIsGone(): void
    {
        $uid        = $this->createRecord('orphan-' . bin2hex(random_bytes(8)));
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->hardDeleteRow(self::TABLE, $uid);
        $this->runTask();

        self::assertFalse(
            $this->get(VaultServiceInterface::class)->exists($identifier),
            'A TCA field secret whose record is gone must be found and deleted by the cleanup task',
        );
    }

    #[Test]
    public function theCommandDeletesATcaFieldSecretWhoseRecordIsGone(): void
    {
        $uid        = $this->createRecord('orphan-cli-' . bin2hex(random_bytes(8)));
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->hardDeleteRow(self::TABLE, $uid);

        $tester = new CommandTester(new VaultCleanupOrphansCommand(
            $this->get(VaultServiceInterface::class),
            $this->get(ConnectionPool::class),
        ));
        $tester->setInputs(['yes']);
        $tester->execute([]);

        self::assertFalse(
            $this->get(VaultServiceInterface::class)->exists($identifier),
            'A TCA field secret whose record is gone must be found and deleted by vault:cleanup-orphans. Output: ' . $tester->getDisplay(),
        );
    }

    #[Test]
    public function theTaskKeepsATcaFieldSecretWhoseRecordExists(): void
    {
        $plaintext  = 'kept-' . bin2hex(random_bytes(8));
        $uid        = $this->createRecord($plaintext);
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->runTask();

        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier));
    }

    /**
     * A secret is an orphan only when its linked record is gone. A record
     * that still exists keeps its secret even when its field no longer holds
     * the identifier (an editor or a script overwrote it): the cleanup does
     * not read the field (#565).
     */
    #[Test]
    public function theTaskKeepsTheSecretOfARecordWhoseFieldWasDamaged(): void
    {
        $plaintext  = 'damaged-' . bin2hex(random_bytes(8));
        $uid        = $this->createRecord($plaintext);
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->getConnectionPool()->getConnectionForTable(self::TABLE)->update(self::TABLE, ['api_key' => 'overwritten'], ['uid' => $uid]);
        $this->runTask();

        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier));
    }

    #[Test]
    public function theCommandKeepsTheSecretOfARecordWhoseFieldWasDamaged(): void
    {
        $plaintext  = 'damaged-cli-' . bin2hex(random_bytes(8));
        $uid        = $this->createRecord($plaintext);
        $identifier = $this->fetchField(self::TABLE, $uid, 'api_key');

        $this->getConnectionPool()->getConnectionForTable(self::TABLE)->update(self::TABLE, ['api_key' => 'overwritten'], ['uid' => $uid]);
        $this->backdateSecrets();

        $tester = new CommandTester(new VaultCleanupOrphansCommand(
            $this->get(VaultServiceInterface::class),
            $this->get(ConnectionPool::class),
        ));
        $tester->setInputs(['yes']);
        $tester->execute([]);

        self::assertSame($plaintext, $this->get(VaultServiceInterface::class)->retrieve($identifier), $tester->getDisplay());
    }

    #[Test]
    public function theTaskDeletesAFlexFormSecretWhoseRecordIsGone(): void
    {
        $uid        = $this->createFlexRecord('flex-orphan-' . bin2hex(random_bytes(8)));
        $identifier = $this->flexIdentifier($uid);

        self::assertSame(
            ['source' => 'flexform_field', 'table' => self::FLEX_TABLE, 'flexField' => 'settings', 'uid' => $uid],
            array_intersect_key($this->storedMetadata($identifier), ['source' => 0, 'table' => 0, 'flexField' => 0, 'uid' => 0]),
        );

        $this->hardDeleteRow(self::FLEX_TABLE, $uid);
        $this->runTask();

        self::assertFalse($this->get(VaultServiceInterface::class)->exists($identifier));
    }

    /**
     * A table that does not exist (an uninstalled extension, a table on
     * another connection that is not configured) proves nothing about the
     * record: the secret stays.
     */
    #[Test]
    public function theCommandKeepsASecretWhoseLinkNamesAnUnknownTable(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier   = $this->generateUuidV7();
        $vaultService->store($identifier, 'unknown-table', [
            'metadata' => SecretRecordLink::forField(SecretRecordLink::SOURCE_TCA_FIELD, 'tx_no_such_table', 'api_key', 1),
        ]);

        $tester = new CommandTester(new VaultCleanupOrphansCommand($vaultService, $this->get(ConnectionPool::class)));
        $tester->setInputs(['yes']);
        $tester->execute([]);

        self::assertTrue($vaultService->exists($identifier), $tester->getDisplay());
    }

    private function createRecord(string $apiKey): int
    {
        return $this->runDataHandler(self::TABLE, [
            'pid'     => 1,
            'title'   => 'Linked record',
            'api_key' => $apiKey,
        ]);
    }

    private function createFlexRecord(string $plaintext): int
    {
        return $this->runDataHandler(self::FLEX_TABLE, [
            'pid'      => 1,
            'title'    => 'Linked FlexForm record',
            'settings' => [
                'data' => [
                    'sDEF' => [
                        'lDEF' => [
                            'apiKey' => [
                                'vDEF' => [
                                    'value'             => $plaintext,
                                    '_vault_identifier' => '',
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ]);
    }

    /**
     * Create one record through DataHandler and return its uid.
     *
     * @param array<string, mixed> $record
     */
    private function runDataHandler(string $table, array $record): int
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start([$table => ['NEW1' => $record]], []);
        $dataHandler->process_datamap();

        $uid = $dataHandler->substNEWwithIDs['NEW1'] ?? null;
        self::assertIsInt($uid);

        return $uid;
    }

    private function runTask(): void
    {
        $this->backdateSecrets();

        $task = new OrphanCleanupTask(
            $this->get(ConnectionPool::class),
            $this->get(VaultServiceInterface::class),
        );
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);

        self::assertTrue($task->execute());
    }

    /**
     * The secrets were created a moment ago; the cleanup only deletes what is
     * older than the retention cutoff (0 days = now).
     */
    private function backdateSecrets(): void
    {
        $this->getConnectionPool()->getConnectionForTable('tx_nrvault_secret')->update(
            'tx_nrvault_secret',
            ['crdate' => time() - 86400],
            [],
        );
    }

    private function hardDeleteRow(string $table, int $uid): void
    {
        $this->getConnectionPool()->getConnectionForTable($table)->delete($table, ['uid' => $uid], [Connection::PARAM_INT]);
    }

    private function fetchField(string $table, int $uid, string $field): string
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $value = $queryBuilder
            ->select($field)
            ->from($table)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();
        self::assertIsString($value);
        self::assertNotSame('', $value);

        return $value;
    }

    private function flexIdentifier(int $uid): string
    {
        $xml = $this->fetchField(self::FLEX_TABLE, $uid, 'settings');
        self::assertSame(1, preg_match('/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/', $xml, $match), 'FlexForm must hold a vault identifier: ' . $xml);

        return $match[0];
    }

    /**
     * @return array<string, mixed>
     */
    private function storedMetadata(string $identifier): array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tx_nrvault_secret');
        $queryBuilder->getRestrictions()->removeAll();

        $raw = $queryBuilder
            ->select('metadata')
            ->from('tx_nrvault_secret')
            ->where($queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)))
            ->executeQuery()
            ->fetchOne();
        self::assertIsString($raw, 'Secret ' . $identifier . ' not found');

        $metadata = json_decode($raw, true);
        self::assertIsArray($metadata, 'metadata is not a JSON object: ' . json_encode($raw));

        $typed = [];
        foreach ($metadata as $key => $value) {
            $typed[(string) $key] = $value;
        }

        return $typed;
    }
}
