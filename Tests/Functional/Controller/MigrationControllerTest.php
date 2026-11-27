<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Types;
use Netresearch\NrVault\Controller\MigrationController;
use Netresearch\NrVault\Domain\Dto\MigrationResult;
use Netresearch\NrVault\Service\FieldValueMigrator;
use Netresearch\NrVault\Service\FieldValueMigratorInterface;
use Netresearch\NrVault\Service\SecretDetectionServiceInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Utility\IdentifierValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Functional tests for MigrationController.
 *
 * Tests the backend module controller for secret detection and migration.
 * These tests verify that the controller's dependencies are properly configured.
 */
#[CoversClass(MigrationController::class)]
#[CoversClass(FieldValueMigrator::class)]
final class MigrationControllerTest extends AbstractVaultFunctionalTestCase
{
    private const FIXTURE_TABLE = 'tx_nrvault_test_migration';

    private const FIXTURE_COLUMN = 'secret_value';

    protected ?string $backendUserFixture = __DIR__ . '/../Hook/Fixtures/be_users.csv';

    protected function tearDown(): void
    {
        if (isset($GLOBALS['TYPO3_CONF_VARS'])) {
            $schemaManager = $this->get(ConnectionPool::class)
                ->getConnectionForTable(self::FIXTURE_TABLE)
                ->createSchemaManager();
            if ($schemaManager->tablesExist([self::FIXTURE_TABLE])) {
                $schemaManager->dropTable(self::FIXTURE_TABLE);
            }
        }

        parent::tearDown();
    }

    #[Test]
    public function secretDetectionServiceIsInjectable(): void
    {
        $detectionService = $this->get(SecretDetectionServiceInterface::class);

        self::assertInstanceOf(SecretDetectionServiceInterface::class, $detectionService);
    }

    #[Test]
    public function secretDetectionServiceCanScanWithNoResults(): void
    {
        $detectionService = $this->get(SecretDetectionServiceInterface::class);

        // With a clean database, scan should return empty results
        $findings = $detectionService->scan();

        self::assertIsArray($findings);
    }

    #[Test]
    public function secretDetectionServiceCountsDetectedSecrets(): void
    {
        $detectionService = $this->get(SecretDetectionServiceInterface::class);

        // First scan to populate findings
        $detectionService->scan();

        // Count should be 0 or more
        $count = $detectionService->getDetectedSecretsCount();

        self::assertGreaterThanOrEqual(0, $count);
    }

    #[Test]
    public function secretDetectionServiceGroupsBySeverity(): void
    {
        $detectionService = $this->get(SecretDetectionServiceInterface::class);

        // First scan to populate findings
        $detectionService->scan();

        // Get grouped findings
        $grouped = $detectionService->getDetectedSecretsBySeverity();

        self::assertIsArray($grouped);
    }

    /**
     * End-to-end migration: a plaintext column value is stored in the vault and
     * the column is rewritten to a VALID vault identifier.
     *
     * This is the regression guard for the `{{uid}}` double-brace bug in the
     * configure step (`MigrationController::configureAction`): the migration
     * substitutes `{uid}` in the identifier pattern via `str_replace`. A
     * double-brace pattern (`table__column__{{uid}}`) leaves literal braces
     * after substitution, which `IdentifierValidator` rejects — so
     * `VaultService::store()` throws and EVERY column migration fails. Here we
     * drive the (private) `migrateColumn` with the single-brace pattern the
     * fixed controller produces and assert the secret is actually stored and
     * the column now holds a syntactically valid identifier.
     */
    #[Test]
    public function migrateColumnStoresSecretAndRewritesColumnWithValidIdentifier(): void
    {
        $this->createMigrationFixtureTable();
        $connectionPool = $this->get(ConnectionPool::class);
        $connection     = $connectionPool->getConnectionForTable(self::FIXTURE_TABLE);
        $connection->insert(self::FIXTURE_TABLE, [self::FIXTURE_COLUMN => 'plaintext-api-key']);

        $uid = (int) $connection->lastInsertId();

        // Pattern exactly as the fixed configureAction builds it: single braces.
        $pattern = self::FIXTURE_TABLE . '__' . self::FIXTURE_COLUMN . '__{uid}';
        $result  = $this->invokeMigrateColumn(self::FIXTURE_TABLE, self::FIXTURE_COLUMN, $pattern);

        self::assertSame(1, $result->migrated, 'Expected exactly one row to be migrated');
        self::assertSame(0, $result->failed, 'Migration must not report failures: ' . ($result->error ?? ''));

        // The column now holds the substituted identifier, which must be valid.
        $expectedIdentifier = self::FIXTURE_TABLE . '__' . self::FIXTURE_COLUMN . '__' . $uid;
        self::assertTrue(
            IdentifierValidator::isValid($expectedIdentifier),
            'The substituted identifier must pass IdentifierValidator',
        );

        $storedColumn = $connection
            ->select([self::FIXTURE_COLUMN], self::FIXTURE_TABLE, ['uid' => $uid])
            ->fetchOne();
        self::assertSame($expectedIdentifier, $storedColumn, 'Column must be rewritten with the vault identifier');

        // The secret is actually retrievable from the vault under that identifier.
        $vaultService = $this->get(VaultServiceInterface::class);
        self::assertTrue($vaultService->exists($expectedIdentifier));
        self::assertSame('plaintext-api-key', $vaultService->retrieve($expectedIdentifier));

        // The record link is stored under metadata with the keys orphan
        // cleanup reads (#565), not as originalTable/originalColumn/originalUid.
        $metadataJson = $connectionPool->getConnectionForTable('tx_nrvault_secret')
            ->select(['metadata'], 'tx_nrvault_secret', ['identifier' => $expectedIdentifier])
            ->fetchOne();
        self::assertIsString($metadataJson);
        $metadata = json_decode($metadataJson, true);
        self::assertIsArray($metadata);
        self::assertIsInt($metadata['migrated_at'] ?? null);
        unset($metadata['migrated_at']);
        self::assertSame(
            ['source' => 'migration', 'table' => self::FIXTURE_TABLE, 'field' => self::FIXTURE_COLUMN, 'uid' => $uid],
            $metadata,
        );

        $vaultService->delete($expectedIdentifier, 'test cleanup');
    }

    /**
     * Bug characterisation: the OLD double-brace pattern leaves literal braces
     * after `{uid}` substitution, producing an INVALID identifier so the row
     * fails to migrate and nothing is stored. This documents precisely why the
     * `{{uid}}` regression broke every backend column migration.
     */
    #[Test]
    public function migrateColumnWithDoubleBracePatternFailsAndStoresNothing(): void
    {
        $this->createMigrationFixtureTable();
        $connectionPool = $this->get(ConnectionPool::class);
        $connection     = $connectionPool->getConnectionForTable(self::FIXTURE_TABLE);
        $connection->insert(self::FIXTURE_TABLE, [self::FIXTURE_COLUMN => 'plaintext-api-key']);

        $uid = (int) $connection->lastInsertId();

        // The buggy pattern: double braces around uid.
        $buggyPattern = self::FIXTURE_TABLE . '__' . self::FIXTURE_COLUMN . '__{{uid}}';
        $result       = $this->invokeMigrateColumn(self::FIXTURE_TABLE, self::FIXTURE_COLUMN, $buggyPattern);

        self::assertSame(0, $result->migrated, 'A literal-brace identifier must not migrate');
        self::assertSame(1, $result->failed, 'The row must be reported as failed');

        // Column is untouched and nothing landed in the vault.
        $storedColumn = $connection
            ->select([self::FIXTURE_COLUMN], self::FIXTURE_TABLE, ['uid' => $uid])
            ->fetchOne();
        self::assertSame('plaintext-api-key', $storedColumn, 'Failed migration must leave the column unchanged');

        $vaultService     = $this->get(VaultServiceInterface::class);
        $brokenIdentifier = self::FIXTURE_TABLE . '__' . self::FIXTURE_COLUMN . '__{' . $uid . '}';
        self::assertFalse($vaultService->exists($brokenIdentifier));
    }

    /**
     * A column narrower than the identifier would truncate it: the row fails,
     * keeps its plaintext, and nothing is stored (#565).
     */
    #[Test]
    public function migrateColumnRefusesAColumnTooNarrowForTheIdentifier(): void
    {
        $this->createMigrationFixtureTable();
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::FIXTURE_TABLE);
        $connection->insert(self::FIXTURE_TABLE, ['narrow' => 'short-secret']);

        $uid = (int) $connection->lastInsertId();

        $identifier = 'a_rather_long_identifier_' . $uid;
        $result     = $this->invokeMigrateColumn(self::FIXTURE_TABLE, 'narrow', 'a_rather_long_identifier_{uid}');

        self::assertSame(0, $result->migrated);
        self::assertSame(1, $result->failed);
        self::assertNull($result->error, 'A row failure is no failure of the whole column');
        self::assertStringContainsString('holds at most 20 characters', implode('; ', $result->failureReasons));
        self::assertSame('short-secret', $connection->select(['narrow'], self::FIXTURE_TABLE, ['uid' => $uid])->fetchOne());
        self::assertFalse($this->get(VaultServiceInterface::class)->exists($identifier));
    }

    /**
     * An identifier that already names a secret must not overwrite it: the
     * row fails and both the secret and the row keep their values (#565).
     */
    #[Test]
    public function migrateColumnDoesNotOverwriteAnExistingSecret(): void
    {
        $this->createMigrationFixtureTable();
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::FIXTURE_TABLE);
        $connection->insert(self::FIXTURE_TABLE, [self::FIXTURE_COLUMN => 'row-plaintext']);

        $uid = (int) $connection->lastInsertId();

        $identifier   = self::FIXTURE_TABLE . '__taken__' . $uid;
        $vaultService = $this->get(VaultServiceInterface::class);
        $vaultService->store($identifier, 'someone-elses-secret');

        $result = $this->invokeMigrateColumn(self::FIXTURE_TABLE, self::FIXTURE_COLUMN, self::FIXTURE_TABLE . '__taken__{uid}');

        self::assertSame(0, $result->migrated);
        self::assertSame(1, $result->failed);
        self::assertStringContainsString('already exists', implode('; ', $result->failureReasons));
        self::assertSame('someone-elses-secret', $vaultService->retrieve($identifier));
        self::assertSame('row-plaintext', $connection->select([self::FIXTURE_COLUMN], self::FIXTURE_TABLE, ['uid' => $uid])->fetchOne());

        $vaultService->delete($identifier, 'test cleanup');
    }

    /**
     * A table without TCA has no ctrl.delete for the deleted restriction to
     * follow; its conventional `deleted` column still keeps deleted rows out
     * (#565).
     */
    #[Test]
    public function migrateColumnSkipsDeletedRowsOfATableWithoutTca(): void
    {
        $this->createMigrationFixtureTable();
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::FIXTURE_TABLE);
        $connection->insert(self::FIXTURE_TABLE, [self::FIXTURE_COLUMN => 'deleted-plaintext', 'deleted' => 1]);

        $uid = (int) $connection->lastInsertId();

        $result = $this->invokeMigrateColumn(self::FIXTURE_TABLE, self::FIXTURE_COLUMN, self::FIXTURE_TABLE . '__deleted__{uid}');

        self::assertSame(0, $result->migrated);
        self::assertSame('deleted-plaintext', $connection->select([self::FIXTURE_COLUMN], self::FIXTURE_TABLE, ['uid' => $uid])->fetchOne());
    }

    /**
     * A disabled secret still owns its identifier: the row fails, and the
     * secret is neither overwritten nor deleted (#565).
     */
    #[Test]
    public function migrateColumnDoesNotOverwriteADisabledSecret(): void
    {
        $this->createMigrationFixtureTable();
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::FIXTURE_TABLE);
        $connection->insert(self::FIXTURE_TABLE, [self::FIXTURE_COLUMN => 'row-plaintext']);

        $uid = (int) $connection->lastInsertId();

        $identifier   = self::FIXTURE_TABLE . '__disabled__' . $uid;
        $vaultService = $this->get(VaultServiceInterface::class);
        $vaultService->store($identifier, 'disabled-secret-value');
        $vaultService->setEnabled($identifier, false);

        $result = $this->invokeMigrateColumn(self::FIXTURE_TABLE, self::FIXTURE_COLUMN, self::FIXTURE_TABLE . '__disabled__{uid}');

        self::assertSame(0, $result->migrated);
        self::assertSame(1, $result->failed);
        self::assertStringContainsString('already exists', implode('; ', $result->failureReasons));
        self::assertSame('row-plaintext', $connection->select([self::FIXTURE_COLUMN], self::FIXTURE_TABLE, ['uid' => $uid])->fetchOne());

        $vaultService->setEnabled($identifier, true);
        self::assertSame('disabled-secret-value', $vaultService->retrieve($identifier), 'The disabled secret keeps its value');

        $vaultService->delete($identifier, 'test cleanup');
    }

    /**
     * A row an editor changed after the migration read it keeps the editor's
     * value: the UPDATE names the value read, matches nothing, and the secret
     * just stored is discarded (#565).
     */
    #[Test]
    public function aValueChangedAfterItWasReadIsNotOverwritten(): void
    {
        $this->createMigrationFixtureTable();
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(self::FIXTURE_TABLE);
        $connection->insert(self::FIXTURE_TABLE, [self::FIXTURE_COLUMN => 'saved-by-an-editor']);

        $uid        = (int) $connection->lastInsertId();
        $identifier = self::FIXTURE_TABLE . '__stale__' . $uid;

        $error = $this->get(FieldValueMigratorInterface::class)
            ->migrate(self::FIXTURE_TABLE, self::FIXTURE_COLUMN, 'uid', (string) $uid, 'value-as-read-earlier', $identifier);

        self::assertStringContainsString('the row changed or is gone', (string) $error);
        self::assertSame('saved-by-an-editor', $connection->select([self::FIXTURE_COLUMN], self::FIXTURE_TABLE, ['uid' => $uid])->fetchOne());
        self::assertFalse($this->get(VaultServiceInterface::class)->exists($identifier), 'The secret just stored is discarded');
    }

    /**
     * Invoke the private `MigrationController::migrateColumn()` via reflection.
     * The full backend-module render path (`handleRequest`/`configureAction`)
     * needs a module routing attribute on the request that functional tests do
     * not provide (see {@see OverviewControllerTest}); the column-rewrite logic
     * we care about lives in `migrateColumn`, which renders nothing.
     */
    private function invokeMigrateColumn(string $table, string $column, string $pattern): MigrationResult
    {
        $controller = $this->get(MigrationController::class);
        $method     = (new ReflectionClass(MigrationController::class))->getMethod('migrateColumn');
        $result     = $method->invoke($controller, $table, $column, $pattern);
        self::assertInstanceOf(MigrationResult::class, $result);

        return $result;
    }

    /**
     * Create the throwaway fixture table the migration runs against. Built via
     * the same schema manager `migrateColumn` uses for validation, so the table
     * and column pass its `listTables()` / `listTableColumns()` checks.
     */
    private function createMigrationFixtureTable(): void
    {
        $schemaManager = $this->get(ConnectionPool::class)
            ->getConnectionForTable(self::FIXTURE_TABLE)
            ->createSchemaManager();

        if ($schemaManager->tablesExist([self::FIXTURE_TABLE])) {
            return;
        }

        $table = new Table(self::FIXTURE_TABLE);
        $table->addColumn('uid', Types::INTEGER, ['autoincrement' => true, 'unsigned' => true]);
        $table->addColumn(self::FIXTURE_COLUMN, Types::TEXT, ['notnull' => false]);
        $table->addColumn('narrow', Types::STRING, ['length' => 20, 'notnull' => false]);
        $table->addColumn('deleted', Types::SMALLINT, ['default' => 0]);
        $table->setPrimaryKey(['uid']);

        $schemaManager->createTable($table);
    }
}
