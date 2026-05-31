<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Hook;

use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Hook\DataHandlerHook;
use Netresearch\NrVault\Hook\PendingSecretExtractor;
use Netresearch\NrVault\Hook\PendingSecretPersister;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Utility\VaultFieldResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Functional tests for DataHandlerHook.
 *
 * Note: The hook's TCA schema discovery (`getVaultFieldNames`) requires tables
 * registered at bootstrap time. These tests use a minimal hook instance with
 * a pre-seeded vault-field cache to bypass that limitation — see the
 * {@see self::createHookWithVaultFields()} PHPDoc for why reflection is used.
 */
#[CoversClass(DataHandlerHook::class)]
final class DataHandlerHookTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function hookStoresNewSecretWhenFieldIsPlaintext(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $hook = $this->createHookWithVaultFields('tx_test', ['secret_field']);

        $secretValue = 'my-new-plain-secret';
        $fieldArray = ['secret_field' => $secretValue, 'title' => 'Test'];

        // Pre-process: replaces plaintext with a UUID
        $hook->processDatamap_preProcessFieldArray($fieldArray, 'tx_test', 'NEW1');

        $vaultIdentifier = $fieldArray['secret_field'];
        self::assertNotSame($secretValue, $vaultIdentifier, 'Field must be replaced by UUID');
        self::assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', $vaultIdentifier, 'Must be a UUID');

        try {
            // After-database: persist vault secret
            $dataHandler = $this->createDataHandler();
            $dataHandler->substNEWwithIDs['NEW1'] = 99;
            $hook->processDatamap_afterDatabaseOperations('new', 'tx_test', 'NEW1', $fieldArray, $dataHandler);

            // Secret must be retrievable by its vault identifier
            $retrieved = $vaultService->retrieve($vaultIdentifier);
            self::assertSame($secretValue, $retrieved, 'Vault must store the original plaintext secret');
        } finally {
            $this->safeDelete($vaultService, $vaultIdentifier);
        }
    }

    #[Test]
    public function hookRotatesExistingSecretWhenUpdateProvided(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $hook = $this->createHookWithVaultFields('tx_test', ['secret_field']);

        // Pre-create the secret
        $vaultIdentifier = $this->generateUuidV7();
        $originalValue = 'original-value';
        $vaultService->store($vaultIdentifier, $originalValue);

        try {
            $originalChecksum = $encryptionService->calculateChecksum($originalValue);

            // Update: field array has new value + existing identifier + checksum
            $newValue = 'rotated-value';
            $fieldArray = [
                'secret_field' => [
                    'value' => $newValue,
                    '_vault_identifier' => $vaultIdentifier,
                    '_vault_checksum' => $originalChecksum,
                ],
            ];

            $hook->processDatamap_preProcessFieldArray($fieldArray, 'tx_test', 99);
            // After pre-processing the identifier must still be the existing one
            self::assertSame($vaultIdentifier, $fieldArray['secret_field'], 'Existing identifier must be preserved');

            $dataHandler = $this->createDataHandler();
            $hook->processDatamap_afterDatabaseOperations('update', 'tx_test', 99, $fieldArray, $dataHandler);

            $vaultService->clearCache();
            $retrieved = $vaultService->retrieve($vaultIdentifier);
            self::assertSame($newValue, $retrieved, 'Vault must contain rotated secret value');
        } finally {
            $this->safeDelete($vaultService, $vaultIdentifier);
        }
    }

    #[Test]
    public function hookClearsFieldWhenEmptyValueProvided(): void
    {
        $hook = $this->createHookWithVaultFields('tx_test', ['secret_field']);

        // Empty value with no existing checksum = skip field entirely
        $fieldArray = ['secret_field' => ''];
        $hook->processDatamap_preProcessFieldArray($fieldArray, 'tx_test', 'NEW1');

        // Field must be removed (not stored as empty UUID)
        self::assertArrayNotHasKey('secret_field', $fieldArray, 'Empty field must be unset');
    }

    #[Test]
    public function hookWritesAuditLogEntryOnSecretStore(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        $vaultService = $this->get(VaultServiceInterface::class);
        $hook = $this->createHookWithVaultFields('tx_test', ['secret_field']);

        $fieldArray = ['secret_field' => 'audit-log-secret'];
        $hook->processDatamap_preProcessFieldArray($fieldArray, 'tx_test', 'NEW1');

        $vaultIdentifier = $fieldArray['secret_field'];

        try {
            $dataHandler = $this->createDataHandler();
            $dataHandler->substNEWwithIDs['NEW1'] = 100;
            $hook->processDatamap_afterDatabaseOperations('new', 'tx_test', 'NEW1', $fieldArray, $dataHandler);

            // Check audit log for this identifier
            $entries = $auditService->query(AuditLogFilter::forSecret($vaultIdentifier));
            self::assertNotEmpty($entries, 'Audit log must contain entry for vault store via DataHandler');
        } finally {
            $this->safeDelete($vaultService, $vaultIdentifier);
        }
    }

    #[Test]
    public function hookDeletesVaultSecretOnRecordDelete(): void
    {
        $this->skipIfNotSqlite();

        $vaultService = $this->get(VaultServiceInterface::class);
        $connectionPool = $this->get(ConnectionPool::class);
        $hook = $this->createHookWithVaultFields('tx_nrvault_hooktest2', ['api_key']);

        // Create test table and insert a record. The DDL below uses
        // SQLite-specific AUTOINCREMENT (single-word); MySQL/MariaDB use
        // `AUTO_INCREMENT` and PostgreSQL uses `SERIAL`/`GENERATED ...`. We
        // pin this test to SQLite via {@see self::skipIfNotSqlite()} above;
        // the functional suite is currently configured for pdo_sqlite in
        // Build/FunctionalTests.xml. If a driver other than sqlite is wired
        // in, the test self-skips rather than failing with a DDL parse error.
        $connection = $connectionPool->getConnectionForTable('tx_nrvault_hooktest2');
        $connection->executeStatement(
            'CREATE TABLE IF NOT EXISTS tx_nrvault_hooktest2 (
                uid INTEGER PRIMARY KEY AUTOINCREMENT,
                pid INTEGER DEFAULT 0,
                api_key VARCHAR(255) DEFAULT \'\'
            )',
        );

        // Store a secret and insert a record referencing it
        $vaultIdentifier = $this->generateUuidV7();
        $vaultService->store($vaultIdentifier, 'delete-test-secret');

        $connection->insert('tx_nrvault_hooktest2', [
            'pid' => 0,
            'api_key' => $vaultIdentifier,
        ]);
        $recordUid = (int) $connection->lastInsertId();

        // Trigger delete hook
        $dataHandler = $this->createDataHandler();
        $hook->processCmdmap_preProcess('delete', 'tx_nrvault_hooktest2', $recordUid, null, $dataHandler, false);

        // Secret must be deleted
        $vaultService->clearCache();
        $retrieved = $vaultService->retrieve($vaultIdentifier);
        self::assertNull($retrieved, 'Vault secret must be deleted when its record is deleted');
    }

    /**
     * Build a DataHandlerHook instance with a pre-seeded vault-field cache.
     *
     * WHY REFLECTION (code smell — documented, not hidden):
     *
     * DataHandlerHook discovers vault fields via
     * {@see TcaSchemaFactory}, which only sees tables
     * registered at **bootstrap time** (via each loaded extension's
     * `ext_tables.sql`). Functional tests cannot easily register synthetic
     * tables into the schema factory mid-test, so we short-circuit the
     * discovery step by writing into the hook's private `$vaultFieldCache`.
     *
     * Alternatives considered:
     *   - Register a real fixture table via `ext_tables.sql` — adds schema
     *     churn for every scenario and pollutes the production schema with
     *     test-only columns.
     *   - Add a public `setVaultFieldsForTable()` seam on
     *     {@see DataHandlerHook} — widens the production API purely for
     *     test convenience.
     *
     * Both were judged worse than this localised reflection. If the hook
     * grows a natural DI seam for vault-field discovery in future, migrate
     * to it and delete this helper.
     *
     * @param list<string> $vaultFields
     */
    private function createHookWithVaultFields(string $table, array $vaultFields): DataHandlerHook
    {
        $hook = new DataHandlerHook(
            $this->get(ConnectionPool::class),
            $this->get(VaultServiceInterface::class),
            $this->get(VaultFieldResolver::class),
            $this->get(PendingSecretExtractor::class),
            $this->get(PendingSecretPersister::class),
        );

        // Pre-seed the field cache via reflection (setAccessible is a no-op since PHP 8.1)
        $cacheProperty = new ReflectionProperty(DataHandlerHook::class, 'vaultFieldCache');
        $cacheProperty->setValue($hook, [$table => $vaultFields]);

        return $hook;
    }

    /**
     * Skip the current test when the functional suite is NOT running on
     * SQLite. Exists so the one SQLite-specific DDL (AUTOINCREMENT) doesn't
     * break a future MySQL/Postgres run.
     */
    private function skipIfNotSqlite(): void
    {
        $connection = $this->get(ConnectionPool::class)->getConnectionByName(
            ConnectionPool::DEFAULT_CONNECTION_NAME,
        );
        $platformClass = $connection->getDatabasePlatform()::class;

        if (!str_contains(strtolower($platformClass), 'sqlite')) {
            self::markTestSkipped(
                \sprintf(
                    'Test uses SQLite-specific DDL (AUTOINCREMENT); current platform is %s.',
                    $platformClass,
                ),
            );
        }
    }

    /**
     * Create a minimal DataHandler for hook callbacks.
     */
    private function createDataHandler(): DataHandler
    {
        /** @phpstan-ignore new.internalClass */
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];

        return $dataHandler;
    }

    /**
     * Delete a vault secret by identifier, swallowing failures so cleanup
     * never masks the original assertion.
     */
    private function safeDelete(VaultServiceInterface $vaultService, string $identifier): void
    {
        try {
            if ($vaultService->exists($identifier)) {
                $vaultService->delete($identifier, 'test cleanup');
            }
        } catch (Throwable) {
            // best-effort cleanup
        }
    }
}
