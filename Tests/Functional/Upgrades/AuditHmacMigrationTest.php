<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Upgrades;

use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Configuration\ExtensionConfiguration;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Traits\LegacyAuditEntryTrait;
use Netresearch\NrVault\Upgrades\AuditHmacMigration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration as Typo3ExtensionConfiguration;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\ArrayUtility;

/**
 * Functional tests for the HMAC audit-chain migration.
 *
 * Seeds audit entries with epoch=0 (legacy SHA-256), runs the migration,
 * and verifies all entries are re-hashed with HMAC-SHA256. Runs on every
 * TYPO3 major: the logic depends on no upgrade API.
 * UpgradeWizardRegistrationTest covers the path through TYPO3's registry.
 */
#[CoversClass(AuditHmacMigration::class)]
final class AuditHmacMigrationTest extends AbstractVaultFunctionalTestCase
{
    use LegacyAuditEntryTrait;

    protected ?string $backendUserFixture = __DIR__ . '/../../Functional/Service/Fixtures/be_users.csv';

    /**
     * Start with legacy SHA-256 (epoch=0); individual tests flip to epoch=1
     * to exercise the migration.
     *
     * @var array<string, mixed>
     */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 0,
    ];

    #[Test]
    public function updateNecessaryReturnsFalseWhenEpochIsZero(): void
    {
        // epoch=0 means HMAC is disabled — no migration needed
        $wizard = $this->buildWizard();

        self::assertFalse(
            $wizard->updateNecessary(),
            'updateNecessary must return false when auditHmacEpoch=0',
        );
    }

    #[Test]
    public function updateNecessaryReturnsFalseWhenNoLegacyEntries(): void
    {
        // Switch to epoch=1 but with no legacy entries
        $this->configureAuditHmacEpoch(1);

        // Write new entries with epoch=1 (via VaultService which picks up the new epoch)
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'hmac-test-value');
        $vaultService->delete($identifier, 'cleanup');

        $wizard = $this->buildWizard();

        self::assertFalse(
            $wizard->updateNecessary(),
            'updateNecessary must return false when all entries are already at current epoch',
        );
    }

    #[Test]
    public function updateNecessaryReturnsTrueWhenLegacyEntriesExist(): void
    {
        // Seed a legacy (epoch=0) audit entry directly in the DB
        $this->seedLegacyAuditEntry('legacy/secret/ident', 'store');

        // Switch to epoch=1 — migration is now needed
        $this->configureAuditHmacEpoch(1);

        $wizard = $this->buildWizard();

        self::assertTrue(
            $wizard->updateNecessary(),
            'updateNecessary must return true when epoch=0 entries exist and target epoch>0',
        );
    }

    #[Test]
    public function updateNecessaryReturnsTrueForEpoch1RowsWhenTargetIsEpoch2(): void
    {
        // First: write entries at epoch=1 via VaultService.
        $this->configureAuditHmacEpoch(1);

        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'epoch1-value');
        $vaultService->delete($identifier, 'cleanup');

        // Now bump the configured epoch to 2 — the existing epoch-1 rows
        // are "outdated" because v1 hashes don't bind forensic fields.
        $this->configureAuditHmacEpoch(2);

        // Build the wizard with a fresh ExtensionConfiguration so it picks
        // up the new epoch from $GLOBALS — the DI-resolved instance is a
        // singleton that cached the previous value at construction.
        $wizard = new AuditHmacMigration(
            $this->get(ConnectionPool::class),
            $this->get(MasterKeyProviderInterface::class),
            new ExtensionConfiguration(new Typo3ExtensionConfiguration()),
            $this->get(AuditLogServiceInterface::class),
            $this->get(AuditChainAnchorStoreInterface::class),
        );

        self::assertTrue(
            $wizard->updateNecessary(),
            'updateNecessary must return true when epoch-1 rows exist and target is epoch 2',
        );
    }

    #[Test]
    public function executeUpdateMigratesLegacyEntriesToHmac(): void
    {
        // Seed legacy entries at epoch=0
        $this->seedLegacyAuditEntry('migrate/test/secret1', 'store');
        $this->seedLegacyAuditEntry('migrate/test/secret2', 'retrieve');

        // Switch to epoch=1
        $this->configureAuditHmacEpoch(1);

        $wizard = $this->buildWizard();
        self::assertTrue($wizard->updateNecessary(), 'Migration must be necessary before running');

        $result = $wizard->executeUpdate();

        self::assertTrue($result, 'executeUpdate must return true on success');

        // All entries should now be at epoch=1
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_audit_log');
        $legacyCount = (int) $connection->createQueryBuilder()
            ->count('uid')
            ->from('tx_nrvault_audit_log')
            ->where('hmac_key_epoch = 0')
            ->executeQuery()
            ->fetchOne();

        self::assertSame(0, $legacyCount, 'No legacy epoch=0 entries must remain after migration');
    }

    #[Test]
    public function executeUpdateBackfillsCorrectHmacHashes(): void
    {
        // Seed a known entry
        $secretId = 'hmac-hash-verify/secret';
        $this->seedLegacyAuditEntry($secretId, 'store');

        // Switch to epoch=1 and run migration
        $this->configureAuditHmacEpoch(1);

        $wizard = $this->buildWizard();
        $wizard->executeUpdate();

        // After migration, hash chain must verify correctly
        $auditService = $this->get(AuditLogServiceInterface::class);
        $result = $auditService->verifyHashChain();

        self::assertTrue(
            $result->isValid(),
            'Hash chain must be valid after HMAC migration: ' . implode(', ', $result->errors),
        );
    }

    #[Test]
    public function updateNecessaryReturnsFalseAfterMigration(): void
    {
        $this->seedLegacyAuditEntry('after-migration/secret', 'store');

        $this->configureAuditHmacEpoch(1);

        $wizard = $this->buildWizard();
        self::assertTrue($wizard->updateNecessary());

        $wizard->executeUpdate();

        // updateNecessary must return false now
        self::assertFalse(
            $wizard->updateNecessary(),
            'updateNecessary must return false after migration completes',
        );
    }

    #[Test]
    public function executeUpdateIsIdempotent(): void
    {
        // Seed 3 legacy (epoch=0) audit entries
        $this->seedLegacyAuditEntry('idempotent/secret/1', 'store');
        $this->seedLegacyAuditEntry('idempotent/secret/2', 'retrieve');
        $this->seedLegacyAuditEntry('idempotent/secret/3', 'delete');

        // Switch to epoch=1
        $this->configureAuditHmacEpoch(1);

        $wizard = $this->buildWizard();
        self::assertTrue($wizard->updateNecessary(), 'Migration must be necessary before first run');

        // First run
        $firstResult = $wizard->executeUpdate();
        self::assertTrue($firstResult, 'First executeUpdate must return true');

        // Snapshot all entry_hash + hmac_key_epoch values
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_audit_log');
        $snapshot1 = $connection->createQueryBuilder()
            ->select('uid', 'entry_hash', 'previous_hash', 'hmac_key_epoch')
            ->from('tx_nrvault_audit_log')
            ->orderBy('uid', 'ASC')
            ->executeQuery()
            ->fetchAllAssociative();

        // Chain must be valid after the first run
        $auditService = $this->get(AuditLogServiceInterface::class);
        self::assertTrue(
            $auditService->verifyHashChain()->isValid(),
            'Hash chain must be valid after first migration run',
        );

        // Second run
        $secondResult = $wizard->executeUpdate();
        self::assertTrue($secondResult, 'Second executeUpdate must return true');

        // Snapshot again
        $snapshot2 = $connection->createQueryBuilder()
            ->select('uid', 'entry_hash', 'previous_hash', 'hmac_key_epoch')
            ->from('tx_nrvault_audit_log')
            ->orderBy('uid', 'ASC')
            ->executeQuery()
            ->fetchAllAssociative();

        // Hash values must be byte-identical — no double-rotation
        self::assertSame(
            $snapshot1,
            $snapshot2,
            'Second executeUpdate must produce byte-identical hashes (idempotent)',
        );

        // Chain must still be valid
        self::assertTrue(
            $auditService->verifyHashChain()->isValid(),
            'Hash chain must be valid after second migration run',
        );

        // updateNecessary must return false after migration
        self::assertFalse(
            $wizard->updateNecessary(),
            'updateNecessary must return false after migration completes',
        );
    }

    /**
     * Switch the configured target epoch mid-test and drop the cached master
     * key so the next audit write derives its HMAC key afresh.
     */
    private function configureAuditHmacEpoch(int $epoch): void
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($confVars);
        $GLOBALS['TYPO3_CONF_VARS'] = ArrayUtility::setValueByPath(
            $confVars,
            'EXTENSIONS/nr_vault/auditHmacEpoch',
            $epoch,
        );
        FileMasterKeyProvider::clearCachedKey();
    }

    /**
     * Build the migration with DI-resolved dependencies. The upgrade-wizard
     * shells that TYPO3 registers are exercised separately, through the
     * registry, in UpgradeWizardRegistrationTest.
     */
    private function buildWizard(): AuditHmacMigration
    {
        return new AuditHmacMigration(
            $this->get(ConnectionPool::class),
            $this->get(MasterKeyProviderInterface::class),
            $this->get(ExtensionConfigurationInterface::class),
            $this->get(AuditLogServiceInterface::class),
            $this->get(AuditChainAnchorStoreInterface::class),
        );
    }
}
