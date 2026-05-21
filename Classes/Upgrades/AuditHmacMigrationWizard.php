<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Upgrades;

use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\AuditMigrationException;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Upgrades\UpgradeWizardInterface;

/**
 * Upgrade wizard to migrate audit log hash chain from SHA-256 to HMAC-SHA256.
 *
 * Appears in the TYPO3 Install Tool after extension update. Automatically
 * detects legacy (epoch 0) entries and re-hashes them with the HMAC key
 * derived from the master key.
 *
 * Safety properties (mirrors `Command/VaultAuditMigrateCommand::migrateEntries`):
 *  - Advisory lock around the loop blocks concurrent audit writes
 *    (MySQL/MariaDB: named `GET_LOCK`; SQLite: `BEGIN EXCLUSIVE`).
 *  - All updates run inside a single transaction; mid-loop failure rolls
 *    back so the chain never lands in mixed-epoch state.
 *  - Re-runs are safe: re-hashing every row from UID 1 with a fresh
 *    `previousHash=''` produces a deterministic chain given the same HMAC
 *    key, so a retry after a transient failure converges to the same
 *    state.
 *
 * Errors are surfaced via PSR-3 logger when available; without a logger
 * the wizard returns false so the Install Tool reports the failure.
 */
final class AuditHmacMigrationWizard implements UpgradeWizardInterface, LoggerAwareInterface
{
    use LoggerAwareTrait;

    private const TABLE_NAME = 'tx_nrvault_audit_log';

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly MasterKeyProviderInterface $masterKeyProvider,
        private readonly ExtensionConfigurationInterface $extensionConfiguration,
    ) {
        $this->logger = new NullLogger();
    }

    public function getTitle(): string
    {
        return 'Vault: Migrate audit hash chain to HMAC-SHA256';
    }

    public function getDescription(): string
    {
        return 'Migrates existing audit log entries from plain SHA-256 hashing to '
            . 'HMAC-SHA256 keyed with a master-key-derived key. This provides '
            . 'tamper resistance against database-privileged attackers. '
            . 'The migration re-hashes all entries while maintaining chain integrity. '
            . 'Runs under an advisory lock and a single transaction — concurrent '
            . 'audit writes are serialised and partial failure rolls back.';
    }

    public function updateNecessary(): bool
    {
        if ($this->extensionConfiguration->getAuditHmacEpoch() === 0) {
            return false;
        }

        return $this->countLegacyEntries() > 0;
    }

    public function executeUpdate(): bool
    {
        $targetEpoch = $this->extensionConfiguration->getAuditHmacEpoch();
        if ($targetEpoch === 0) {
            return true;
        }

        $connection = $this->connectionPool->getConnectionForTable(self::TABLE_NAME);
        $hmacKey = AuditLogService::deriveHmacKey($this->masterKeyProvider);

        try {
            return $this->rehashChain($connection, $hmacKey, $targetEpoch);
        } catch (Throwable $e) {
            $this->logger->error(
                'AuditHmacMigrationWizard: re-hash failed; transaction rolled back',
                ['exception' => $e],
            );

            return false;
        } finally {
            sodium_memzero($hmacKey);
        }
    }

    /**
     * @return string[]
     */
    public function getPrerequisites(): array
    {
        return [];
    }

    private function rehashChain(Connection $connection, string $hmacKey, int $targetEpoch): bool
    {
        $isSQLite = $connection->getDatabasePlatform() instanceof SQLitePlatform;
        $this->acquireAuditLock($connection, $isSQLite);
        $lockAcquired = true;
        $committed = false;

        try {
            $migratedCount = $this->rehashAllRows($connection, $hmacKey, $targetEpoch);
            $this->commit($connection, $isSQLite);
            $committed = true;

            $this->logger->info(
                'AuditHmacMigrationWizard: migrated audit chain to HMAC',
                ['migratedCount' => $migratedCount, 'targetEpoch' => $targetEpoch],
            );

            return true;
        } finally {
            $this->releaseAuditLock($connection, $isSQLite, $committed, $lockAcquired);
        }
    }

    private function rehashAllRows(Connection $connection, string $hmacKey, int $targetEpoch): int
    {
        $result = $connection->createQueryBuilder()
            ->select('*')
            ->from(self::TABLE_NAME)
            ->orderBy('uid', 'ASC')
            ->executeQuery();

        $previousHash = '';
        $migratedCount = 0;

        while (($row = $result->fetchAssociative()) !== false) {
            $entry = $this->extractRow($row);

            $newHash = AuditLogService::calculateHash(
                $entry['uid'],
                $entry['secretId'],
                $entry['action'],
                $entry['actorUid'],
                $entry['crdate'],
                $previousHash,
                $hmacKey,
            );

            $connection->update(
                self::TABLE_NAME,
                [
                    'entry_hash' => $newHash,
                    'previous_hash' => $previousHash,
                    'hmac_key_epoch' => $targetEpoch,
                ],
                ['uid' => $entry['uid']],
            );

            $previousHash = $newHash;
            if ($entry['epoch'] === 0) {
                ++$migratedCount;
            }
        }

        return $migratedCount;
    }

    /**
     * Type-safe extraction of the audit row fields used by the hash calculation.
     *
     * @param array<string, mixed> $row
     *
     * @return array{uid: int, secretId: string, action: string, actorUid: int, crdate: int, epoch: int}
     */
    private function extractRow(array $row): array
    {
        return [
            'uid' => is_numeric($row['uid'] ?? null) ? (int) $row['uid'] : 0,
            'secretId' => \is_string($row['secret_identifier'] ?? null) ? $row['secret_identifier'] : '',
            'action' => \is_string($row['action'] ?? null) ? $row['action'] : '',
            'actorUid' => is_numeric($row['actor_uid'] ?? null) ? (int) $row['actor_uid'] : 0,
            'crdate' => is_numeric($row['crdate'] ?? null) ? (int) $row['crdate'] : 0,
            'epoch' => is_numeric($row['hmac_key_epoch'] ?? null) ? (int) $row['hmac_key_epoch'] : 0,
        ];
    }

    /**
     * Acquire an advisory lock to block concurrent AuditLogService::log() writes.
     * SQLite: BEGIN EXCLUSIVE serialises all writers.
     * MySQL/MariaDB: named GET_LOCK + transaction.
     *
     * `GET_LOCK` returns 1 on success, 0 on timeout (5 s), and NULL on error
     * (replication conflict, killed thread, etc.). The previous version
     * ignored the return value, so a contended or errored lock would silently
     * fall through and run the migration unprotected. We now abort the
     * migration when the lock isn't acquired and let the caller retry.
     *
     * @throws AuditMigrationException If the lock cannot be acquired
     */
    private function acquireAuditLock(Connection $connection, bool $isSQLite): void
    {
        if ($isSQLite) {
            $connection->executeStatement('BEGIN EXCLUSIVE');

            return;
        }
        $lockResult = $connection->executeQuery('SELECT GET_LOCK("nr_vault_audit", 5)')->fetchOne();
        if (!is_numeric($lockResult) || (int) $lockResult !== 1) {
            throw AuditMigrationException::lockAcquisitionFailed($lockResult);
        }
        $connection->beginTransaction();
    }

    private function commit(Connection $connection, bool $isSQLite): void
    {
        if ($isSQLite) {
            $connection->executeStatement('COMMIT');

            return;
        }
        $connection->commit();
    }

    /**
     * Release the advisory lock acquired by {@see acquireAuditLock()}.
     *
     * Rollback fires when `$committed` is false. Lock release is best-effort —
     * the connection close also releases — so we swallow secondary errors.
     * Skip rollback / release if the lock was never acquired (lockAcquired=false).
     */
    private function releaseAuditLock(Connection $connection, bool $isSQLite, bool $committed, bool $lockAcquired): void
    {
        if (!$lockAcquired) {
            return;
        }
        if (!$committed) {
            try {
                if ($isSQLite) {
                    $connection->executeStatement('ROLLBACK');
                } else {
                    $connection->rollBack();
                }
            } catch (Throwable) {
                // Rollback errors during cleanup are non-actionable; the outer
                // catch in executeUpdate() has already logged the root cause.
            }
        }
        if (!$isSQLite) {
            try {
                $connection->executeStatement('SELECT RELEASE_LOCK("nr_vault_audit")');
            } catch (Throwable) {
                // Lock release best-effort: connection close also releases.
            }
        }
    }

    private function countLegacyEntries(): int
    {
        $connection = $this->connectionPool->getConnectionForTable(self::TABLE_NAME);
        $queryBuilder = $connection->createQueryBuilder();
        $result = $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq(
                    'hmac_key_epoch',
                    $queryBuilder->createNamedParameter(0, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($result) ? (int) $result : 0;
    }
}
