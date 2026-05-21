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

        // Acquire an advisory lock to block concurrent AuditLogService::log()
        // writes for the duration of the migration. SQLite: BEGIN EXCLUSIVE
        // serialises all writers. MySQL/MariaDB: named GET_LOCK + transaction.
        if ($isSQLite) {
            $connection->executeStatement('BEGIN EXCLUSIVE');
        } else {
            $connection->executeStatement('SELECT GET_LOCK("nr_vault_audit", 5)');
            $connection->beginTransaction();
        }

        $committed = false;

        try {
            $result = $connection->createQueryBuilder()
                ->select('*')
                ->from(self::TABLE_NAME)
                ->orderBy('uid', 'ASC')
                ->executeQuery();

            $previousHash = '';
            $migratedCount = 0;

            while (($row = $result->fetchAssociative()) !== false) {
                $rowUid = $row['uid'] ?? 0;
                $uid = is_numeric($rowUid) ? (int) $rowUid : 0;
                $rowSecretId = $row['secret_identifier'] ?? '';
                $secretId = \is_string($rowSecretId) ? $rowSecretId : '';
                $rowAction = $row['action'] ?? '';
                $actionStr = \is_string($rowAction) ? $rowAction : '';
                $rowActorUid = $row['actor_uid'] ?? 0;
                $actorUid = is_numeric($rowActorUid) ? (int) $rowActorUid : 0;
                $rowCrdate = $row['crdate'] ?? 0;
                $crdate = is_numeric($rowCrdate) ? (int) $rowCrdate : 0;
                $rowEpoch = $row['hmac_key_epoch'] ?? 0;
                $epoch = is_numeric($rowEpoch) ? (int) $rowEpoch : 0;

                $newHash = AuditLogService::calculateHash(
                    $uid,
                    $secretId,
                    $actionStr,
                    $actorUid,
                    $crdate,
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
                    ['uid' => $uid],
                );

                $previousHash = $newHash;
                if ($epoch === 0) {
                    ++$migratedCount;
                }
            }

            if ($isSQLite) {
                $connection->executeStatement('COMMIT');
            } else {
                $connection->commit();
            }
            $committed = true;

            $this->logger->info(
                'AuditHmacMigrationWizard: migrated audit chain to HMAC',
                ['migratedCount' => $migratedCount, 'targetEpoch' => $targetEpoch],
            );

            return true;
        } finally {
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
