<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Upgrades;

use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Audit\AuditChainLockTrait;
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
    use AuditChainLockTrait;
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
        return 'Migrates existing audit log entries to the configured HMAC '
            . 'epoch. Epoch 1 upgrades plain SHA-256 to HMAC-SHA256 (tamper '
            . 'resistance against DB-privileged attackers). Epoch 2 extends '
            . 'the HMAC payload to cover forensic fields (success, '
            . 'error_message, reason, ip_address, user_agent, context) so '
            . 'they too become tamper-evident. Epoch 3 additionally binds the '
            . 'epoch selector (hmac_key_epoch) — closing the algorithm-downgrade '
            . 'forgery — and the attribution fields (actor_type, actor_username, '
            . 'actor_role, request_id). '
            . 'The migration re-hashes all entries while maintaining chain integrity. '
            . 'Runs under an advisory lock and a single transaction — concurrent '
            . 'audit writes are serialised and partial failure rolls back.';
    }

    public function updateNecessary(): bool
    {
        $targetEpoch = $this->extensionConfiguration->getAuditHmacEpoch();
        if ($targetEpoch === 0) {
            return false;
        }

        return $this->countOutdatedEntries($targetEpoch) > 0;
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
        $committed = false;

        try {
            $migratedCount = $this->rehashAllRows($connection, $hmacKey, $targetEpoch);
            $this->commitAuditLock($connection, $isSQLite);
            $committed = true;

            $this->logger->info(
                'AuditHmacMigrationWizard: migrated audit chain to HMAC',
                ['migratedCount' => $migratedCount, 'targetEpoch' => $targetEpoch],
            );

            return true;
        } finally {
            $this->cleanupAuditLock($connection, $isSQLite, $committed);
        }
    }

    /**
     * Best-effort rollback + release. Acquire failures throw before the try
     * block so we only get here when the lock WAS acquired. Secondary errors
     * during rollback / release are swallowed so they don't mask the root
     * cause already logged by `executeUpdate()`.
     */
    private function cleanupAuditLock(Connection $connection, bool $isSQLite, bool $committed): void
    {
        if (!$committed) {
            try {
                $this->rollbackAuditLock($connection, $isSQLite);
            } catch (Throwable) {
                // Rollback errors during cleanup are non-actionable; the outer
                // catch in executeUpdate() has already logged the root cause.
            }
        }

        try {
            $this->releaseAuditLock($connection, $isSQLite);
        } catch (Throwable) {
            // Lock release best-effort: connection close also releases.
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
            $entry = AuditLogService::extractHashRow($row);

            // Dispatch by target epoch: v1 covers identity fields only, v2
            // adds the forensic fields (success / error_message / reason /
            // ip_address / user_agent / hash_before / hash_after / context),
            // v3 also binds the epoch selector (hmac_key_epoch) and the
            // attribution fields (actor_type / actor_username / actor_role /
            // request_id). extractV3HashRow() reads hmac_key_epoch from the
            // row, so seed it with the target epoch the row is being rehashed
            // to before extraction.
            if ($targetEpoch >= 3) {
                $row['hmac_key_epoch'] = $targetEpoch;
                $newHash = AuditLogService::calculateHashV3(
                    AuditLogService::extractV3HashRow($row),
                    $previousHash,
                    $hmacKey,
                );
            } elseif ($targetEpoch >= 2) {
                $newHash = AuditLogService::calculateHashV2(
                    AuditLogService::extractV2HashRow($row),
                    $previousHash,
                    $hmacKey,
                );
            } else {
                $newHash = AuditLogService::calculateHash(
                    $entry['uid'],
                    $entry['secretId'],
                    $entry['action'],
                    $entry['actorUid'],
                    $entry['crdate'],
                    $previousHash,
                    $hmacKey,
                );
            }

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
            if ($entry['epoch'] !== $targetEpoch) {
                ++$migratedCount;
            }
        }

        return $migratedCount;
    }

    /**
     * Count rows whose stored epoch is below the configured target. Covers
     * 0 → 1, 0 → 2, AND 1 → 2 migrations, so the wizard surfaces in the
     * Install Tool whenever any row would benefit from a re-hash.
     */
    private function countOutdatedEntries(int $targetEpoch): int
    {
        $connection = $this->connectionPool->getConnectionForTable(self::TABLE_NAME);
        $queryBuilder = $connection->createQueryBuilder();
        $result = $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->lt(
                    'hmac_key_epoch',
                    $queryBuilder->createNamedParameter($targetEpoch, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($result) ? (int) $result : 0;
    }
}
