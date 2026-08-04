<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use Netresearch\NrVault\Exception\AuditWriteException;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;

/**
 * Shared advisory-lock primitives for the audit chain.
 *
 * Used by:
 *  - {@see AuditLogService} — runtime audit-log writes.
 *  - {@see \Netresearch\NrVault\Command\VaultAuditMigrateCommand} —
 *    one-shot CLI re-hash from SHA-256 to HMAC.
 *  - {@see \Netresearch\NrVault\Upgrades\AuditHmacMigrationWizard} —
 *    install-tool counterpart of the above.
 *
 * Lock behaviour:
 *  - SQLite: `BEGIN EXCLUSIVE` — serialises all writers for the transaction.
 *  - MySQL/MariaDB: named `GET_LOCK("nr_vault_audit", 5)` + transaction.
 *    `GET_LOCK` returns 1 on success, 0 on timeout, NULL on error — we
 *    abort on anything other than 1 so we never silently write unprotected
 *    audit entries.
 *
 * Nesting inside a caller-managed Doctrine transaction (master-key rotation
 * runs audit writes + the chain re-key inside ONE transaction with the DEK
 * re-encryption):
 *  - MySQL/MariaDB: `GET_LOCK` is re-acquirable per session (counted), and
 *    Doctrine DBAL 4 maps the nested begin/commit/rollback onto savepoints.
 *  - SQLite: a raw `BEGIN EXCLUSIVE` cannot nest. When a Doctrine-managed
 *    transaction is already active, acquire/commit/rollback fall back to
 *    Doctrine savepoints; write-serialisation is then provided by the outer
 *    transaction's database-file write lock. `Connection::isTransactionActive()`
 *    discriminates the two modes — a raw `BEGIN EXCLUSIVE` is invisible to
 *    Doctrine's nesting counter (false), a savepoint acquire is not (true).
 *
 * Lock failures surface as {@see AuditWriteException}. Callers that want a
 * context-specific exception type can catch and re-throw.
 */
trait AuditChainLockTrait
{
    /**
     * @throws AuditWriteException If the named lock cannot be acquired
     */
    private function acquireAuditLock(Connection $connection, bool $isSQLite): void
    {
        if ($isSQLite) {
            if ($connection->isTransactionActive()) {
                // Nested mode: savepoint via Doctrine (see trait docblock).
                $connection->beginTransaction();

                return;
            }

            $connection->executeStatement('BEGIN EXCLUSIVE');

            return;
        }

        $lockResult = $connection->executeQuery('SELECT GET_LOCK("nr_vault_audit", 5)')->fetchOne();
        if (!is_numeric($lockResult) || (int) $lockResult !== 1) {
            throw AuditWriteException::lockAcquisitionFailed($lockResult);
        }

        // The lock is now held. If `beginTransaction()` throws, the caller's
        // try/finally has not started yet — so we must release the lock
        // ourselves before re-throwing, or it leaks for the duration of the
        // connection's lifetime.
        try {
            $connection->beginTransaction();
        } catch (Throwable $e) {
            try {
                $connection->executeStatement('SELECT RELEASE_LOCK("nr_vault_audit")');
            } catch (Throwable) {
                // Best-effort: connection close will release.
            }

            throw $e;
        }
    }

    private function commitAuditLock(Connection $connection, bool $isSQLite): void
    {
        if ($isSQLite) {
            if ($connection->isTransactionActive()) {
                // Nested mode: release the savepoint; durability comes from
                // the caller's outer commit.
                $connection->commit();

                return;
            }

            $connection->executeStatement('COMMIT');

            return;
        }

        $connection->commit();
    }

    private function rollbackAuditLock(Connection $connection, bool $isSQLite): void
    {
        if ($isSQLite) {
            if ($connection->isTransactionActive()) {
                // Nested mode: roll back to the savepoint; the caller's outer
                // transaction decides the final fate.
                $connection->rollBack();

                return;
            }

            $connection->executeStatement('ROLLBACK');

            return;
        }

        $connection->rollBack();
    }

    private function releaseAuditLock(Connection $connection, bool $isSQLite): void
    {
        if (!$isSQLite) {
            $connection->executeStatement('SELECT RELEASE_LOCK("nr_vault_audit")');
        }
    }
}
