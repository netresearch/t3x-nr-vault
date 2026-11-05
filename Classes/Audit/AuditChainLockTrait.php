<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Netresearch\NrVault\Exception\AuditWriteException;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;

use function hrtime;
use function usleep;

/**
 * Shared advisory-lock primitives for the audit chain.
 *
 * Used by:
 *  - {@see AuditLogService} — runtime audit-log writes.
 *  - {@see \Netresearch\NrVault\Command\VaultAuditMigrateCommand} —
 *    one-shot CLI re-hash from SHA-256 to HMAC.
 *  - {@see \Netresearch\NrVault\Upgrades\AuditHmacMigration} —
 *    install-tool counterpart of the above.
 *
 * Lock behaviour:
 *  - SQLite: `BEGIN EXCLUSIVE` — serialises all writers for the transaction.
 *    A transaction owner that needs a Doctrine-managed transaction
 *    (`$managedSQLite`, {@see VaultMutationTransaction}) begins through
 *    Doctrine and takes the RESERVED lock with a write that matches no row.
 *  - MySQL/MariaDB: named `GET_LOCK("nr_vault_audit", 5)` + transaction.
 *    `GET_LOCK` returns 1 on success, 0 on timeout, NULL on error — we
 *    abort on anything other than 1 so we never silently write unprotected
 *    audit entries.
 *  - PostgreSQL: session-level `pg_try_advisory_lock()` on a fixed key,
 *    polled for up to 5 seconds, then a transaction. Like `GET_LOCK` it is
 *    counted per session and released explicitly after the commit. The
 *    non-blocking variant is used because a lock wait that ends in an error
 *    (`lock_timeout`) would abort a caller's surrounding transaction.
 *
 * Nesting inside a caller-managed Doctrine transaction (master-key rotation
 * runs audit writes + the chain re-key inside ONE transaction with the DEK
 * re-encryption):
 *  - MySQL/MariaDB and PostgreSQL: the named/advisory lock is re-acquirable
 *    per session (counted), and Doctrine DBAL 4 maps the nested
 *    begin/commit/rollback onto savepoints.
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
     * `pg_advisory_lock` key space is one bigint per database. The value is
     * the ASCII bytes of "nrvaudit", so it cannot collide with a small
     * integer key another extension picks.
     */
    private const POSTGRESQL_AUDIT_LOCK_KEY = 0x6E72766175646974;

    /** Same bound as the `GET_LOCK(..., 5)` timeout on MySQL/MariaDB. */
    private const AUDIT_LOCK_TIMEOUT_SECONDS = 5;

    /**
     * @throws AuditWriteException If the named lock cannot be acquired
     */
    private function acquireAuditLock(
        Connection $connection,
        bool $isSQLite,
        bool $managedSQLite = false,
    ): void {
        if ($isSQLite) {
            if ($managedSQLite) {
                // Doctrine opens a DEFERRED transaction. The owner reads before
                // it writes, so two concurrent owners would each hold a SHARED
                // lock and SQLite would fail the second upgrade at once,
                // without its busy timeout. A write that matches no row takes
                // the RESERVED lock now, so the second writer waits as it does
                // behind BEGIN EXCLUSIVE.
                $connection->beginTransaction();

                try {
                    $connection->executeStatement(
                        'UPDATE ' . AuditLogService::TABLE_NAME . ' SET uid = uid WHERE 1 = 0',
                    );
                } catch (Throwable $e) {
                    $connection->rollBack();

                    throw AuditWriteException::writeFailed($e);
                }

                return;
            }

            if ($connection->isTransactionActive()) {
                // Nested mode: savepoint via Doctrine (see trait docblock).
                $connection->beginTransaction();

                return;
            }

            $connection->executeStatement('BEGIN EXCLUSIVE');

            return;
        }

        if ($this->isPostgreSqlAuditConnection($connection)) {
            $this->acquirePostgreSqlAuditLock($connection);
        } else {
            $lockResult = $connection
                ->executeQuery('SELECT GET_LOCK("nr_vault_audit", 5)')
                ->fetchOne();
            if (!is_numeric($lockResult) || (int) $lockResult !== 1) {
                throw AuditWriteException::lockAcquisitionFailed($lockResult);
            }
        }

        // The lock is now held. If `beginTransaction()` throws, the caller's
        // try/finally has not started yet — so we must release the lock
        // ourselves before re-throwing, or it leaks for the duration of the
        // connection's lifetime.
        try {
            $connection->beginTransaction();
        } catch (Throwable $e) {
            try {
                $this->releaseAuditLock($connection, false);
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
        if ($isSQLite) {
            return;
        }

        if ($this->isPostgreSqlAuditConnection($connection)) {
            $connection->executeQuery(
                'SELECT pg_advisory_unlock(?)',
                [self::POSTGRESQL_AUDIT_LOCK_KEY],
                [Connection::PARAM_INT],
            );

            return;
        }

        $connection->executeStatement('SELECT RELEASE_LOCK("nr_vault_audit")');
    }

    private function isPostgreSqlAuditConnection(Connection $connection): bool
    {
        return $connection->getDatabasePlatform() instanceof PostgreSQLPlatform;
    }

    /**
     * Poll the non-blocking advisory lock until it is granted or the timeout
     * ends. `pg_try_advisory_lock()` answers false on contention instead of
     * raising an error, so a failed attempt leaves an enclosing transaction
     * usable.
     *
     * @throws AuditWriteException If the lock is not granted within the timeout
     */
    private function acquirePostgreSqlAuditLock(Connection $connection): void
    {
        $deadline = hrtime(true) + self::AUDIT_LOCK_TIMEOUT_SECONDS * 1_000_000_000;

        do {
            // CASE turns the boolean into an integer, which every PDO driver
            // returns in the same shape.
            $lockResult = $connection
                ->executeQuery(
                    'SELECT CASE WHEN pg_try_advisory_lock(?) THEN 1 ELSE 0 END',
                    [self::POSTGRESQL_AUDIT_LOCK_KEY],
                    [Connection::PARAM_INT],
                )
                ->fetchOne();
            if (is_numeric($lockResult) && (int) $lockResult === 1) {
                return;
            }

            if (!is_numeric($lockResult)) {
                break;
            }

            usleep(50_000);
        } while (hrtime(true) < $deadline);

        throw AuditWriteException::postgreSqlLockAcquisitionFailed($lockResult);
    }
}
