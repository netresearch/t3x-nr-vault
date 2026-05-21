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
use TYPO3\CMS\Core\Database\Connection;

/**
 * Shared advisory-lock primitives for the audit chain.
 *
 * SQLite: BEGIN EXCLUSIVE — serialises all writers for the transaction.
 * MySQL/MariaDB: named `GET_LOCK("nr_vault_audit", 5)` + transaction.
 * `GET_LOCK` returns 1 on success, 0 on timeout (5 s), NULL on error — we
 * abort on anything other than 1 so we never silently write unprotected
 * audit entries.
 *
 * Used by {@see AuditLogService} (runtime writes). Migration paths
 * (wizard / migrate command) inline the same pattern but throw
 * {@see \Netresearch\NrVault\Exception\AuditMigrationException} instead of
 * `AuditWriteException`; sharing the trait between contexts would force a
 * common exception type and lose the runtime-vs-migration distinction
 * surfaced in PR #133 review.
 */
trait AuditChainLockTrait
{
    /**
     * @throws AuditWriteException If the named lock cannot be acquired
     */
    private function acquireAuditLock(Connection $connection, bool $isSQLite): void
    {
        if ($isSQLite) {
            $connection->executeStatement('BEGIN EXCLUSIVE');

            return;
        }
        $lockResult = $connection->executeQuery('SELECT GET_LOCK("nr_vault_audit", 5)')->fetchOne();
        if (!is_numeric($lockResult) || (int) $lockResult !== 1) {
            throw AuditWriteException::lockAcquisitionFailed($lockResult);
        }
        $connection->beginTransaction();
    }

    private function commitAuditLock(Connection $connection, bool $isSQLite): void
    {
        if ($isSQLite) {
            $connection->executeStatement('COMMIT');

            return;
        }
        $connection->commit();
    }

    private function rollbackAuditLock(Connection $connection, bool $isSQLite): void
    {
        if ($isSQLite) {
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
