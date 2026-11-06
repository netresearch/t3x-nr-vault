<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

use Throwable;

use function is_scalar;
use function sprintf;

/**
 * Thrown when an audit-log write cannot proceed safely.
 *
 * Raised by {@see \Netresearch\NrVault\Audit\AuditChainLockTrait} via every
 * audit-chain writer — `AuditLogService::log()` (runtime) and the migration
 * sites (`AuditHmacMigration`, `VaultAuditMigrateCommand`) — when the
 * advisory lock that serialises hash-chain writers cannot be acquired
 * (`GET_LOCK` returned 0 = timeout or NULL = database error; on PostgreSQL
 * `pg_try_advisory_lock` stayed false for the whole timeout), and by
 * `AuditLogService::log()` for any other failure of the chain write itself
 * (via {@see self::writeFailed()}). `log()` therefore has a single failure
 * contract: it either persisted the entry or threw this exception —
 * which is what the SEC-3 compensating rollbacks in `VaultService` key on.
 * Migration callers may catch this and translate to a context-specific
 * exception if they need a distinct type.
 */
final class AuditWriteException extends VaultException
{
    /**
     * The audit-chain write itself failed (INSERT/UPDATE error, broken
     * schema, connection loss mid-transaction, …).
     */
    public static function writeFailed(Throwable $cause): self
    {
        return new self(
            'Audit-log write failed: ' . $cause->getMessage(),
            1754038801,
            $cause,
        );
    }

    /**
     * @param mixed $rawResult The value returned by `SELECT GET_LOCK(...)` —
     *                         normally 1/0/NULL but driver-dependent
     */
    public static function lockAcquisitionFailed(mixed $rawResult): self
    {
        return self::lockNotAcquired('GET_LOCK', $rawResult);
    }

    /**
     * The PostgreSQL advisory lock was not granted within the timeout.
     *
     * PostgreSQL has no named lock: `pg_locks` shows a bigint key split into
     * `classid` (high 32 bits) and `objid` (low 32 bits), with `objsubid` 1.
     * The hint names that query, because a search for "nr_vault_audit" finds
     * nothing there. `pg_locks` covers the whole cluster while the key is per
     * database, so the query is limited to the current database.
     *
     * @param mixed $rawResult The last value returned by the lock query — 0
     *                         while another session holds the lock
     * @param int   $lockKey   The advisory-lock key that was not granted
     */
    public static function postgreSqlLockAcquisitionFailed(mixed $rawResult, int $lockKey): self
    {
        return self::lockNotAcquired(
            'pg_try_advisory_lock',
            $rawResult,
            sprintf(
                'check for a stuck audit log writer: SELECT pid FROM pg_locks'
                . " WHERE locktype = 'advisory' AND classid = %d AND objid = %d AND objsubid = 1"
                . ' AND database = (SELECT oid FROM pg_database WHERE datname = current_database()).',
                ($lockKey >> 32) & 0xFFFFFFFF,
                $lockKey & 0xFFFFFFFF,
            ),
        );
    }

    private static function lockNotAcquired(
        string $lockFunction,
        mixed $rawResult,
        string $hint = 'check for a stuck audit log writer holding the named lock "nr_vault_audit".',
    ): self {
        $detail = match (true) {
            $rawResult === null   => 'NULL (DB error)',
            is_scalar($rawResult) => (string) $rawResult,
            default               => 'non-scalar',
        };

        return new self(
            sprintf(
                'Audit-log advisory lock could not be acquired (%s returned %s). '
                . 'Retry the operation; if the failure persists, %s',
                $lockFunction,
                $detail,
                $hint,
            ),
            1747825331,
        );
    }
}
