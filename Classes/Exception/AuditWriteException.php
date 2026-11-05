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
     * @param mixed $rawResult The last value returned by
     *                         `pg_try_advisory_lock(...)` — 0 while another
     *                         writer holds the lock, NULL on a database error
     */
    public static function postgreSqlLockAcquisitionFailed(mixed $rawResult): self
    {
        return self::lockNotAcquired('pg_try_advisory_lock', $rawResult);
    }

    private static function lockNotAcquired(string $lockFunction, mixed $rawResult): self
    {
        $detail = match (true) {
            $rawResult === null   => 'NULL (DB error)',
            is_scalar($rawResult) => (string) $rawResult,
            default               => 'non-scalar',
        };

        return new self(
            sprintf(
                'Audit-log advisory lock could not be acquired (%s returned %s). '
                . 'Retry the operation; if the failure persists, check for a stuck '
                . 'audit log writer holding the audit-chain lock "nr_vault_audit".',
                $lockFunction,
                $detail,
            ),
            1747825331,
        );
    }
}
