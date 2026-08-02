<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

use Throwable;

/**
 * Thrown when an audit-log write cannot proceed safely.
 *
 * Raised by {@see \Netresearch\NrVault\Audit\AuditChainLockTrait} via every
 * audit-chain writer — `AuditLogService::log()` (runtime) and the migration
 * sites (`AuditHmacMigrationWizard`, `VaultAuditMigrateCommand`) — when the
 * advisory lock that serialises hash-chain writers cannot be acquired
 * (`GET_LOCK` returned 0 = timeout, or NULL = database error), and by
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
        $detail = match (true) {
            $rawResult === null => 'NULL (DB error)',
            \is_scalar($rawResult) => (string) $rawResult,
            default => 'non-scalar',
        };

        return new self(
            \sprintf(
                'Audit-log advisory lock could not be acquired (GET_LOCK returned %s). '
                . 'Retry the operation; if the failure persists, check for a stuck '
                . 'audit log writer holding the named lock "nr_vault_audit".',
                $detail,
            ),
            1747825331,
        );
    }
}
