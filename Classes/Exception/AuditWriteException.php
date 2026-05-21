<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

/**
 * Thrown when an audit-log write cannot proceed safely.
 *
 * Raised by {@see \Netresearch\NrVault\Audit\AuditChainLockTrait} via every
 * audit-chain writer — `AuditLogService::log()` (runtime) and the migration
 * sites (`AuditHmacMigrationWizard`, `VaultAuditMigrateCommand`) — when the
 * advisory lock that serialises hash-chain writers cannot be acquired
 * (`GET_LOCK` returned 0 = timeout, or NULL = database error). Migration
 * callers may catch this and translate to a context-specific exception if
 * they need a distinct type.
 */
final class AuditWriteException extends VaultException
{
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
