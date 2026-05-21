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
 * Currently raised by {@see \Netresearch\NrVault\Audit\AuditLogService::log()}
 * when the advisory lock that serialises hash-chain writers cannot be
 * acquired — `GET_LOCK` returned 0 (timeout) or NULL (database error).
 *
 * Distinct from {@see AuditMigrationException} because the runtime audit-log
 * write path needs to surface a different concern than a one-shot install-tool
 * migration: callers of `AuditLogService::log()` may want to retry, while a
 * migration failure typically aborts the wizard.
 */
final class AuditWriteException extends VaultException
{
    public static function lockAcquisitionFailed(string $detail): self
    {
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
