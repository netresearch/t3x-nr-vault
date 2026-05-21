<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

/**
 * Thrown when an audit-log migration cannot proceed safely.
 *
 * Currently raised by the install-tool wizard
 * (`Classes/Upgrades/AuditHmacMigrationWizard`) when the advisory lock that
 * protects the migration cannot be acquired — either because another
 * process holds it (timeout) or because the database returned an error.
 */
final class AuditMigrationException extends VaultException
{
    public static function lockAcquisitionFailed(string $detail): self
    {
        return new self(
            \sprintf(
                'Audit-log advisory lock could not be acquired (GET_LOCK returned %s). '
                . 'Retry the migration; if the failure persists, check for a stuck audit '
                . 'log writer and consider RELEASE_LOCK("nr_vault_audit") manually.',
                $detail,
            ),
            1747825330,
        );
    }
}
