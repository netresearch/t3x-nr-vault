<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor;

/**
 * Severity of a single readiness {@see Finding}.
 *
 * Three levels, not five: the only decision this feeds is the `vault:doctor`
 * exit code, and a deployment gate has exactly three answers — go, go with a
 * note, stop. Backing values are part of the JSON contract.
 */
enum FindingSeverity: string
{
    /**
     * The control is satisfied. Reported rather than omitted, so the JSON
     * output is the full control list and "N of M passed" needs no second
     * source of truth.
     */
    case Pass = 'pass';

    /**
     * The control is not satisfied, but the vault still protects secrets.
     * Audit-relevant weakness or operational hygiene — worth fixing before an
     * audit, not worth blocking a deployment over.
     */
    case Warning = 'warning';

    /**
     * The control is not satisfied in a way that breaks the profile's own
     * promise: secrets unreadable, master key exposed, audit trail unprovable.
     * A hardened deployment must not go live in this state.
     */
    case Critical = 'critical';

    /**
     * Ordering weight for aggregation — higher wins.
     *
     * Used by {@see DoctorReport} to reduce a finding list to one verdict; the
     * numbers are internal and deliberately not the exit codes (Pass exits 0,
     * but so may a report with no findings at all).
     */
    public function rank(): int
    {
        return match ($this) {
            self::Pass => 0,
            self::Warning => 1,
            self::Critical => 2,
        };
    }

    /**
     * Bootstrap contextual class for the backend badge.
     */
    public function bootstrapContext(): string
    {
        return match ($this) {
            self::Pass => 'success',
            self::Warning => 'warning',
            self::Critical => 'danger',
        };
    }
}
