<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain;

/**
 * Reasons a secret may be flagged as a redaction candidate.
 *
 * Backing values are stable identifiers used in templates / CSS hooks.
 */
enum StalenessRule: string
{
    case Dead = 'dead';
    case Expired = 'expired';
    case AutomationStale = 'automation_stale';
    case NeverRotated = 'never_rotated';

    /**
     * Bootstrap contextual colour for the backend badge: 'danger' (delete
     * candidate) or 'warning' (review).
     */
    public function severity(): string
    {
        return match ($this) {
            self::Dead, self::Expired => 'danger',
            self::AutomationStale, self::NeverRotated => 'warning',
        };
    }

    /**
     * Fallback English label (templates use XLIFF; this is for CLI/logs/tests).
     */
    public function label(): string
    {
        return match ($this) {
            self::Dead => 'Dead',
            self::Expired => 'Expired',
            self::AutomationStale => 'Automation-stale',
            self::NeverRotated => 'Never rotated',
        };
    }
}
