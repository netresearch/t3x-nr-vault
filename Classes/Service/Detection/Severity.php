<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Detection;

/**
 * Severity level for detected secrets.
 */
enum Severity: string
{
    case Critical = 'critical';
    case High     = 'high';
    case Medium   = 'medium';
    case Low      = 'low';

    /**
     * Get numeric order for comparison (lower = more severe).
     */
    public function order(): int
    {
        return match ($this) {
            self::Critical => 0,
            self::High     => 1,
            self::Medium   => 2,
            self::Low      => 3,
        };
    }

    /**
     * Check if this severity is at least as severe as the given minimum.
     */
    public function isAtLeast(self $minimum): bool
    {
        return $this->order() <= $minimum->order();
    }
}
