<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

/**
 * Aggregate usage KPIs for the analytics dashboard.
 */
final readonly class VaultUsageStats
{
    /**
     * @param list<UsageBar> $byAdapter
     * @param list<UsageBar> $byContext
     */
    public function __construct(
        public int $total,
        public int $active,
        public int $disabled,
        public int $expired,
        public int $frontendAccessible,
        public int $neverRotated,
        public int $automatedReads,
        public int $manualReveals,
        public int $windowDays,
        public array $byAdapter,
        public array $byContext,
    ) {}
}
