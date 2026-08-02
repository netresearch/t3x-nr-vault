<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Dto;

use Netresearch\NrVault\Domain\Dto\UsageBar;
use Netresearch\NrVault\Domain\Dto\VaultUsageStats;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * The analytics dashboard reads eleven separate counters off this object, all of
 * them `int`, several of them adjacent in the constructor signature — `expired`,
 * `frontendAccessible` and `neverRotated` sit next to each other and would swap
 * silently. Named arguments plus a per-property assertion make that swap a test
 * failure rather than a wrong KPI tile.
 */
#[CoversClass(VaultUsageStats::class)]
final class VaultUsageStatsTest extends TestCase
{
    #[Test]
    public function exposesEveryCounterUnderItsOwnName(): void
    {
        $stats = new VaultUsageStats(
            total: 30,
            active: 27,
            disabled: 3,
            expired: 4,
            frontendAccessible: 5,
            neverRotated: 6,
            automatedReads: 700,
            manualReveals: 8,
            windowDays: 30,
            byAdapter: [],
            byContext: [],
        );

        self::assertSame(30, $stats->total);
        self::assertSame(27, $stats->active);
        self::assertSame(3, $stats->disabled);
        self::assertSame(4, $stats->expired);
        self::assertSame(5, $stats->frontendAccessible);
        self::assertSame(6, $stats->neverRotated);
        self::assertSame(700, $stats->automatedReads);
        self::assertSame(8, $stats->manualReveals);
        self::assertSame(30, $stats->windowDays);
    }

    /**
     * The two distributions are separate lists and must stay that way — the
     * dashboard renders them as two charts with different labels, so crossing
     * them would put context names under the adapter heading.
     */
    #[Test]
    public function keepsTheAdapterAndContextDistributionsApart(): void
    {
        $byAdapter = [new UsageBar(label: 'local', value: 20, percent: 67)];
        $byContext = [
            new UsageBar(label: 'payment', value: 18, percent: 60),
            new UsageBar(label: '', value: 12, percent: 40),
        ];

        $stats = $this->statsWith($byAdapter, $byContext);

        self::assertSame($byAdapter, $stats->byAdapter);
        self::assertSame($byContext, $stats->byContext);
        self::assertSame('local', $stats->byAdapter[0]->label);
        self::assertCount(2, $stats->byContext);
    }

    /**
     * A vault with no secrets yet: every counter zero and both distributions
     * empty. The dashboard renders this on a fresh installation, so it must be a
     * constructible state rather than something the DTO rejects.
     */
    #[Test]
    public function acceptsAnEmptyVault(): void
    {
        $stats = new VaultUsageStats(
            total: 0,
            active: 0,
            disabled: 0,
            expired: 0,
            frontendAccessible: 0,
            neverRotated: 0,
            automatedReads: 0,
            manualReveals: 0,
            windowDays: 7,
            byAdapter: [],
            byContext: [],
        );

        self::assertSame(0, $stats->total);
        self::assertSame(7, $stats->windowDays);
        self::assertSame([], $stats->byAdapter);
        self::assertSame([], $stats->byContext);
    }

    /**
     * @param list<UsageBar> $byAdapter
     * @param list<UsageBar> $byContext
     */
    private function statsWith(array $byAdapter, array $byContext): VaultUsageStats
    {
        return new VaultUsageStats(
            total: 30,
            active: 30,
            disabled: 0,
            expired: 0,
            frontendAccessible: 0,
            neverRotated: 0,
            automatedReads: 0,
            manualReveals: 0,
            windowDays: 30,
            byAdapter: $byAdapter,
            byContext: $byContext,
        );
    }
}
