<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Dto;

use Netresearch\NrVault\Domain\Dto\UsageBar;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * One bar of the analytics distribution chart. The DTO computes nothing — the
 * percentage is worked out by the producing service — so what is worth pinning
 * is that the three values reach the template unchanged and in their declared
 * types, since the Fluid layer renders `percent` straight into a style attribute.
 */
#[CoversClass(UsageBar::class)]
final class UsageBarTest extends TestCase
{
    #[Test]
    public function exposesConstructorData(): void
    {
        $bar = new UsageBar(label: 'local', value: 42, percent: 66);

        self::assertSame('local', $bar->label);
        self::assertSame(42, $bar->value);
        self::assertSame(66, $bar->percent);
    }

    /**
     * An empty distribution is a legitimate state (a fresh installation), not an
     * error the DTO has to reject — the chart just renders a zero-width bar.
     */
    #[Test]
    public function acceptsAZeroBar(): void
    {
        $bar = new UsageBar(label: '', value: 0, percent: 0);

        self::assertSame('', $bar->label);
        self::assertSame(0, $bar->value);
        self::assertSame(0, $bar->percent);
    }
}
