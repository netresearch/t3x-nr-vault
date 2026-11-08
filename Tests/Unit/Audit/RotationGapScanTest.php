<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Netresearch\NrVault\Audit\RotationGapScan;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(RotationGapScan::class)]
final class RotationGapScanTest extends TestCase
{
    #[Test]
    public function anEmptyScanIsRepairableWithNothingToReseal(): void
    {
        $scan = new RotationGapScan();

        self::assertTrue($scan->isRepairable());
        self::assertFalse($scan->hasPreviousKeyRows());
    }

    #[Test]
    public function aProblemMakesTheScanUnrepairableEvenWithRowsToReseal(): void
    {
        $scan = new RotationGapScan(
            previousKeyRows: [['uid' => 5, 'action' => 'read', 'secretIdentifier' => 'x', 'crdate' => 1]],
            problems: ['Rows uid 4 to 4 are missing.'],
        );

        self::assertFalse($scan->isRepairable());
        self::assertTrue($scan->hasPreviousKeyRows());
    }
}
