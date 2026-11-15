<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Acknowledgement;

use Netresearch\NrVault\Audit\Acknowledgement\AcknowledgementOutcome;
use Netresearch\NrVault\Audit\Acknowledgement\AcknowledgementStatus;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AcknowledgementOutcome::class)]
final class AcknowledgementOutcomeTest extends TestCase
{
    #[Test]
    public function anAcknowledgedOutcomeCarriesItsCounts(): void
    {
        $outcome = new AcknowledgementOutcome(AcknowledgementStatus::Acknowledged, 3, 1);

        self::assertTrue($outcome->isAcknowledged());
        self::assertSame(3, $outcome->acknowledgedCount);
        self::assertSame(1, $outcome->anchorsPublished);
    }

    /**
     * Every status other than `Acknowledged` counts as not acknowledged.
     */
    #[Test]
    public function everyOtherStatusIsARefusalWithoutCounts(): void
    {
        foreach (AcknowledgementStatus::cases() as $status) {
            if ($status === AcknowledgementStatus::Acknowledged) {
                continue;
            }

            $outcome = AcknowledgementOutcome::refused($status);

            self::assertFalse($outcome->isAcknowledged(), $status->value);
            self::assertSame($status, $outcome->status);
            self::assertSame(0, $outcome->acknowledgedCount);
            self::assertSame(0, $outcome->anchorsPublished);
        }
    }
}
