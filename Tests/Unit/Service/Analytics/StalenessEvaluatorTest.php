<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Analytics;

use Netresearch\NrVault\Domain\StalenessRule;
use Netresearch\NrVault\Service\Analytics\StalenessEvaluator;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(StalenessEvaluator::class)]
final class StalenessEvaluatorTest extends TestCase
{
    private const NOW = 1_700_000_000;
    private const DAY = 86_400;

    private function evaluator(): StalenessEvaluator
    {
        // thresholds: neverRead 30, notRead 90, neverRotated 180
        return new StalenessEvaluator(30, 90, 180);
    }

    #[Test]
    public function neverReadAndAgedIsDead(): void
    {
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 40 * self::DAY,
            readCount: 0,
            lastReadAt: null,
            lastRotatedAt: 0,
            expiresAt: 0,
            automatedReads: 0,
            manualReveals: 0,
        );

        self::assertContains(StalenessRule::Dead, $rules);
    }

    #[Test]
    public function neverReadButYoungIsNotDead(): void
    {
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 10 * self::DAY,
            readCount: 0,
            lastReadAt: null,
            lastRotatedAt: 0,
            expiresAt: 0,
            automatedReads: 0,
            manualReveals: 0,
        );

        self::assertNotContains(StalenessRule::Dead, $rules);
    }

    #[Test]
    public function coldReadIsDeadAtBoundary(): void
    {
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 200 * self::DAY,
            readCount: 5,
            lastReadAt: self::NOW - 90 * self::DAY,
            lastRotatedAt: self::NOW - 5 * self::DAY,
            expiresAt: 0,
            automatedReads: 0,
            manualReveals: 0,
        );

        self::assertContains(StalenessRule::Dead, $rules);
    }

    #[Test]
    public function expiredButPresentIsFlagged(): void
    {
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 100 * self::DAY,
            readCount: 3,
            lastReadAt: self::NOW - 1 * self::DAY,
            lastRotatedAt: self::NOW - 1 * self::DAY,
            expiresAt: self::NOW - 5 * self::DAY,
            automatedReads: 2,
            manualReveals: 0,
        );

        self::assertContains(StalenessRule::Expired, $rules);
        self::assertNotContains(StalenessRule::Dead, $rules);
    }

    #[Test]
    public function manualOnlyIsAutomationStaleNotDead(): void
    {
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 320 * self::DAY,
            readCount: 9,
            lastReadAt: self::NOW - 41 * self::DAY,
            lastRotatedAt: 0,
            expiresAt: 0,
            automatedReads: 0,
            manualReveals: 9,
        );

        self::assertContains(StalenessRule::AutomationStale, $rules);
        self::assertContains(StalenessRule::NeverRotated, $rules);
        self::assertNotContains(StalenessRule::Dead, $rules);
    }

    #[Test]
    public function deadSuppressesAutomationStale(): void
    {
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 300 * self::DAY,
            readCount: 0,
            lastReadAt: null,
            lastRotatedAt: self::NOW - 1 * self::DAY,
            expiresAt: 0,
            automatedReads: 0,
            manualReveals: 5,
        );

        self::assertContains(StalenessRule::Dead, $rules);
        self::assertNotContains(StalenessRule::AutomationStale, $rules);
    }

    #[Test]
    public function healthySecretHasNoRules(): void
    {
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 30 * self::DAY,
            readCount: 100,
            lastReadAt: self::NOW - 1 * self::DAY,
            lastRotatedAt: self::NOW - 10 * self::DAY,
            expiresAt: self::NOW + 365 * self::DAY,
            automatedReads: 50,
            manualReveals: 1,
        );

        self::assertSame([], $rules);
    }

    #[Test]
    public function lastReadAtZeroIsTreatedAsNeverRead(): void
    {
        // lastReadAt = 0 must NOT be interpreted as "read at epoch" (huge cold age).
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 200 * self::DAY,
            readCount: 5,
            lastReadAt: 0,
            lastRotatedAt: self::NOW - 5 * self::DAY,
            expiresAt: 0,
            automatedReads: 1,
            manualReveals: 0,
        );

        self::assertNotContains(StalenessRule::Dead, $rules);
    }

    #[Test]
    public function neverReadExactlyAtThresholdIsDead(): void
    {
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 30 * self::DAY,
            readCount: 0,
            lastReadAt: null,
            lastRotatedAt: self::NOW - 1 * self::DAY,
            expiresAt: 0,
            automatedReads: 0,
            manualReveals: 0,
        );

        self::assertContains(StalenessRule::Dead, $rules);
    }

    #[Test]
    public function neverRotatedExactlyAtThresholdIsFlagged(): void
    {
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 200 * self::DAY,
            readCount: 5,
            lastReadAt: self::NOW - 1 * self::DAY,
            lastRotatedAt: self::NOW - 180 * self::DAY,
            expiresAt: 0,
            automatedReads: 1,
            manualReveals: 0,
        );

        self::assertContains(StalenessRule::NeverRotated, $rules);
        self::assertNotContains(StalenessRule::Dead, $rules);
    }

    #[Test]
    public function expiresAtEqualToNowIsNotExpired(): void
    {
        $rules = $this->evaluator()->evaluate(
            now: self::NOW,
            crdate: self::NOW - 10 * self::DAY,
            readCount: 5,
            lastReadAt: self::NOW - 1 * self::DAY,
            lastRotatedAt: self::NOW - 1 * self::DAY,
            expiresAt: self::NOW,
            automatedReads: 1,
            manualReveals: 0,
        );

        self::assertNotContains(StalenessRule::Expired, $rules);
    }
}
