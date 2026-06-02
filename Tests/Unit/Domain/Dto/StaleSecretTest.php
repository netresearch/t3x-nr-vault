<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Dto;

use Netresearch\NrVault\Domain\Dto\StaleSecret;
use Netresearch\NrVault\Domain\StalenessRule;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * Unit tests for the StaleSecret value object, in particular the
 * highestSeverity() projection used to colour the redaction-candidates row.
 */
#[CoversClass(StaleSecret::class)]
final class StaleSecretTest extends TestCase
{
    #[Test]
    public function highestSeverityIsDangerWhenAnyRuleIsDanger(): void
    {
        $secret = $this->secretWithRules([StalenessRule::NeverRotated, StalenessRule::Expired]);

        self::assertSame('danger', $secret->highestSeverity());
    }

    #[Test]
    public function highestSeverityIsWarningWhenAllRulesAreWarning(): void
    {
        $secret = $this->secretWithRules([StalenessRule::NeverRotated, StalenessRule::AutomationStale]);

        self::assertSame('warning', $secret->highestSeverity());
    }

    #[Test]
    public function highestSeverityDefaultsToWarningWithoutRules(): void
    {
        $secret = $this->secretWithRules([]);

        self::assertSame('warning', $secret->highestSeverity());
    }

    #[Test]
    public function exposesConstructorData(): void
    {
        $secret = new StaleSecret(
            uid: 9,
            identifier: 'stripe_test_old',
            context: 'payment',
            adapter: 'local',
            lastReadAt: 123,
            automatedReads: 2,
            manualReveals: 5,
            ageDays: 214,
            rules: [StalenessRule::Dead],
        );

        self::assertSame(9, $secret->uid);
        self::assertSame('stripe_test_old', $secret->identifier);
        self::assertSame('payment', $secret->context);
        self::assertSame('local', $secret->adapter);
        self::assertSame(123, $secret->lastReadAt);
        self::assertSame(2, $secret->automatedReads);
        self::assertSame(5, $secret->manualReveals);
        self::assertSame(214, $secret->ageDays);
        self::assertSame([StalenessRule::Dead], $secret->rules);
    }

    /**
     * @param list<StalenessRule> $rules
     */
    private function secretWithRules(array $rules): StaleSecret
    {
        return new StaleSecret(
            uid: 1,
            identifier: 'k',
            context: '',
            adapter: 'local',
            lastReadAt: null,
            automatedReads: 0,
            manualReveals: 0,
            ageDays: 1,
            rules: $rules,
        );
    }
}
