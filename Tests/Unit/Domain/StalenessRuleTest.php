<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain;

use Netresearch\NrVault\Domain\StalenessRule;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(StalenessRule::class)]
final class StalenessRuleTest extends TestCase
{
    #[Test]
    #[DataProvider('severityProvider')]
    public function severityMapsToBootstrapContext(StalenessRule $rule, string $expected): void
    {
        self::assertSame($expected, $rule->severity());
    }

    /**
     * @return iterable<string, array{StalenessRule, string}>
     */
    public static function severityProvider(): iterable
    {
        yield 'dead is danger' => [StalenessRule::Dead, 'danger'];
        yield 'expired is danger' => [StalenessRule::Expired, 'danger'];
        yield 'automation-stale is warning' => [StalenessRule::AutomationStale, 'warning'];
        yield 'never-rotated is warning' => [StalenessRule::NeverRotated, 'warning'];
    }

    #[Test]
    public function eachCaseHasNonEmptyLabel(): void
    {
        foreach (StalenessRule::cases() as $rule) {
            self::assertNotSame('', $rule->label());
        }
    }
}
