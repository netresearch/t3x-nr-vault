<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

// Enums are not valid coverage targets in PHPUnit 12
#[CoversNothing]
final class SecretPlacementTest extends TestCase
{
    #[Test]
    public function allCasesHaveDescriptions(): void
    {
        foreach (SecretPlacement::cases() as $case) {
            $description = $case->description();
            self::assertNotSame('', $description, "Case {$case->name} should have a description");
            self::assertIsString($description);
        }
    }

    #[Test]
    #[DataProvider('configRequirementProvider')]
    public function requiresConfigReturnsCorrectValue(SecretPlacement $placement, bool $expected): void
    {
        self::assertSame($expected, $placement->requiresConfig());
    }

    public static function configRequirementProvider(): iterable
    {
        yield 'Bearer does not require config' => [SecretPlacement::Bearer, false];
        yield 'BasicAuth does not require config' => [SecretPlacement::BasicAuth, false];
        yield 'Header requires config' => [SecretPlacement::Header, true];
        yield 'QueryParam requires config' => [SecretPlacement::QueryParam, true];
        yield 'BodyField requires config' => [SecretPlacement::BodyField, true];
        yield 'OAuth2 requires config' => [SecretPlacement::OAuth2, true];
        yield 'ApiKey does not require config' => [SecretPlacement::ApiKey, false];
    }

    #[Test]
    #[DataProvider('defaultConfigKeyProvider')]
    public function defaultConfigKeyReturnsCorrectValue(SecretPlacement $placement, ?string $expected): void
    {
        self::assertSame($expected, $placement->defaultConfigKey());
    }

    public static function defaultConfigKeyProvider(): iterable
    {
        yield 'Header defaults to X-API-Key' => [SecretPlacement::Header, 'X-API-Key'];
        yield 'QueryParam defaults to api_key' => [SecretPlacement::QueryParam, 'api_key'];
        yield 'BodyField defaults to api_key' => [SecretPlacement::BodyField, 'api_key'];
        yield 'Bearer has no default key' => [SecretPlacement::Bearer, null];
        yield 'BasicAuth has no default key' => [SecretPlacement::BasicAuth, null];
        yield 'OAuth2 has no default key' => [SecretPlacement::OAuth2, null];
        yield 'ApiKey defaults to X-API-Key' => [SecretPlacement::ApiKey, 'X-API-Key'];
    }

    #[Test]
    public function tryFromReturnsCorrectCase(): void
    {
        self::assertSame(SecretPlacement::Bearer, SecretPlacement::tryFrom('bearer'));
        self::assertSame(SecretPlacement::BasicAuth, SecretPlacement::tryFrom('basic'));
        self::assertSame(SecretPlacement::Header, SecretPlacement::tryFrom('header'));
        self::assertSame(SecretPlacement::QueryParam, SecretPlacement::tryFrom('query'));
        self::assertSame(SecretPlacement::BodyField, SecretPlacement::tryFrom('body_field'));
        self::assertSame(SecretPlacement::OAuth2, SecretPlacement::tryFrom('oauth2'));
        self::assertSame(SecretPlacement::ApiKey, SecretPlacement::tryFrom('api_key'));
    }

    #[Test]
    public function tryFromReturnsNullForInvalidValue(): void
    {
        self::assertNull(SecretPlacement::tryFrom('invalid'));
        self::assertNull(SecretPlacement::tryFrom(''));
        self::assertNull(SecretPlacement::tryFrom('BEARER'));
    }

    #[Test]
    public function casesReturnsAllValues(): void
    {
        $cases = SecretPlacement::cases();

        self::assertCount(7, $cases);
        self::assertContains(SecretPlacement::Bearer, $cases);
        self::assertContains(SecretPlacement::BasicAuth, $cases);
        self::assertContains(SecretPlacement::Header, $cases);
        self::assertContains(SecretPlacement::QueryParam, $cases);
        self::assertContains(SecretPlacement::BodyField, $cases);
        self::assertContains(SecretPlacement::OAuth2, $cases);
        self::assertContains(SecretPlacement::ApiKey, $cases);
    }
}
