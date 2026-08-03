<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Dto;

use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(SecretFilters::class)]
final class SecretFiltersTest extends TestCase
{
    #[Test]
    public function constructorDefaultsAllPropertiesToNull(): void
    {
        $subject = new SecretFilters();

        self::assertNull($subject->owner);
        self::assertNull($subject->prefix);
        self::assertNull($subject->context);
        self::assertNull($subject->scopePid);
    }

    #[Test]
    public function constructorSetsProvidedValues(): void
    {
        $subject = new SecretFilters(
            owner: 5,
            prefix: 'app/',
            context: 'backend',
            scopePid: 3,
        );

        self::assertSame(5, $subject->owner);
        self::assertSame('app/', $subject->prefix);
        self::assertSame('backend', $subject->context);
        self::assertSame(3, $subject->scopePid);
    }

    #[Test]
    public function fromArrayCreatesObjectWithAllFields(): void
    {
        $subject = SecretFilters::fromArray([
            'owner' => 10,
            'prefix' => 'service/',
            'context' => 'default',
            'scopePid' => 7,
        ]);

        self::assertSame(10, $subject->owner);
        self::assertSame('service/', $subject->prefix);
        self::assertSame('default', $subject->context);
        self::assertSame(7, $subject->scopePid);
    }

    #[Test]
    public function fromArrayWithEmptyArrayCreatesObjectWithNullDefaults(): void
    {
        $subject = SecretFilters::fromArray([]);

        self::assertNull($subject->owner);
        self::assertNull($subject->prefix);
        self::assertNull($subject->context);
        self::assertNull($subject->scopePid);
    }

    #[Test]
    public function fromArrayIgnoresMissingOptionalFields(): void
    {
        $subject = SecretFilters::fromArray(['owner' => 3]);

        self::assertSame(3, $subject->owner);
        self::assertNull($subject->prefix);
        self::assertNull($subject->context);
        self::assertNull($subject->scopePid);
    }

    #[Test]
    public function hasFiltersReturnsFalseWhenNoFiltersSet(): void
    {
        $subject = new SecretFilters();

        self::assertFalse($subject->hasFilters());
    }

    #[Test]
    #[DataProvider('hasFiltersProvider')]
    public function hasFiltersReturnsTrueWhenAnyFilterIsSet(SecretFilters $subject): void
    {
        self::assertTrue($subject->hasFilters());
    }

    public static function hasFiltersProvider(): iterable
    {
        yield 'owner set' => [new SecretFilters(owner: 1)];
        yield 'prefix set' => [new SecretFilters(prefix: 'app/')];
        yield 'context set' => [new SecretFilters(context: 'default')];
        yield 'scopePid set' => [new SecretFilters(scopePid: 5)];
        yield 'all set' => [new SecretFilters(owner: 1, prefix: 'p', context: 'c', scopePid: 2)];
    }

    #[Test]
    public function toArrayOmitsNullValues(): void
    {
        $subject = new SecretFilters();

        self::assertSame([], $subject->toArray());
    }

    #[Test]
    public function toArrayIncludesOnlySetValues(): void
    {
        $subject = new SecretFilters(owner: 5, prefix: 'api/');

        $array = $subject->toArray();

        self::assertSame(['owner' => 5, 'prefix' => 'api/'], $array);
        self::assertArrayNotHasKey('context', $array);
        self::assertArrayNotHasKey('scopePid', $array);
    }

    #[Test]
    public function toArrayWithAllFiltersSetReturnsAllKeys(): void
    {
        $subject = new SecretFilters(
            owner: 1,
            prefix: 'svc/',
            context: 'backend',
            scopePid: 3,
        );

        self::assertSame([
            'owner' => 1,
            'prefix' => 'svc/',
            'context' => 'backend',
            'scopePid' => 3,
        ], $subject->toArray());
    }

    #[Test]
    #[DataProvider('toArraySingleFieldProvider')]
    public function toArrayIncludesOnlyNonNullField(
        SecretFilters $subject,
        string $expectedKey,
        mixed $expectedValue,
    ): void {
        $array = $subject->toArray();

        self::assertCount(1, $array);
        self::assertArrayHasKey($expectedKey, $array);
        self::assertSame($expectedValue, $array[$expectedKey]);
    }

    public static function toArraySingleFieldProvider(): iterable
    {
        yield 'only owner' => [new SecretFilters(owner: 42), 'owner', 42];
        yield 'only prefix' => [new SecretFilters(prefix: 'myapp/'), 'prefix', 'myapp/'];
        yield 'only context' => [new SecretFilters(context: 'frontend'), 'context', 'frontend'];
        yield 'only scopePid' => [new SecretFilters(scopePid: 10), 'scopePid', 10];
    }

    #[Test]
    public function fromArrayRoundTripToArray(): void
    {
        $original = [
            'owner' => 7,
            'prefix' => 'test/',
            'context' => 'backend',
            'scopePid' => 5,
            'includeDisabled' => true,
        ];

        $subject = SecretFilters::fromArray($original);

        self::assertSame($original, $subject->toArray());
    }

    /**
     * `includeDisabled` widens the result set instead of restricting it, so it
     * must not count as a filter — a query carrying only that flag is an
     * unfiltered listing that happens to include disabled secrets. Counting it
     * would make callers that branch on `hasFilters()` treat the widest
     * possible query as the narrowest.
     */
    #[Test]
    public function includeDisabledDoesNotCountAsAFilter(): void
    {
        $subject = new SecretFilters(includeDisabled: true);

        self::assertTrue($subject->includeDisabled);
        self::assertFalse($subject->hasFilters());
    }

    #[Test]
    public function includeDisabledDefaultsToOff(): void
    {
        self::assertFalse((new SecretFilters())->includeDisabled);
        self::assertFalse(SecretFilters::fromArray([])->includeDisabled);
        self::assertArrayNotHasKey('includeDisabled', (new SecretFilters())->toArray());
    }
}
