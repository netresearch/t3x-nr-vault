<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use DateTimeImmutable;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AuditLogFilter::class)]
final class AuditLogFilterTest extends TestCase
{
    private const SINCE_DATE = '2024-01-01';

    #[Test]
    public function constructorWithNoArgumentsCreatesEmptyFilter(): void
    {
        $filter = new AuditLogFilter();

        self::assertNull($filter->secretIdentifier);
        self::assertNull($filter->action);
        self::assertNull($filter->actorUid);
        self::assertNull($filter->success);
        self::assertNull($filter->since);
        self::assertNull($filter->until);
        self::assertTrue($filter->isEmpty());
    }

    #[Test]
    public function forSecretCreatesFilterWithIdentifier(): void
    {
        $filter = AuditLogFilter::forSecret('api-key');

        self::assertEquals('api-key', $filter->secretIdentifier);
        self::assertFalse($filter->isEmpty());
    }

    #[Test]
    public function forActionCreatesFilterWithAction(): void
    {
        $filter = AuditLogFilter::forAction('read');

        self::assertEquals('read', $filter->action);
        self::assertFalse($filter->isEmpty());
    }

    #[Test]
    public function forActorCreatesFilterWithActorUid(): void
    {
        $filter = AuditLogFilter::forActor(42);

        self::assertEquals(42, $filter->actorUid);
        self::assertFalse($filter->isEmpty());
    }

    #[Test]
    public function failedOnlyCreatesFilterWithSuccessFalse(): void
    {
        $filter = AuditLogFilter::failedOnly();

        self::assertFalse($filter->success);
        self::assertFalse($filter->isEmpty());
    }

    #[Test]
    public function dateRangeCreatesFilterWithDates(): void
    {
        $since = new DateTimeImmutable(self::SINCE_DATE);
        $until = new DateTimeImmutable('2024-01-31');

        $filter = AuditLogFilter::dateRange($since, $until);

        self::assertSame($since, $filter->since);
        self::assertSame($until, $filter->until);
        self::assertFalse($filter->isEmpty());
    }

    #[Test]
    public function withSecretReturnsNewFilterWithIdentifier(): void
    {
        $original = AuditLogFilter::forAction('read');
        $modified = $original->withSecret('api-key');

        self::assertNotSame($original, $modified);
        self::assertEquals('api-key', $modified->secretIdentifier);
        self::assertEquals('read', $modified->action);
    }

    #[Test]
    public function withActionReturnsNewFilterWithAction(): void
    {
        $original = AuditLogFilter::forSecret('api-key');
        $modified = $original->withAction('delete');

        self::assertNotSame($original, $modified);
        self::assertEquals('api-key', $modified->secretIdentifier);
        self::assertEquals('delete', $modified->action);
    }

    #[Test]
    public function withActorReturnsNewFilterWithActorUid(): void
    {
        $original = AuditLogFilter::forSecret('api-key');
        $modified = $original->withActor(42);

        self::assertNotSame($original, $modified);
        self::assertEquals('api-key', $modified->secretIdentifier);
        self::assertEquals(42, $modified->actorUid);
    }

    #[Test]
    public function withSuccessReturnsNewFilterWithSuccess(): void
    {
        $original = AuditLogFilter::forSecret('api-key');
        $modified = $original->withSuccess(true);

        self::assertNotSame($original, $modified);
        self::assertEquals('api-key', $modified->secretIdentifier);
        self::assertTrue($modified->success);
    }

    #[Test]
    public function withDateRangeReturnsNewFilterWithDates(): void
    {
        $since = new DateTimeImmutable(self::SINCE_DATE);
        $until = new DateTimeImmutable('2024-01-31');

        $original = AuditLogFilter::forSecret('api-key');
        $modified = $original->withDateRange($since, $until);

        self::assertNotSame($original, $modified);
        self::assertEquals('api-key', $modified->secretIdentifier);
        self::assertSame($since, $modified->since);
        self::assertSame($until, $modified->until);
    }

    #[Test]
    public function isEmptyReturnsTrueForEmptyFilter(): void
    {
        $filter = new AuditLogFilter();

        self::assertTrue($filter->isEmpty());
    }

    #[Test]
    public function isEmptyReturnsFalseWhenAnyFieldSet(): void
    {
        self::assertFalse(AuditLogFilter::forSecret('test')->isEmpty());
        self::assertFalse(AuditLogFilter::forAction('read')->isEmpty());
        self::assertFalse(AuditLogFilter::forActor(1)->isEmpty());
        self::assertFalse(AuditLogFilter::failedOnly()->isEmpty());
        self::assertFalse(AuditLogFilter::dateRange(new DateTimeImmutable())->isEmpty());
    }

    #[Test]
    public function chainingMethodsBuildsComplexFilter(): void
    {
        $since = new DateTimeImmutable(self::SINCE_DATE);

        $filter = AuditLogFilter::forSecret('api-key')
            ->withAction('read')
            ->withActor(42)
            ->withSuccess(true)
            ->withDateRange($since);

        self::assertEquals('api-key', $filter->secretIdentifier);
        self::assertEquals('read', $filter->action);
        self::assertEquals(42, $filter->actorUid);
        self::assertTrue($filter->success);
        self::assertSame($since, $filter->since);
    }
}
