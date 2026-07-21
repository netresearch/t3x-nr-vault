<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Widgets\DataProvider;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Widgets\DataProvider\AuditActivityDataProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Unit tests for {@see AuditActivityDataProvider}.
 */
#[CoversClass(AuditActivityDataProvider::class)]
final class AuditActivityDataProviderTest extends TestCase
{
    private const DAY = 86400;

    /** 2026-07-01T00:00:00Z — a fixed UTC day-start for deterministic buckets. */
    private const FIRST_DAY = 1_782_864_000;

    #[Test]
    public function shapeChartDataZeroFillsDaysWithoutActivity(): void
    {
        $shaped = AuditActivityDataProvider::shapeChartData(
            [
                ['day_start' => self::FIRST_DAY, 'entry_count' => 4],
                ['day_start' => self::FIRST_DAY + (2 * self::DAY), 'entry_count' => 7],
            ],
            self::FIRST_DAY,
            4,
        );

        self::assertSame(['2026-07-01', '2026-07-02', '2026-07-03', '2026-07-04'], $shaped['labels']);
        self::assertCount(1, $shaped['datasets']);
        self::assertSame('Audit events', $shaped['datasets'][0]['label']);
        self::assertSame([4, 0, 7, 0], $shaped['datasets'][0]['data']);
        self::assertCount(4, $shaped['datasets'][0]['backgroundColor']);
    }

    #[Test]
    public function shapeChartDataCastsNumericStringAggregates(): void
    {
        // MySQL COUNT(*) and the day_start literal can come back as strings.
        $shaped = AuditActivityDataProvider::shapeChartData(
            [
                ['day_start' => (string) self::FIRST_DAY, 'entry_count' => '42'],
            ],
            self::FIRST_DAY,
            1,
        );

        self::assertSame([42], $shaped['datasets'][0]['data']);
    }

    #[Test]
    public function shapeChartDataSkipsRowsWithNonNumericDayStart(): void
    {
        $shaped = AuditActivityDataProvider::shapeChartData(
            [
                ['day_start' => null, 'entry_count' => 50],
                ['day_start' => 'not-a-timestamp', 'entry_count' => 60],
                ['day_start' => self::FIRST_DAY, 'entry_count' => 3],
            ],
            self::FIRST_DAY,
            2,
        );

        self::assertSame([3, 0], $shaped['datasets'][0]['data']);
    }

    #[Test]
    public function shapeChartDataTreatsMissingEntryCountAsZero(): void
    {
        $shaped = AuditActivityDataProvider::shapeChartData(
            [
                ['day_start' => self::FIRST_DAY],
            ],
            self::FIRST_DAY,
            1,
        );

        self::assertSame([0], $shaped['datasets'][0]['data']);
    }

    #[Test]
    public function shapeChartDataIgnoresRowsOutsideTheWindow(): void
    {
        $shaped = AuditActivityDataProvider::shapeChartData(
            [
                ['day_start' => self::FIRST_DAY - self::DAY, 'entry_count' => 99],
            ],
            self::FIRST_DAY,
            2,
        );

        self::assertSame([0, 0], $shaped['datasets'][0]['data']);
    }

    #[Test]
    public function getChartDataRunsSingleGroupedQueryAndCoversConfiguredDays(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchAllAssociative')->willReturn([]);

        $expressionBuilder = $this->createStub(ExpressionBuilder::class);
        $expressionBuilder->method('gte')->willReturn('crdate >= ?');

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('addSelectLiteral')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('groupBy')->willReturnSelf();
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $queryBuilder->expects(self::once())->method('executeQuery')->willReturn($result);

        $connectionPool = $this->createStub(ConnectionPool::class);
        $connectionPool->method('getQueryBuilderForTable')->willReturn($queryBuilder);

        $shaped = (new AuditActivityDataProvider($connectionPool, 14))->getChartData();

        self::assertCount(14, $shaped['labels']);
        self::assertSame(array_fill(0, 14, 0), $shaped['datasets'][0]['data']);
    }
}
