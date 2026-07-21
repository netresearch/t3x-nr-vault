<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Widgets\DataProvider;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Widgets\DataProvider\ActiveSecretCountDataProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\QueryRestrictionContainerInterface;

/**
 * Unit tests for {@see ActiveSecretCountDataProvider}.
 */
#[CoversClass(ActiveSecretCountDataProvider::class)]
final class ActiveSecretCountDataProviderTest extends TestCase
{
    /**
     * Field names passed to ExpressionBuilder::eq(), captured per test.
     *
     * @var list<string>
     */
    private array $eqFields = [];

    #[Test]
    #[DataProvider('countResultProvider')]
    public function getNumberNormalizesFetchOneResult(mixed $fetchOneResult, int $expected): void
    {
        $subject = new ActiveSecretCountDataProvider(
            $this->createConnectionPoolStub($fetchOneResult),
        );

        self::assertSame($expected, $subject->getNumber());
    }

    /**
     * @return iterable<string, array{0: mixed, 1: int}>
     */
    public static function countResultProvider(): iterable
    {
        yield 'integer count' => [5, 5];
        yield 'numeric-string count (MySQL aggregate)' => ['12', 12];
        yield 'zero rows' => [0, 0];
        yield 'false (no result row)' => [false, 0];
        yield 'null' => [null, 0];
    }

    #[Test]
    public function getNumberFiltersOnDeletedAndHiddenFlags(): void
    {
        $subject = new ActiveSecretCountDataProvider(
            $this->createConnectionPoolStub(3),
        );
        $subject->getNumber();

        self::assertSame(['deleted', 'hidden'], $this->eqFields);
    }

    private function createConnectionPoolStub(mixed $fetchOneResult): ConnectionPool
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchOne')->willReturn($fetchOneResult);

        $expressionBuilder = $this->createStub(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturnCallback(
            function (string $field): string {
                $this->eqFields[] = $field;

                return $field . ' = ?';
            },
        );

        $restrictions = $this->createStub(QueryRestrictionContainerInterface::class);

        $queryBuilder = $this->createStub(QueryBuilder::class);
        $queryBuilder->method('getRestrictions')->willReturn($restrictions);
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $queryBuilder->method('executeQuery')->willReturn($result);

        $connectionPool = $this->createStub(ConnectionPool::class);
        $connectionPool->method('getQueryBuilderForTable')->willReturn($queryBuilder);

        return $connectionPool;
    }
}
