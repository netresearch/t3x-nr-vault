<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Hook\RecordLinkFactory;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\QueryRestrictionContainerInterface;
use TYPO3\CMS\Core\Schema\TcaSchema;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

/**
 * The record link names the live record: a workspace version row is linked
 * through its t3ver_oid (#565). The query itself runs against a real schema
 * in WorkspacePublishOrphanCleanupTest.
 */
#[CoversClass(RecordLinkFactory::class)]
#[AllowMockObjectsWithoutExpectations]
final class RecordLinkFactoryTest extends TestCase
{
    private ConnectionPool&MockObject $connectionPool;

    private TcaSchemaFactory&MockObject $schemaFactory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->schemaFactory  = $this->createMock(TcaSchemaFactory::class);
    }

    #[Test]
    public function aVersionRowIsLinkedThroughItsLiveUid(): void
    {
        $this->mockSchema(workspaceAware: true);
        $this->mockOriginalUid(7);

        self::assertSame(7, $this->subject()->liveUid('tx_table', 12));
    }

    #[Test]
    public function aLiveRowKeepsItsUid(): void
    {
        $this->mockSchema(workspaceAware: true);
        $this->mockOriginalUid(0);

        self::assertSame(12, $this->subject()->liveUid('tx_table', 12));
    }

    #[Test]
    public function aMissingRowKeepsItsUid(): void
    {
        $this->mockSchema(workspaceAware: true);
        $this->mockOriginalUid(false);

        self::assertSame(12, $this->subject()->liveUid('tx_table', 12));
    }

    #[Test]
    public function aTableWithoutVersioningIsNotQueried(): void
    {
        $this->mockSchema(workspaceAware: false);
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');

        self::assertSame(12, $this->subject()->liveUid('tx_table', 12));
    }

    #[Test]
    public function aTableWithoutSchemaIsNotQueried(): void
    {
        $this->schemaFactory->method('has')->willReturn(false);
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');

        self::assertSame(12, $this->subject()->liveUid('tx_unknown', 12));
    }

    #[Test]
    #[DataProvider('nonPositiveUidProvider')]
    public function aNonPositiveUidIsReturnedUnchecked(int $uid): void
    {
        $this->schemaFactory->expects(self::never())->method('has');

        self::assertSame($uid, $this->subject()->liveUid('tx_table', $uid));
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function nonPositiveUidProvider(): iterable
    {
        yield 'zero (unresolved NEW id)' => [0];
        yield 'negative' => [-1];
    }

    #[Test]
    public function forFieldLinksTheLiveUid(): void
    {
        $this->mockSchema(workspaceAware: true);
        $this->mockOriginalUid(7);

        self::assertSame(
            ['source' => 'tca_field', 'table' => 'tx_table', 'field' => 'api_key', 'uid' => 7, 'copied_from' => 'x'],
            $this->subject()->forField('tca_field', 'tx_table', 'api_key', 12, ['copied_from' => 'x']),
        );
    }

    #[Test]
    public function forFlexFieldLinksTheLiveUid(): void
    {
        $this->mockSchema(workspaceAware: true);
        $this->mockOriginalUid(7);

        self::assertSame(
            ['source' => 'flexform_field', 'table' => 'tx_table', 'flexField' => 'settings', 'uid' => 7],
            $this->subject()->forFlexField('flexform_field', 'tx_table', 'settings', 12),
        );
    }

    private function subject(): RecordLinkFactory
    {
        return new RecordLinkFactory($this->connectionPool, $this->schemaFactory);
    }

    private function mockSchema(bool $workspaceAware): void
    {
        $schema = $this->createMock(TcaSchema::class);
        $schema->method('isWorkspaceAware')->willReturn($workspaceAware);

        $this->schemaFactory->method('has')->willReturn(true);
        $this->schemaFactory->method('get')->willReturn($schema);
    }

    private function mockOriginalUid(int|false $originalUid): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn($originalUid);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('uid = :uid');

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('getRestrictions')->willReturn($this->createMock(QueryRestrictionContainerInterface::class));
        $queryBuilder->expects(self::once())->method('select')->with('t3ver_oid')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':uid');
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connectionPool->method('getQueryBuilderForTable')->willReturn($queryBuilder);
    }
}
