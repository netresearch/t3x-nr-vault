<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Result;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Doctrine\DBAL\Schema\Column;
use Netresearch\NrVault\Domain\Dto\OrphanReference;
use Netresearch\NrVault\Service\OrphanReferenceChecker;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use RuntimeException;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\QueryRestrictionContainerInterface;

/**
 * What the checker makes of the lookups. The queries themselves run against a
 * real schema in SecretRecordLinkCleanupTest and
 * WorkspacePublishOrphanCleanupTest (Tests/AGENTS.md: a stubbed pool proves
 * the logic, never the SQL).
 */
#[CoversClass(OrphanReferenceChecker::class)]
#[AllowMockObjectsWithoutExpectations]
final class OrphanReferenceCheckerTest extends TestCase
{
    private const IDENTIFIER = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private ConnectionPool&MockObject $connectionPool;

    /** @var AbstractSchemaManager<AbstractPlatform>&MockObject */
    private AbstractSchemaManager&MockObject $schemaManager;

    private ExpressionBuilder&MockObject $expressionBuilder;

    protected function setUp(): void
    {
        parent::setUp();

        $this->schemaManager = $this->createMock(AbstractSchemaManager::class);
        $connection          = $this->createMock(Connection::class);
        $connection->method('createSchemaManager')->willReturn($this->schemaManager);

        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $this->expressionBuilder = $this->createMock(ExpressionBuilder::class);
    }

    #[Test]
    public function aSecretNoRowHoldsIsAnOrphan(): void
    {
        $this->mockTable(['api_key']);
        $this->mockHolderCount(0);

        self::assertTrue((new OrphanReferenceChecker($this->connectionPool))->isOrphaned($this->reference(), self::IDENTIFIER));
    }

    #[Test]
    public function aSecretSomeRowHoldsIsKept(): void
    {
        $this->mockTable(['api_key']);
        $this->mockHolderCount(1);

        self::assertFalse((new OrphanReferenceChecker($this->connectionPool))->isOrphaned($this->reference(), self::IDENTIFIER));
    }

    #[Test]
    public function aPlainFieldIsComparedByValue(): void
    {
        $this->mockTable(['api_key']);
        $this->mockHolderCount(0);
        $this->expressionBuilder->expects(self::once())->method('eq')->with('api_key', ':identifier')->willReturn('api_key = :identifier');
        $this->expressionBuilder->expects(self::never())->method('like');

        (new OrphanReferenceChecker($this->connectionPool))->isOrphaned($this->reference(), self::IDENTIFIER);
    }

    #[Test]
    public function aFlexFormFieldIsSearchedInsideTheXml(): void
    {
        $this->mockTable(['settings']);
        $this->mockHolderCount(0);
        $this->expressionBuilder->expects(self::once())->method('like')->with('settings', ':identifier')->willReturn('settings LIKE :identifier');
        $this->expressionBuilder->expects(self::never())->method('eq');

        (new OrphanReferenceChecker($this->connectionPool))->isOrphaned(new OrphanReference('tx_table', 'settings', 5, true), self::IDENTIFIER);
    }

    /**
     * DBAL keys listTableColumns() by the platform-quoted name of a reserved
     * word; the link holds the plain name.
     */
    #[Test]
    #[DataProvider('quotedKeyProvider')]
    public function aReservedWordColumnIsRecognised(string $quotedKey): void
    {
        $this->schemaManager->method('tablesExist')->willReturn(true);
        $this->schemaManager->method('listTableColumns')->willReturn([$quotedKey => self::createStub(Column::class)]);
        $this->mockHolderCount(0);

        $checker = new OrphanReferenceChecker($this->connectionPool);

        self::assertTrue($checker->isOrphaned(new OrphanReference('tx_table', 'key', 5), self::IDENTIFIER));
        self::assertSame([], $checker->getUnresolvedReferences());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function quotedKeyProvider(): iterable
    {
        yield 'SQLite / PostgreSQL' => ['"key"'];
        yield 'MySQL / MariaDB' => ['`key`'];
        yield 'SQL Server' => ['[key]'];
    }

    #[Test]
    public function columnNamesAreComparedCaseInsensitively(): void
    {
        $this->mockTable(['api_key']);
        $this->mockHolderCount(0);

        self::assertTrue((new OrphanReferenceChecker($this->connectionPool))->isOrphaned(new OrphanReference('tx_table', 'API_Key', 5), self::IDENTIFIER));
    }

    #[Test]
    public function theColumnsOfATableAreReadOnce(): void
    {
        $this->schemaManager->method('tablesExist')->willReturn(true);
        $this->schemaManager->expects(self::once())->method('listTableColumns')
            ->willReturn(['api_key' => self::createStub(Column::class)]);
        $this->mockHolderCount(0);

        $checker = new OrphanReferenceChecker($this->connectionPool);
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);
    }

    #[Test]
    public function aLinkWithoutFieldIsKept(): void
    {
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');
        $checker = new OrphanReferenceChecker($this->connectionPool);

        self::assertFalse($checker->isOrphaned(new OrphanReference('tx_table', '', 5), self::IDENTIFIER));
        self::assertSame('names no field', $checker->getUnresolvedReferences()[0]['reason']);
    }

    #[Test]
    public function anEmptyIdentifierIsKept(): void
    {
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');

        self::assertFalse((new OrphanReferenceChecker($this->connectionPool))->isOrphaned($this->reference(), ''));
    }

    #[Test]
    public function anUnknownTableIsKept(): void
    {
        $this->schemaManager->method('tablesExist')->willReturn(false);
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');
        $checker = new OrphanReferenceChecker($this->connectionPool);

        self::assertFalse($checker->isOrphaned($this->reference(), self::IDENTIFIER));
        self::assertSame('names an unknown table', $checker->getUnresolvedReferences()[0]['reason']);
    }

    #[Test]
    public function anUnknownColumnIsKept(): void
    {
        $this->mockTable(['title']);
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');
        $checker = new OrphanReferenceChecker($this->connectionPool);

        self::assertFalse($checker->isOrphaned($this->reference(), self::IDENTIFIER));
        self::assertSame('names an unknown field', $checker->getUnresolvedReferences()[0]['reason']);
    }

    #[Test]
    public function aFailingLookupIsKept(): void
    {
        $this->schemaManager->method('tablesExist')->willThrowException(new RuntimeException('connection lost', 1795700001));
        $checker = new OrphanReferenceChecker($this->connectionPool);

        self::assertFalse($checker->isOrphaned($this->reference(), self::IDENTIFIER));
        self::assertSame('could not be resolved: connection lost', $checker->getUnresolvedReferences()[0]['reason']);
    }

    #[Test]
    public function aKeptReferenceIsRecordedAndLoggedWithItsContext(): void
    {
        $this->schemaManager->method('tablesExist')->willReturn(false);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('warning')->with(
            self::stringContains('{identifier}'),
            [
                'identifier' => self::IDENTIFIER,
                'table'      => 'tx_table',
                'field'      => 'api_key',
                'uid'        => 5,
                'reason'     => 'names an unknown table',
            ],
        );

        $checker = new OrphanReferenceChecker($this->connectionPool, $logger);
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);

        self::assertSame(
            [['identifier' => self::IDENTIFIER, 'table' => 'tx_table', 'field' => 'api_key', 'uid' => 5, 'reason' => 'names an unknown table']],
            $checker->getUnresolvedReferences(),
        );
    }

    #[Test]
    public function aCheckedReferenceIsNotRecorded(): void
    {
        $this->mockTable(['api_key']);
        $this->mockHolderCount(1);
        $checker = new OrphanReferenceChecker($this->connectionPool);
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);

        self::assertSame([], $checker->getUnresolvedReferences());
    }

    private function reference(): OrphanReference
    {
        return new OrphanReference('tx_table', 'api_key', 5);
    }

    /**
     * @param list<string> $columns
     */
    private function mockTable(array $columns): void
    {
        $this->schemaManager->method('tablesExist')->willReturn(true);

        $list = [];
        foreach ($columns as $name) {
            $list[$name] = self::createStub(Column::class);
        }

        $this->schemaManager->method('listTableColumns')->willReturn($list);
    }

    private function mockHolderCount(int $count): void
    {
        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn($count);

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('getRestrictions')->willReturn($this->createMock(QueryRestrictionContainerInterface::class));
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('expr')->willReturn($this->expressionBuilder);
        $queryBuilder->method('escapeLikeWildcards')->willReturnArgument(0);
        $queryBuilder->method('createNamedParameter')->willReturn(':identifier');
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connectionPool->method('getQueryBuilderForTable')->willReturn($queryBuilder);
    }
}
