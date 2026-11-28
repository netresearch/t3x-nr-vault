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
use Netresearch\NrVault\Service\OrphanReferenceCheckerInterface;
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

use function array_column;

/**
 * What the checker makes of the lookups. The queries themselves run against a
 * real schema in SecretRecordLinkCleanupTest and
 * WorkspacePublishOrphanCleanupTest (Tests/AGENTS.md: a stubbed pool proves
 * the logic, never the SQL); the query count is pinned there as well.
 */
#[CoversClass(OrphanReferenceChecker::class)]
#[AllowMockObjectsWithoutExpectations]
final class OrphanReferenceCheckerTest extends TestCase
{
    private const IDENTIFIER = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const OTHER_IDENTIFIER = '01937b6e-4b6c-7abc-8def-0123456789ac';

    /** Placeholder the mocked query builder returns for every parameter. */
    private const PARAMETER = ':parameter';

    private const UNKNOWN_TABLE = 'names an unknown table';

    private ConnectionPool&MockObject $connectionPool;

    /** @var AbstractSchemaManager<AbstractPlatform>&MockObject */
    private AbstractSchemaManager&MockObject $schemaManager;

    private QueryBuilder&MockObject $queryBuilder;

    private ExpressionBuilder&MockObject $expressionBuilder;

    /** Whether the query being built is the holder count (not a select). */
    private bool $isCounting = false;

    /** What the primary-key read of the linked row returns. */
    private mixed $linkedRowValue = false;

    /** What the authoritative holder count (eq or LIKE) returns. */
    private int $holderCount = 0;

    protected function setUp(): void
    {
        parent::setUp();

        $this->schemaManager = $this->createMock(AbstractSchemaManager::class);
        $connection          = $this->createMock(Connection::class);
        $connection->method('createSchemaManager')->willReturn($this->schemaManager);

        $this->expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $this->expressionBuilder->method('eq')->willReturn('eq');
        $this->expressionBuilder->method('neq')->willReturn('neq');
        $this->expressionBuilder->method('like')->willReturn('like');

        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturnCallback(fn (): mixed => $this->isCounting ? $this->holderCount : $this->linkedRowValue);

        $this->queryBuilder = $this->createMock(QueryBuilder::class);
        $this->queryBuilder->method('getRestrictions')->willReturn($this->createMock(QueryRestrictionContainerInterface::class));
        $this->queryBuilder->method('select')->willReturnCallback(function (): QueryBuilder {
            $this->isCounting = false;

            return $this->queryBuilder;
        });
        $this->queryBuilder->method('count')->willReturnCallback(function (): QueryBuilder {
            $this->isCounting = true;

            return $this->queryBuilder;
        });
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('where')->willReturnSelf();
        $this->queryBuilder->method('expr')->willReturn($this->expressionBuilder);
        $this->queryBuilder->method('escapeLikeWildcards')->willReturnArgument(0);
        $this->queryBuilder->method('createNamedParameter')->willReturn(self::PARAMETER);
        $this->queryBuilder->method('executeQuery')->willReturn($result);

        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);
        $this->connectionPool->method('getQueryBuilderForTable')->willReturn($this->queryBuilder);
    }

    #[Test]
    public function aSecretItsLinkedRowHoldsIsKeptWithoutTheCount(): void
    {
        $this->mockTable(['uid', 'api_key']);
        $this->linkedRowValue = self::IDENTIFIER;
        $this->queryBuilder->expects(self::never())->method('count');

        self::assertFalse($this->checker()->isOrphaned($this->reference(), self::IDENTIFIER));
    }

    #[Test]
    public function aSecretNoRowHoldsIsAnOrphan(): void
    {
        $this->mockTable(['uid', 'api_key']);
        $this->linkedRowValue = '';
        $this->holderCount    = 0;

        self::assertTrue($this->checker()->isOrphaned($this->reference(), self::IDENTIFIER));
    }

    #[Test]
    public function aSecretAnotherRowHoldsIsKept(): void
    {
        $this->mockTable(['uid', 'api_key']);
        $this->linkedRowValue = '';
        $this->holderCount    = 1;

        self::assertFalse($this->checker()->isOrphaned($this->reference(), self::IDENTIFIER));
    }

    /**
     * The database's collation may match a value PHP does not (case, trailing
     * spaces under MySQL's defaults). A PHP miss is never the final answer:
     * the authoritative count decides, and here it finds the holder.
     */
    #[Test]
    public function aHolderOnlyTheDatabaseMatchesKeepsTheSecret(): void
    {
        $this->mockTable(['uid', 'api_key']);
        $this->linkedRowValue = strtoupper(self::IDENTIFIER) . ' ';
        $this->holderCount    = 1;
        $this->queryBuilder->expects(self::once())->method('count')->willReturnCallback(function (): QueryBuilder {
            $this->isCounting = true;

            return $this->queryBuilder;
        });

        self::assertFalse($this->checker()->isOrphaned($this->reference(), self::IDENTIFIER));
    }

    #[Test]
    public function aSecretWhoseLinkedRowIsGoneIsCheckedAgainstTheOtherRows(): void
    {
        $this->mockTable(['uid', 'api_key']);
        $this->linkedRowValue = false;
        $this->holderCount    = 1;

        self::assertFalse($this->checker()->isOrphaned($this->reference(), self::IDENTIFIER));
    }

    /**
     * Every secret its linked row does not hold costs one count; no column is
     * loaded into memory.
     */
    #[Test]
    public function eachSecretTheLinkedRowDoesNotHoldIsCountedOnce(): void
    {
        $this->mockTable(['uid', 'api_key']);
        $this->linkedRowValue = '';
        $this->queryBuilder->expects(self::exactly(2))->method('count')->willReturnCallback(function (): QueryBuilder {
            $this->isCounting = true;

            return $this->queryBuilder;
        });

        $checker = $this->checker();
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);
        $checker->isOrphaned($this->reference(), self::OTHER_IDENTIFIER);
    }

    #[Test]
    public function aTableWithoutUidIsScannedDirectly(): void
    {
        $this->mockTable(['api_key']);
        $this->linkedRowValue = self::IDENTIFIER; // would answer "held" if it were read
        $this->holderCount    = 0;

        self::assertTrue($this->checker()->isOrphaned($this->reference(), self::IDENTIFIER));
    }

    #[Test]
    public function aFlexFormSecretItsLinkedRowHoldsIsKept(): void
    {
        $this->mockTable(['uid', 'settings']);
        $this->linkedRowValue = '<T3FlexForms><value index="vDEF">' . self::IDENTIFIER . '</value></T3FlexForms>';
        $this->expressionBuilder->expects(self::never())->method('like');

        self::assertFalse($this->checker()->isOrphaned($this->flexReference(), self::IDENTIFIER));
    }

    #[Test]
    public function aFlexFormSecretAnotherRowHoldsIsFoundInsideTheXml(): void
    {
        $this->mockTable(['uid', 'settings']);
        $this->linkedRowValue = '<T3FlexForms/>';
        $this->holderCount    = 1;
        $this->expressionBuilder->expects(self::once())->method('like')->with('settings', self::PARAMETER)->willReturn('like');

        self::assertFalse($this->checker()->isOrphaned($this->flexReference(), self::IDENTIFIER));
    }

    #[Test]
    public function aFlexFormSecretNoXmlHoldsIsAnOrphan(): void
    {
        $this->mockTable(['uid', 'settings']);
        $this->linkedRowValue = '<T3FlexForms/>';
        $this->holderCount    = 0;

        self::assertTrue($this->checker()->isOrphaned($this->flexReference(), self::IDENTIFIER));
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
        $this->schemaManager->method('listTableColumns')->willReturn(['uid' => self::createStub(Column::class), $quotedKey => self::createStub(Column::class)]);
        $this->linkedRowValue = '';

        $checker = $this->checker();

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
        $this->mockTable(['uid', 'api_key']);
        $this->linkedRowValue = '';

        self::assertTrue($this->checker()->isOrphaned(new OrphanReference('tx_table', 'API_Key', 5), self::IDENTIFIER));
    }

    #[Test]
    public function tableAndColumnsAreIntrospectedOncePerRun(): void
    {
        $this->schemaManager->expects(self::once())->method('tablesExist')->willReturn(true);
        $this->schemaManager->expects(self::once())->method('listTableColumns')
            ->willReturn(['uid' => self::createStub(Column::class), 'api_key' => self::createStub(Column::class)]);
        $this->linkedRowValue = self::IDENTIFIER;

        $checker = $this->checker();
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);
    }

    #[Test]
    public function resetForgetsTheCachesOfTheEarlierRun(): void
    {
        $this->schemaManager->expects(self::exactly(2))->method('tablesExist')->willReturn(false);

        $checker = $this->checker();
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);
        $checker->reset();

        self::assertSame([], $checker->getUnresolvedReferences());
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);
    }

    #[Test]
    public function aLinkWithoutFieldIsKept(): void
    {
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');
        $checker = $this->checker();

        self::assertFalse($checker->isOrphaned(new OrphanReference('tx_table', '', 5), self::IDENTIFIER));
        self::assertSame('names no field', $checker->getUnresolvedReferences()[0]['reason']);
    }

    #[Test]
    public function anEmptyIdentifierIsKept(): void
    {
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');

        self::assertFalse($this->checker()->isOrphaned($this->reference(), ''));
    }

    #[Test]
    public function anUnknownTableIsKept(): void
    {
        $this->schemaManager->method('tablesExist')->willReturn(false);
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');
        $checker = $this->checker();

        self::assertFalse($checker->isOrphaned($this->reference(), self::IDENTIFIER));
        self::assertSame(self::UNKNOWN_TABLE, $checker->getUnresolvedReferences()[0]['reason']);
    }

    #[Test]
    public function anUnknownColumnIsKept(): void
    {
        $this->mockTable(['uid', 'title']);
        $this->connectionPool->expects(self::never())->method('getQueryBuilderForTable');
        $checker = $this->checker();

        self::assertFalse($checker->isOrphaned($this->reference(), self::IDENTIFIER));
        self::assertSame('names an unknown field', $checker->getUnresolvedReferences()[0]['reason']);
    }

    #[Test]
    public function aFailingLookupIsKept(): void
    {
        $this->schemaManager->method('tablesExist')->willThrowException(new RuntimeException('connection lost', 1795700001));
        $checker = $this->checker();

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
                'reason'     => self::UNKNOWN_TABLE,
                'transient'  => false,
            ],
        );

        $checker = new OrphanReferenceChecker($this->connectionPool, $logger);
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);

        self::assertSame(
            [['identifier' => self::IDENTIFIER, 'table' => 'tx_table', 'field' => 'api_key', 'uid' => 5, 'reason' => self::UNKNOWN_TABLE, 'transient' => false]],
            $checker->getUnresolvedReferences(),
        );
    }

    /**
     * A query or connection error may clear on the next run: the kept
     * reference is marked transient, which fails the cleanup run. A link
     * that cannot be checked as it stands is not (#565).
     */
    #[Test]
    public function aFailedLookupIsRecordedAsTransient(): void
    {
        $this->schemaManager->method('tablesExist')->willThrowException(new RuntimeException('connection lost', 1795000110));

        $checker = $this->checker();
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);

        self::assertSame([true], array_column($checker->getUnresolvedReferences(), 'transient'));
    }

    #[Test]
    public function aCheckedReferenceIsNotRecorded(): void
    {
        $this->mockTable(['uid', 'api_key']);
        $this->linkedRowValue = self::IDENTIFIER;
        $checker              = $this->checker();
        $checker->isOrphaned($this->reference(), self::IDENTIFIER);

        self::assertSame([], $checker->getUnresolvedReferences());
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function cutoffProvider(): iterable
    {
        $now = 1_800_000_000;

        yield 'no retention: the minimum age alone' => [0, $now - OrphanReferenceCheckerInterface::MINIMUM_AGE_SECONDS];
        yield 'negative retention reads as none' => [-3, $now - OrphanReferenceCheckerInterface::MINIMUM_AGE_SECONDS];
        yield 'one day: the retention is the stricter cutoff' => [1, $now - 86400];
        yield 'thirty days' => [30, $now - 30 * 86400];
    }

    #[Test]
    #[DataProvider('cutoffProvider')]
    public function theCutoffIsTheRetentionCappedByTheMinimumAge(int $retentionDays, int $expected): void
    {
        self::assertSame($expected, $this->checker()->deletionCutoff($retentionDays, 1_800_000_000));
    }

    private function checker(): OrphanReferenceChecker
    {
        return new OrphanReferenceChecker($this->connectionPool);
    }

    private function reference(): OrphanReference
    {
        return new OrphanReference('tx_table', 'api_key', 5);
    }

    private function flexReference(): OrphanReference
    {
        return new OrphanReference('tx_table', 'settings', 5, true);
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
}
