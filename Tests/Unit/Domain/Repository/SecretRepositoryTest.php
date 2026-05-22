<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Domain\Repository;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepository;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use RuntimeException;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Unit tests for {@see SecretRepository}.
 *
 * NOTE: {@see \PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations}
 * is intentionally NOT used — it would mask orphaned mocks (real wiring bugs).
 */
#[CoversClass(SecretRepository::class)]
final class SecretRepositoryTest extends TestCase
{
    private SecretRepository $subject;

    private ConnectionPool $connectionPool;

    private Connection $connection;

    private QueryBuilder $queryBuilder;

    private ExpressionBuilder $expressionBuilder;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionPool = $this->createStub(ConnectionPool::class);
        $this->connection = $this->createStub(Connection::class);
        $this->queryBuilder = $this->createStub(QueryBuilder::class);
        $this->expressionBuilder = $this->createStub(ExpressionBuilder::class);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($this->connection);

        $this->connection
            ->method('createQueryBuilder')
            ->willReturn($this->queryBuilder);

        $this->queryBuilder
            ->method('expr')
            ->willReturn($this->expressionBuilder);

        $this->subject = new SecretRepository($this->connectionPool);
    }

    #[Test]
    public function findByIdentifierReturnsNullWhenNotFound(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchAssociative')->willReturn(false);

        $this->setupQueryBuilderForSelect($result);

        self::assertNull($this->subject->findByIdentifier('nonexistent'));
    }

    #[Test]
    public function findByIdentifierReturnsSecretWhenFound(): void
    {
        $secretRow = $this->createSecretRow('test-id');
        $result = $this->createStub(Result::class);
        $result->method('fetchAssociative')->willReturn($secretRow);

        // Group load issues a second executeQuery on the MM table — wire both
        // result mocks explicitly instead of letting fetchAllAssociative
        // silently default to []. Passing the same $result mock previously
        // made the test pass for the wrong reason.
        $groupResult = $this->createStub(Result::class);
        $groupResult->method('fetchAllAssociative')->willReturn([]);

        $this->setupQueryBuilderForSelect($result);
        $this->queryBuilder->method('executeQuery')
            ->willReturnOnConsecutiveCalls($result, $groupResult);

        $secret = $this->subject->findByIdentifier('test-id');

        self::assertInstanceOf(Secret::class, $secret);
        self::assertSame('test-id', $secret->getIdentifier());
    }

    #[Test]
    public function findByUidReturnsNullWhenNotFound(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchAssociative')->willReturn(false);

        $this->setupQueryBuilderForSelect($result);

        self::assertNull($this->subject->findByUid(999));
    }

    #[Test]
    public function findByUidReturnsSecretWhenFound(): void
    {
        $secretRow = $this->createSecretRow('uid-test', 42);
        $result = $this->createStub(Result::class);
        $result->method('fetchAssociative')->willReturn($secretRow);

        $groupResult = $this->createStub(Result::class);
        $groupResult->method('fetchAllAssociative')->willReturn([]);

        $this->setupQueryBuilderForSelect($result);
        $this->queryBuilder->method('executeQuery')
            ->willReturnOnConsecutiveCalls($result, $groupResult);

        $secret = $this->subject->findByUid(42);

        self::assertInstanceOf(Secret::class, $secret);
        self::assertSame(42, $secret->getUid());
    }

    #[Test]
    public function existsReturnsFalseWhenNotFound(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchOne')->willReturn(0);

        $this->setupQueryBuilderForCount($result);

        self::assertFalse($this->subject->exists('nonexistent'));
    }

    #[Test]
    public function existsReturnsTrueWhenFound(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchOne')->willReturn(1);

        $this->setupQueryBuilderForCount($result);

        self::assertTrue($this->subject->exists('test-id'));
    }

    #[Test]
    public function saveInsertsNewSecret(): void
    {
        $connection = $this->useStrictConnectionMock();

        $secret = $this->newEncryptedSecret('new-secret');

        $connection
            ->expects(self::once())
            ->method('insert')
            ->with('tx_nrvault_secret', self::callback(static fn (array $data): bool => $data['identifier'] === 'new-secret'
                && isset($data['crdate'])));

        $connection
            ->method('lastInsertId')
            ->willReturn('1');

        // Mock MM table delete (no groups)
        $connection
            ->method('delete')
            ->with('tx_nrvault_secret_begroups_mm', self::anything());

        $saved = $this->subject->save($secret);

        // save() returns a NEW instance on INSERT (uid attached); the
        // original is left unmutated by design.
        self::assertNull($secret->getUid());
        self::assertSame(1, $saved->getUid());
    }

    #[Test]
    public function saveUpdatesExistingSecret(): void
    {
        $connection = $this->useStrictConnectionMock();

        $secret = $this->newEncryptedSecret('existing-secret', uid: 42);

        $connection
            ->expects(self::once())
            ->method('update')
            ->with(
                'tx_nrvault_secret',
                self::anything(),
                ['uid' => 42],
            );

        // Mock MM table delete
        $connection
            ->method('delete')
            ->with('tx_nrvault_secret_begroups_mm', ['uid_local' => 42]);

        $this->subject->save($secret);
    }

    #[Test]
    public function deleteDoesNothingForNewSecret(): void
    {
        $connection = $this->useStrictConnectionMock();

        $secret = new Secret(identifier: 'new-unsaved');

        $connection
            ->expects(self::never())
            ->method('update');

        $this->subject->delete($secret);
    }

    #[Test]
    public function deleteSoftDeletesExistingSecret(): void
    {
        $connection = $this->useStrictConnectionMock();

        $secret = new Secret(identifier: 'to-delete', uid: 42);

        $connection
            ->expects(self::once())
            ->method('update')
            ->with(
                'tx_nrvault_secret',
                self::callback(static fn (array $data): bool => $data['deleted'] === 1 && isset($data['tstamp'])),
                ['uid' => 42],
            );

        $this->subject->delete($secret);
    }

    #[Test]
    public function findIdentifiersReturnsEmptyArrayWhenNone(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchAssociative')->willReturn(false);

        $this->setupQueryBuilderForSelect($result);

        $identifiers = $this->subject->findIdentifiers();

        self::assertSame([], $identifiers);
    }

    #[Test]
    public function findIdentifiersReturnsIdentifiers(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchAssociative')
            ->willReturnOnConsecutiveCalls(
                ['identifier' => 'secret-1'],
                ['identifier' => 'secret-2'],
                false,
            );

        $this->setupQueryBuilderForSelect($result);

        $identifiers = $this->subject->findIdentifiers();

        self::assertSame(['secret-1', 'secret-2'], $identifiers);
    }

    #[Test]
    public function findIdentifiersWithOwnerFilter(): void
    {
        $queryBuilder = $this->useStrictQueryBuilderMock();

        $result = $this->createStub(Result::class);
        $result->method('fetchAssociative')->willReturn(false);

        $this->setupQueryBuilderForSelect($result);

        $queryBuilder
            ->expects(self::atLeastOnce())
            ->method('andWhere')
            ->willReturnSelf();

        $this->subject->findIdentifiers(new SecretFilters(owner: 1));
    }

    #[Test]
    public function findIdentifiersWithPrefixFilter(): void
    {
        [$queryBuilder, $expressionBuilder] = $this->useStrictQueryBuilderAndExpressionBuilderMocks();

        $result = $this->createStub(Result::class);
        $result->method('fetchAssociative')->willReturn(false);

        $this->setupQueryBuilderForSelect($result);

        $queryBuilder
            ->expects(self::atLeastOnce())
            ->method('andWhere')
            ->willReturnSelf();

        $expressionBuilder
            ->expects(self::atLeastOnce())
            ->method('like')
            ->willReturn('identifier LIKE ?');

        $this->subject->findIdentifiers(new SecretFilters(prefix: 'api-'));
    }

    #[Test]
    public function findByGroupsReturnsEmptyArrayWhenNoGroups(): void
    {
        $result = $this->subject->findByGroups([]);

        self::assertSame([], $result);
    }

    #[Test]
    public function findByGroupsReturnsEmptyArrayWhenNoSecrets(): void
    {
        $mmResult = $this->createStub(Result::class);
        $mmResult->method('fetchFirstColumn')->willReturn([]);

        $this->setupQueryBuilderForSelect($mmResult);

        $result = $this->subject->findByGroups([1, 2]);

        self::assertSame([], $result);
    }

    #[Test]
    public function findExpiredReturnsExpiredSecrets(): void
    {
        $expiredRow = $this->createSecretRow('expired', 1);
        $expiredRow['expires_at'] = time() - 3600;

        $result = $this->createStub(Result::class);
        $result->method('fetchAllAssociative')->willReturn([$expiredRow]);

        $this->setupQueryBuilderForSelect($result);

        $secrets = $this->subject->findExpired();

        self::assertCount(1, $secrets);
        self::assertSame('expired', $secrets[0]->getIdentifier());
    }

    #[Test]
    public function findExpiringSoonReturnsSecretsExpiringSoon(): void
    {
        $soonRow = $this->createSecretRow('expiring-soon', 1);
        $soonRow['expires_at'] = time() + 3600;

        $result = $this->createStub(Result::class);
        $result->method('fetchAllAssociative')->willReturn([$soonRow]);

        $this->setupQueryBuilderForSelect($result);

        $secrets = $this->subject->findExpiringSoon(7);

        self::assertCount(1, $secrets);
    }

    #[Test]
    public function countAllReturnsCount(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchOne')->willReturn(5);

        $this->setupQueryBuilderForCount($result);

        self::assertSame(5, $this->subject->countAll());
    }

    #[Test]
    public function countAllReturnsZeroForNonNumericFetchOne(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchOne')->willReturn('not-a-number');

        $this->setupQueryBuilderForCount($result);

        self::assertSame(0, $this->subject->countAll());
    }

    #[Test]
    public function findByIdentifierLoadsGroupsWhenPresent(): void
    {
        // Use a fresh subject to avoid setUp createQueryBuilder stub conflict
        $connectionPool = $this->createStub(ConnectionPool::class);
        $connection = $this->createStub(Connection::class);
        $expressionBuilder = $this->createStub(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('field = ?');

        $connectionPool->method('getConnectionForTable')->willReturn($connection);
        $subject = new SecretRepository($connectionPool);

        $secretRow = $this->createSecretRow('secret-with-groups', 10);

        $secretResult = $this->createStub(Result::class);
        $secretResult->method('fetchAssociative')->willReturn($secretRow);

        $groupResult = $this->createStub(Result::class);
        $groupResult->method('fetchAllAssociative')->willReturn([
            ['uid_foreign' => 3],
            ['uid_foreign' => 7],
        ]);

        $qb1 = $this->createQueryBuilderStub($secretResult, $expressionBuilder);
        $qb2 = $this->createQueryBuilderStub($groupResult, $expressionBuilder);

        $connection->method('createQueryBuilder')
            ->willReturnOnConsecutiveCalls($qb1, $qb2);

        $secret = $subject->findByIdentifier('secret-with-groups');

        self::assertInstanceOf(Secret::class, $secret);
        self::assertSame([3, 7], $secret->getAllowedGroups());
    }

    #[Test]
    public function findByUidLoadsGroupsWhenPresent(): void
    {
        // Use a fresh subject to avoid setUp createQueryBuilder stub conflict
        $connectionPool = $this->createStub(ConnectionPool::class);
        $connection = $this->createStub(Connection::class);
        $expressionBuilder = $this->createStub(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('field = ?');

        $connectionPool->method('getConnectionForTable')->willReturn($connection);
        $subject = new SecretRepository($connectionPool);

        $secretRow = $this->createSecretRow('uid-with-groups', 20);

        $secretResult = $this->createStub(Result::class);
        $secretResult->method('fetchAssociative')->willReturn($secretRow);

        $groupResult = $this->createStub(Result::class);
        $groupResult->method('fetchAllAssociative')->willReturn([
            ['uid_foreign' => 5],
        ]);

        $qb1 = $this->createQueryBuilderStub($secretResult, $expressionBuilder);
        $qb2 = $this->createQueryBuilderStub($groupResult, $expressionBuilder);

        $connection->method('createQueryBuilder')
            ->willReturnOnConsecutiveCalls($qb1, $qb2);

        $secret = $subject->findByUid(20);

        self::assertInstanceOf(Secret::class, $secret);
        self::assertSame([5], $secret->getAllowedGroups());
    }

    #[Test]
    public function saveInsertsNewSecretWithGroups(): void
    {
        $connection = $this->useStrictConnectionMock();

        $secret = $this->newEncryptedSecret('new-secret-groups', allowedGroups: [3, 7]);

        $connection
            ->method('lastInsertId')
            ->willReturn('5');

        // Expect: 1 secret insert + 2 MM group inserts = 3 inserts total
        $connection
            ->expects(self::exactly(3))
            ->method('insert');

        // Expect: 1 delete of existing MM rows before saving groups
        $connection
            ->expects(self::once())
            ->method('delete');

        $saved = $this->subject->save($secret);

        self::assertNull($secret->getUid());
        self::assertSame(5, $saved->getUid());
    }

    /**
     * Tighten params matcher: verify the first element is the current timestamp
     * (within a tolerance — to avoid microsecond race). The previous version
     * asserted only `count($params) === 2 && $params[1] === 42` so a broken
     * `last_read_at` (e.g. always passing `0`) would have gone unnoticed.
     * Also replace `stringContains(...)` on the SQL with an exact match so
     * whitespace / column-order regressions in the UPDATE are caught.
     */
    #[Test]
    public function incrementReadCountUpdatesDatabase(): void
    {
        $connection = $this->useStrictConnectionMock();

        $expectedSql = 'UPDATE tx_nrvault_secret SET read_count = read_count + 1, last_read_at = ? WHERE uid = ?';

        $connection
            ->expects(self::once())
            ->method('executeStatement')
            ->with(
                self::equalTo($expectedSql),
                self::callback(static fn (array $params): bool => \count($params) === 2
                    && $params[1] === 42
                    && \is_int($params[0])
                    && $params[0] >= (time() - 2)
                    && $params[0] <= (time() + 2)),
                self::anything(),
            );

        $this->subject->incrementReadCount(42);
    }

    #[Test]
    public function findAllWithFiltersReturnsEmptyArrayWhenNoRows(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchAllAssociative')->willReturn([]);

        $this->setupQueryBuilderForSelect($result);

        $secrets = $this->subject->findAllWithFilters();

        self::assertSame([], $secrets);
    }

    #[Test]
    public function findAllWithFiltersReturnsSecretsWithBatchLoadedGroups(): void
    {
        // Use a fresh subject to avoid setUp createQueryBuilder stub conflict
        $connectionPool = $this->createStub(ConnectionPool::class);
        $connection = $this->createStub(Connection::class);
        $expressionBuilder = $this->createStub(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('field = ?');
        $expressionBuilder->method('in')->willReturn('field IN (?)');

        $connectionPool->method('getConnectionForTable')->willReturn($connection);
        $subject = new SecretRepository($connectionPool);

        $row1 = $this->createSecretRow('batch-1', 1);
        $row2 = $this->createSecretRow('batch-2', 2);

        $mainResult = $this->createStub(Result::class);
        $mainResult->method('fetchAllAssociative')->willReturn([$row1, $row2]);

        $mmResult = $this->createStub(Result::class);
        $mmResult->method('fetchAllAssociative')->willReturn([]);

        $qb1 = $this->createQueryBuilderStub($mainResult, $expressionBuilder);
        $qb2 = $this->createQueryBuilderStub($mmResult, $expressionBuilder);

        $connection->method('createQueryBuilder')
            ->willReturnOnConsecutiveCalls($qb1, $qb2);

        $secrets = $subject->findAllWithFilters();

        self::assertCount(2, $secrets);
        self::assertSame('batch-1', $secrets[0]->getIdentifier());
        self::assertSame('batch-2', $secrets[1]->getIdentifier());
    }

    #[Test]
    public function findAllWithFiltersAppliesOwnerFilter(): void
    {
        $queryBuilder = $this->useStrictQueryBuilderMock();

        $result = $this->createStub(Result::class);
        $result->method('fetchAllAssociative')->willReturn([]);

        $this->setupQueryBuilderForSelect($result);

        $queryBuilder
            ->expects(self::atLeastOnce())
            ->method('andWhere')
            ->willReturnSelf();

        $this->subject->findAllWithFilters(new SecretFilters(owner: 3));
    }

    #[Test]
    public function findAllWithFiltersAppliesContextAndScopePidFilters(): void
    {
        $queryBuilder = $this->useStrictQueryBuilderMock();

        $result = $this->createStub(Result::class);
        $result->method('fetchAllAssociative')->willReturn([]);

        $this->setupQueryBuilderForSelect($result);

        $queryBuilder
            ->expects(self::atLeastOnce())
            ->method('andWhere')
            ->willReturnSelf();

        $this->expressionBuilder->method('like')->willReturn('identifier LIKE ?');

        $this->subject->findAllWithFilters(new SecretFilters(prefix: 'api-', context: 'myctx', scopePid: 5));
    }

    #[Test]
    public function findByGroupsReturnsSecretsForMatchingGroups(): void
    {
        // Create a fresh subject with its own connection mock to avoid setUp stub conflicts
        $connectionPool = $this->createStub(ConnectionPool::class);
        $connection = $this->createStub(Connection::class);
        $expressionBuilder = $this->createStub(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('field = ?');
        $expressionBuilder->method('in')->willReturn('field IN (?)');

        $connectionPool->method('getConnectionForTable')->willReturn($connection);

        $subject = new SecretRepository($connectionPool);

        // First call: MM query returning secret UIDs
        $mmResult = $this->createStub(Result::class);
        $mmResult->method('fetchFirstColumn')->willReturn([1, 2]);

        // Second call: main secrets query
        $row1 = $this->createSecretRow('group-secret-1', 1);
        $row2 = $this->createSecretRow('group-secret-2', 2);
        $secretsResult = $this->createStub(Result::class);
        $secretsResult->method('fetchAllAssociative')->willReturn([$row1, $row2]);

        // Third/fourth calls: individual group loads per secret (returns empty)
        $emptyResult1 = $this->createStub(Result::class);
        $emptyResult1->method('fetchAllAssociative')->willReturn([]);
        $emptyResult2 = $this->createStub(Result::class);
        $emptyResult2->method('fetchAllAssociative')->willReturn([]);

        $qb1 = $this->createQueryBuilderStub($mmResult, $expressionBuilder);
        $qb2 = $this->createQueryBuilderStub($secretsResult, $expressionBuilder);
        $qb3 = $this->createQueryBuilderStub($emptyResult1, $expressionBuilder);
        $qb4 = $this->createQueryBuilderStub($emptyResult2, $expressionBuilder);

        $connection->method('createQueryBuilder')
            ->willReturnOnConsecutiveCalls($qb1, $qb2, $qb3, $qb4);

        $secrets = $subject->findByGroups([5, 9]);

        self::assertCount(2, $secrets);
    }

    /**
     * Characterisation test + documented gap.
     *
     * `SecretRepository::findIdentifiers()` silently coerces a non-string
     * identifier row to an empty string and appends it to the result array.
     * This is BUG-MASKING behaviour — downstream consumers cannot
     * distinguish a real (but empty) identifier from a data-integrity
     * problem.
     *
     * Correct behaviour would be either:
     *   (a) log a warning and skip the row, OR
     *   (b) throw a domain exception.
     *
     * We mark this test INCOMPLETE so it is visible in every CI run as a
     * pending quality debt, without blocking unrelated merges. When the
     * production code is fixed to (a) or (b), the `markTestIncomplete()`
     * call must be removed and the assertions below re-enabled.
     *
     * @see SecretRepository::findIdentifiers() lines 183-190
     */
    #[Test]
    public function findIdentifiersDoesNotSilentlyReturnEmptyStringForNonStringRow(): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchAssociative')
            ->willReturnOnConsecutiveCalls(
                ['identifier' => 42],   // non-string — driver/schema anomaly
                false,
            );

        $this->setupQueryBuilderForSelect($result);

        // Pin the current buggy behaviour so a regression to "worse" (e.g.
        // returning a bogus non-empty string) is caught.
        $identifiers = $this->subject->findIdentifiers();
        self::assertSame([''], $identifiers, 'current (buggy) behaviour pinned');

        self::markTestIncomplete(
            'BUG: SecretRepository::findIdentifiers() silently returns [""] for '
            . 'a non-string identifier row. It should either skip the row with '
            . 'a logged warning or throw. Fix the production code, then remove '
            . 'this markTestIncomplete() call and change the assertion to '
            . '`assertNotSame([""], $identifiers)`.',
        );
    }

    // ------------------------------------------------------------------
    // Negative-path tests for save().
    // ------------------------------------------------------------------

    /**
     * If the underlying `Connection::insert()` fails (driver-level error),
     * the exception must propagate — the repository does NOT swallow it.
     *
     * We use a plain `\RuntimeException` here rather than a Doctrine one:
     * `Doctrine\DBAL\Exception` is an interface, and the concrete
     * `DriverException` hierarchy carries a driver-level payload that is
     * irrelevant to this behavioural test.
     */
    #[Test]
    public function saveThrowsWhenConnectionInsertFails(): void
    {
        $secret = $this->newEncryptedSecret('insert-fail');

        $this->connection
            ->method('insert')
            ->willThrowException(new RuntimeException('Constraint violation'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Constraint violation');

        $this->subject->save($secret);
    }

    /**
     * `Connection::lastInsertId()` returns `string` (TYPO3 Connection override
     * casts to string). A non-numeric return must not crash — the repository
     * should coerce to `0` and leave the secret's UID unset (i.e. set to 0).
     *
     * @param non-empty-string $description
     */
    #[Test]
    #[DataProvider('nonNumericLastInsertIdProvider')]
    public function saveHandlesNonNumericLastInsertId(string $lastInsertIdValue, int $expectedUid, string $description): void
    {
        $secret = $this->newEncryptedSecret('nonnum-lastinsert');

        $this->connection->method('insert')->willReturn(1);
        $this->connection->method('lastInsertId')->willReturn($lastInsertIdValue);
        $this->connection->method('delete')->willReturn(0);

        $saved = $this->subject->save($secret);

        // The original secret's UID is unchanged (immutable entity); the
        // returned instance carries the coerced UID.
        self::assertNull($secret->getUid());
        self::assertSame(
            $expectedUid,
            $saved->getUid(),
            \sprintf('Failed asserting UID fallback for case: %s', $description),
        );
    }

    /**
     * @return iterable<string, array{string, int, string}>
     */
    public static function nonNumericLastInsertIdProvider(): iterable
    {
        yield 'numeric zero string' => ['0', 0, 'last_insert_id = "0" — repository must treat as 0'];
        yield 'empty string' => ['', 0, 'empty string — driver may signal no-id'];
        yield 'non-numeric' => ['abc', 0, 'garbage return — must not crash, fall back to 0'];
    }

    /**
     * Covers the insert-groups path on update (previously only the MM delete
     * was asserted, leaving the subsequent `insert()`s uncovered).
     */
    #[Test]
    public function saveUpdatesExistingSecretWithNonEmptyGroups(): void
    {
        $connection = $this->useStrictConnectionMock();

        $secret = $this->newEncryptedSecret('existing-with-groups', uid: 77, allowedGroups: [11, 13]);

        // 1 update on the secret row, 2 inserts on the MM table for the 2 groups
        $connection->expects(self::once())->method('update');
        $connection->expects(self::exactly(2))->method('insert')
            ->with(
                'tx_nrvault_secret_begroups_mm',
                self::callback(static fn (array $data): bool => $data['uid_local'] === 77
                    && \in_array($data['uid_foreign'], [11, 13], true)
                    && isset($data['sorting'])),
            );

        // Exactly one MM delete before the re-inserts
        $connection->expects(self::once())->method('delete')
            ->with('tx_nrvault_secret_begroups_mm', ['uid_local' => 77]);

        $this->subject->save($secret);
    }

    /**
     * Swap the default Connection stub for a strict MockObject and re-wire the
     * connection pool. Call BEFORE any test-specific stubbing. Use from tests
     * that need $connection->expects(...) verification.
     */
    private function useStrictConnectionMock(): Connection&MockObject
    {
        $mock = $this->createMock(Connection::class);
        $mock->method('createQueryBuilder')->willReturn($this->queryBuilder);
        $this->connection = $mock;

        $pool = $this->createStub(ConnectionPool::class);
        $pool->method('getConnectionForTable')->willReturn($mock);
        $this->connectionPool = $pool;

        $this->subject = new SecretRepository($pool);

        return $mock;
    }

    /**
     * Swap the default QueryBuilder stub for a strict MockObject and re-wire
     * the connection chain. Call BEFORE any test-specific stubbing.
     */
    private function useStrictQueryBuilderMock(): QueryBuilder&MockObject
    {
        $mock = $this->createMock(QueryBuilder::class);
        $mock->method('expr')->willReturn($this->expressionBuilder);
        $this->queryBuilder = $mock;

        $connection = $this->createStub(Connection::class);
        $connection->method('createQueryBuilder')->willReturn($mock);
        $this->connection = $connection;

        $pool = $this->createStub(ConnectionPool::class);
        $pool->method('getConnectionForTable')->willReturn($connection);
        $this->connectionPool = $pool;

        $this->subject = new SecretRepository($pool);

        return $mock;
    }

    /**
     * Swap both the default QueryBuilder AND ExpressionBuilder stubs for strict
     * MockObjects and re-wire the connection chain. Call BEFORE any
     * test-specific stubbing. Returns both so callers can add expectations.
     *
     * @return array{0: QueryBuilder&MockObject, 1: ExpressionBuilder&MockObject}
     */
    private function useStrictQueryBuilderAndExpressionBuilderMocks(): array
    {
        $exprMock = $this->createMock(ExpressionBuilder::class);
        $this->expressionBuilder = $exprMock;

        $qbMock = $this->createMock(QueryBuilder::class);
        $qbMock->method('expr')->willReturn($exprMock);
        $this->queryBuilder = $qbMock;

        $connection = $this->createStub(Connection::class);
        $connection->method('createQueryBuilder')->willReturn($qbMock);
        $this->connection = $connection;

        $pool = $this->createStub(ConnectionPool::class);
        $pool->method('getConnectionForTable')->willReturn($connection);
        $this->connectionPool = $pool;

        $this->subject = new SecretRepository($pool);

        return [$qbMock, $exprMock];
    }

    /**
     * Create a minimal QueryBuilder stub wired to the given (or shared) ExpressionBuilder.
     */
    private function createQueryBuilderStub(Result $result, ?ExpressionBuilder $expressionBuilder = null): QueryBuilder
    {
        $qb = $this->createStub(QueryBuilder::class);
        $qb->method('select')->willReturnSelf();
        $qb->method('from')->willReturnSelf();
        $qb->method('where')->willReturnSelf();
        $qb->method('andWhere')->willReturnSelf();
        $qb->method('orderBy')->willReturnSelf();
        $qb->method('addOrderBy')->willReturnSelf();
        $qb->method('expr')->willReturn($expressionBuilder ?? $this->expressionBuilder);
        $qb->method('createNamedParameter')->willReturn('?');
        $qb->method('executeQuery')->willReturn($result);

        return $qb;
    }

    private function setupQueryBuilderForSelect(Result $result): void
    {
        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('where')->willReturnSelf();
        $this->queryBuilder->method('andWhere')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);
        $this->queryBuilder->method('createNamedParameter')->willReturn('?');

        $this->expressionBuilder->method('eq')->willReturn('field = ?');
        $this->expressionBuilder->method('in')->willReturn('field IN (?)');
        $this->expressionBuilder->method('gt')->willReturn('field > ?');
        $this->expressionBuilder->method('lt')->willReturn('field < ?');
        $this->expressionBuilder->method('lte')->willReturn('field <= ?');
    }

    private function setupQueryBuilderForCount(Result $result): void
    {
        $this->queryBuilder->method('count')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('where')->willReturnSelf();
        $this->queryBuilder->method('executeQuery')->willReturn($result);
        $this->queryBuilder->method('createNamedParameter')->willReturn('?');

        $this->expressionBuilder->method('eq')->willReturn('field = ?');
    }

    /**
     * Build a Secret with the seven crypto/envelope fields populated to
     * defaults appropriate for save()-path tests. The ctor enforces the
     * tri-state crypto invariant so callers can't omit individual fields.
     *
     * @param list<int> $allowedGroups
     */
    private function newEncryptedSecret(
        string $identifier,
        ?int $uid = null,
        array $allowedGroups = [],
    ): Secret {
        return new Secret(
            identifier: $identifier,
            uid: $uid,
            encryptedValue: 'encrypted',
            encryptedDek: 'dek',
            dekNonce: 'deknonce',
            valueNonce: 'valuenonce',
            encryptionVersion: 1,
            allowedGroups: $allowedGroups,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function createSecretRow(string $identifier, int $uid = 1): array
    {
        return [
            'uid' => $uid,
            'pid' => 0,
            'identifier' => $identifier,
            'encrypted_value' => base64_encode('encrypted'),
            'nonce' => base64_encode('nonce123456789012'),
            'encryption_version' => 1,
            'context' => '',
            'label' => 'Test Secret',
            'description' => 'Test description',
            'owner_uid' => 0,
            'scope_pid' => 0,
            'expires_at' => 0,
            'allowed_groups' => 0,
            'tstamp' => time(),
            'crdate' => time(),
            'deleted' => 0,
        ];
    }
}
