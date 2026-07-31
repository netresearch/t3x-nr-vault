<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Audit\AuditChainLockTrait;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Tests\Unit\Fixtures\AuditChainLockHost;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use TYPO3\CMS\Core\Database\Connection;

/**
 * The audit chain's write serialisation. Two distinct protocols hide behind one
 * API, and picking the wrong one is not a cosmetic bug:
 *
 *  - **Raw mode** (SQLite, no outer transaction) issues `BEGIN EXCLUSIVE` /
 *    `COMMIT` / `ROLLBACK` as statements, because that is the only way to get an
 *    exclusive SQLite write lock.
 *  - **Nested mode** (SQLite inside a caller-managed Doctrine transaction, as
 *    master-key rotation does) must use Doctrine's begin/commit/rollBack so the
 *    nesting counter maps them onto savepoints. A raw `BEGIN EXCLUSIVE` there
 *    would fail — SQLite cannot nest transactions — and take the rotation down.
 *
 * `Connection::isTransactionActive()` is the discriminator, so each of the six
 * mode/operation combinations is pinned to the exact calls it must make.
 */
#[CoversTrait(AuditChainLockTrait::class)]
final class AuditChainLockTraitTest extends TestCase
{
    private AuditChainLockHost $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->subject = new AuditChainLockHost();
    }

    // -------------------------------------------------------------------------
    // acquire
    // -------------------------------------------------------------------------

    #[Test]
    public function sqliteWithoutAnOuterTransactionIssuesBeginExclusive(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('isTransactionActive')->willReturn(false);
        $connection->expects(self::once())->method('executeStatement')->with('BEGIN EXCLUSIVE');
        $connection->expects(self::never())->method('beginTransaction');

        $this->subject->acquire($connection, true);
    }

    /**
     * Inside a caller-managed transaction the raw statement would fail, so the
     * trait must fall back to a Doctrine savepoint instead.
     */
    #[Test]
    public function sqliteInsideAnOuterTransactionTakesASavepointInsteadOfBeginExclusive(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('isTransactionActive')->willReturn(true);
        $connection->expects(self::once())->method('beginTransaction');
        $connection->expects(self::never())->method('executeStatement');

        $this->subject->acquire($connection, true);
    }

    #[Test]
    public function mysqlTakesTheNamedLockAndThenOpensATransaction(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())
            ->method('executeQuery')
            ->with('SELECT GET_LOCK("nr_vault_audit", 5)')
            ->willReturn($this->lockResult(1));
        $connection->expects(self::once())->method('beginTransaction');

        $this->subject->acquire($connection, false);
    }

    /**
     * `GET_LOCK` returns 0 on timeout and NULL on error. Anything but 1 must
     * abort — writing an audit entry without the lock would let two workers
     * interleave chain links.
     */
    #[Test]
    public function mysqlLockTimeoutAbortsBeforeAnyTransactionIsOpened(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('executeQuery')->willReturn($this->lockResult(0));
        $connection->expects(self::never())->method('beginTransaction');

        $this->expectException(AuditWriteException::class);

        $this->subject->acquire($connection, false);
    }

    #[Test]
    public function mysqlLockErrorAbortsWhenGetLockReturnsNull(): void
    {
        $connection = self::createStub(Connection::class);
        $connection->method('executeQuery')->willReturn($this->lockResult(null));

        $this->expectException(AuditWriteException::class);

        $this->subject->acquire($connection, false);
    }

    /**
     * The lock is already held when `beginTransaction()` runs, and the caller's
     * `finally` has not started yet — so the trait itself has to release it or it
     * leaks for the connection's lifetime.
     */
    #[Test]
    public function mysqlReleasesTheNamedLockWhenOpeningTheTransactionFails(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('executeQuery')->willReturn($this->lockResult(1));
        $connection->method('beginTransaction')->willThrowException(new RuntimeException('deadlock', 1750000010));
        $connection->expects(self::once())
            ->method('executeStatement')
            ->with('SELECT RELEASE_LOCK("nr_vault_audit")');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('deadlock');

        $this->subject->acquire($connection, false);
    }

    /**
     * The release is best-effort: if it also fails, the ORIGINAL failure must
     * still be what reaches the caller — swapping it for the release error would
     * hide the real cause, and closing the connection releases the lock anyway.
     */
    #[Test]
    public function aFailingReleaseDoesNotMaskTheOriginalTransactionFailure(): void
    {
        $connection = self::createStub(Connection::class);
        $connection->method('executeQuery')->willReturn($this->lockResult(1));
        $connection->method('beginTransaction')->willThrowException(new RuntimeException('original', 1750000011));
        $connection->method('executeStatement')->willThrowException(new RuntimeException('gone', 1750000012));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('original');

        $this->subject->acquire($connection, false);
    }

    // -------------------------------------------------------------------------
    // commit
    // -------------------------------------------------------------------------

    #[Test]
    public function sqliteCommitWithoutAnOuterTransactionIssuesCommitAsAStatement(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('isTransactionActive')->willReturn(false);
        $connection->expects(self::once())->method('executeStatement')->with('COMMIT');
        $connection->expects(self::never())->method('commit');

        $this->subject->commit($connection, true);
    }

    #[Test]
    public function sqliteCommitInsideAnOuterTransactionReleasesTheSavepoint(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('isTransactionActive')->willReturn(true);
        $connection->expects(self::once())->method('commit');
        $connection->expects(self::never())->method('executeStatement');

        $this->subject->commit($connection, true);
    }

    #[Test]
    public function mysqlCommitUsesDoctrine(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())->method('commit');
        $connection->expects(self::never())->method('executeStatement');

        $this->subject->commit($connection, false);
    }

    // -------------------------------------------------------------------------
    // rollback
    // -------------------------------------------------------------------------

    #[Test]
    public function sqliteRollbackWithoutAnOuterTransactionIssuesRollbackAsAStatement(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('isTransactionActive')->willReturn(false);
        $connection->expects(self::once())->method('executeStatement')->with('ROLLBACK');
        $connection->expects(self::never())->method('rollBack');

        $this->subject->rollback($connection, true);
    }

    /**
     * Rolling back to the savepoint leaves the caller's outer transaction alive —
     * a raw `ROLLBACK` would abort the master-key rotation wrapped around it.
     */
    #[Test]
    public function sqliteRollbackInsideAnOuterTransactionRollsBackToTheSavepointOnly(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('isTransactionActive')->willReturn(true);
        $connection->expects(self::once())->method('rollBack');
        $connection->expects(self::never())->method('executeStatement');

        $this->subject->rollback($connection, true);
    }

    #[Test]
    public function mysqlRollbackUsesDoctrine(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())->method('rollBack');
        $connection->expects(self::never())->method('executeStatement');

        $this->subject->rollback($connection, false);
    }

    // -------------------------------------------------------------------------
    // release
    // -------------------------------------------------------------------------

    #[Test]
    public function mysqlReleaseDropsTheNamedLock(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::once())
            ->method('executeStatement')
            ->with('SELECT RELEASE_LOCK("nr_vault_audit")');

        $this->subject->release($connection, false);
    }

    /**
     * SQLite has no named lock — the transaction IS the lock, so a release would
     * be a stray statement.
     */
    #[Test]
    public function sqliteReleaseIsANoOp(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->expects(self::never())->method('executeStatement');

        $this->subject->release($connection, true);
    }

    private function lockResult(mixed $value): Result
    {
        $result = self::createStub(Result::class);
        $result->method('fetchOne')->willReturn($value);

        return $result;
    }
}
