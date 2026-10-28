<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use ArrayObject;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Doctrine\DBAL\Result;
use Netresearch\NrVault\Audit\VaultMutationTransaction;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\InvalidArgumentException as LoggerInvalidArgumentException;
use Psr\Log\LoggerInterface;
use RuntimeException;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

#[CoversClass(VaultMutationTransaction::class)]
final class VaultMutationTransactionTest extends TestCase
{
    private const FIRST_FAILURE = 'The mutation failed first.';

    private const DENIAL_MUST_SURFACE = 'The unrecorded denial must surface.';

    #[Test]
    public function commitEffectsRunOnlyAfterTheOwnedTransactionHasCommitted(): void
    {
        $active     = false;
        $connection = $this->createMock(Connection::class);
        $connection
            ->method('getDatabasePlatform')
            ->willReturn(new SQLitePlatform());
        $connection
            ->method('isTransactionActive')
            ->willReturnCallback(
                static function () use (&$active): bool {
                    return $active;
                },
            );
        $connection
            ->expects(self::once())
            ->method('beginTransaction')
            ->willReturnCallback(
                static function () use (&$active): void {
                    $active = true;
                },
            );
        $connection
            ->expects(self::once())
            ->method('commit')
            ->willReturnCallback(
                static function () use (&$active): void {
                    self::assertTrue($active);
                    $active = false;
                },
            );
        $connection->expects(self::never())->method('rollBack');
        $subject   = $this->subject($connection);
        $published = new ArrayObject();

        $subject->run(
            static function () use ($subject, &$published, &$active): void {
                self::assertTrue($subject->isActive());
                self::assertTrue($active);
                $subject->afterCommit(
                    static function () use ($subject, &$published, &$active): void {
                        /** @var bool $active Changed by the commit callback. */
                        self::assertFalse($active);
                        self::assertFalse($subject->isActive());
                        $published->append('published');
                    },
                );
                self::assertCount(0, $published);
            },
        );

        self::assertCount(1, $published);
    }

    #[Test]
    public function rollbackDropsSuccessEffectsAndReplaysDeniedEntriesAfterward(): void
    {
        $active     = false;
        $connection = $this->createMock(Connection::class);
        $connection
            ->method('getDatabasePlatform')
            ->willReturn(new SQLitePlatform());
        $connection
            ->method('isTransactionActive')
            ->willReturnCallback(
                static function () use (&$active): bool {
                    return $active;
                },
            );
        $connection
            ->method('beginTransaction')
            ->willReturnCallback(
                static function () use (&$active): void {
                    $active = true;
                },
            );
        $connection
            ->expects(self::once())
            ->method('rollBack')
            ->willReturnCallback(
                static function () use (&$active): void {
                    $active = false;
                },
            );
        $connection->expects(self::never())->method('commit');
        $subject  = $this->subject($connection);
        $replayed = false;
        $original = new RuntimeException('mutation failed', 1793180101);

        try {
            $subject->run(
                static function () use ($subject, &$replayed, &$active, $original): never {
                    $subject->afterCommit(
                        static function (): never {
                            self::fail(
                                'A rolled-back success must never be published.',
                            );
                        },
                    );
                    $subject->afterRollback(
                        static function () use ($subject, &$replayed, &$active): void {
                            self::assertFalse($active);
                            self::assertFalse($subject->isActive());
                            $replayed = true;
                        },
                    );

                    throw $original;
                },
            );
            self::fail('The original mutation failure must propagate.');
        } catch (RuntimeException $failure) {
            self::assertSame($original, $failure);
        }

        self::assertTrue($replayed);
    }

    #[Test]
    public function aPostCommitListenerFailureDoesNotAttemptRollback(): void
    {
        $active     = false;
        $connection = $this->createMock(Connection::class);
        $connection
            ->method('getDatabasePlatform')
            ->willReturn(new SQLitePlatform());
        $connection
            ->method('isTransactionActive')
            ->willReturnCallback(
                static function () use (&$active): bool {
                    return $active;
                },
            );
        $connection
            ->method('beginTransaction')
            ->willReturnCallback(
                static function () use (&$active): void {
                    $active = true;
                },
            );
        $connection
            ->expects(self::once())
            ->method('commit')
            ->willReturnCallback(
                static function () use (&$active): void {
                    $active = false;
                },
            );
        $connection->expects(self::never())->method('rollBack');
        $subject         = $this->subject($connection);
        $listenerFailure = new RuntimeException('listener failed', 1793180103);

        $this->expectExceptionObject($listenerFailure);
        $subject->run(
            static function () use ($subject, $listenerFailure): void {
                $subject->afterCommit(
                    static function () use ($listenerFailure): never {
                        throw $listenerFailure;
                    },
                );
            },
        );
    }

    #[Test]
    public function aSplitTableMappingIsRejectedBeforeAnyMutation(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('getDatabasePlatform')->willReturn(new SQLitePlatform());
        $connection->expects(self::never())->method('beginTransaction');
        $other = self::createStub(Connection::class);
        $pool  = self::createStub(ConnectionPool::class);
        $pool
            ->method('getConnectionForTable')
            ->willReturnCallback(
                static fn (
                    string $table,
                ): Connection => $table === 'tx_nrvault_secret_writegroups_mm' ? $other : $connection,
            );
        $subject = new VaultMutationTransaction($pool);

        $this->expectException(AuditWriteException::class);
        $this->expectExceptionCode(1793180004);
        $subject->run(
            static function (): never {
                self::fail(
                    'Split mappings must fail before the mutation callback.',
                );
            },
        );
    }

    #[Test]
    public function aCallerOwnedTransactionIsRejectedWithoutCommittingIt(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('isTransactionActive')->willReturn(true);
        $connection->method('getDatabasePlatform')->willReturn(new SQLitePlatform());
        $connection->expects(self::never())->method('beginTransaction');
        $connection->expects(self::never())->method('commit');
        $connection->expects(self::never())->method('rollBack');
        $subject = $this->subject($connection);

        $this->expectException(AuditWriteException::class);
        $this->expectExceptionCode(1793180002);
        $subject->run(
            static function (): never {
                self::fail(
                    'Caller-owned transactions cannot participate in this protocol.',
                );
            },
        );
    }

    #[Test]
    public function mysqlKeepsItsNamedLockThroughCommitAndReleasesBeforePublishing(): void
    {
        $active     = false;
        $locked     = false;
        $connection = $this->createMock(Connection::class);
        $connection
            ->method('getDatabasePlatform')
            ->willReturn(new MySQLPlatform());
        $connection
            ->method('isTransactionActive')
            ->willReturnCallback(
                static function () use (&$active): bool {
                    return $active;
                },
            );
        $result = self::createStub(Result::class);
        $result->method('fetchOne')->willReturn(1);
        $connection
            ->expects(self::once())
            ->method('executeQuery')
            ->with('SELECT GET_LOCK("nr_vault_audit", 5)')
            ->willReturnCallback(
                static function () use (&$locked, $result): Result {
                    $locked = true;

                    return $result;
                },
            );
        $connection
            ->expects(self::once())
            ->method('beginTransaction')
            ->willReturnCallback(
                static function () use (&$active, &$locked): void {
                    self::assertTrue($locked);
                    $active = true;
                },
            );
        $connection
            ->expects(self::once())
            ->method('commit')
            ->willReturnCallback(
                static function () use (&$active, &$locked): void {
                    self::assertTrue($locked);
                    self::assertTrue($active);
                    $active = false;
                },
            );
        $connection
            ->expects(self::once())
            ->method('executeStatement')
            ->with('SELECT RELEASE_LOCK("nr_vault_audit")')
            ->willReturnCallback(
                static function () use (&$active, &$locked): int {
                    self::assertFalse($active);
                    self::assertTrue($locked);
                    $locked = false;

                    return 1;
                },
            );
        $connection->expects(self::never())->method('rollBack');
        $subject   = $this->subject($connection);
        $published = false;

        $subject->run(
            static function () use ($subject, &$locked, &$published): void {
                self::assertTrue($locked);
                $subject->afterCommit(
                    static function () use (&$locked, &$published): void {
                        /** @var bool $locked Changed by the release callback. */
                        self::assertFalse($locked);
                        $published = true;
                    },
                );
            },
        );

        /** @var bool $published Changed by the publication callback. */
        self::assertTrue($published);
    }

    #[Test]
    public function anAfterCommitActionOutsideATransactionRunsImmediately(): void
    {
        $connection = self::createStub(Connection::class);
        $subject    = $this->subject($connection);
        $actions    = new ArrayObject();

        $subject->afterCommit(
            static function () use ($actions): void {
                $actions->append('immediate');
            },
        );

        self::assertSame(['immediate'], $actions->getArrayCopy());
        self::assertFalse($subject->isActive());
    }

    #[Test]
    public function aRollbackActionRegisteredOutsideATransactionCannotLeakIntoALaterAttempt(): void
    {
        $subject  = $this->subject($this->sqliteConnectionForAttempts());
        $actions  = new ArrayObject();
        $original = new AuditWriteException('The later mutation was refused.', 1793180201);
        $subject->afterRollback(
            static function () use ($actions): void {
                $actions->append('unowned rollback');
            },
        );
        self::assertCount(0, $actions);

        try {
            $subject->run(
                static function () use ($original): never {
                    throw $original;
                },
            );
            self::fail('The later mutation must fail.');
        } catch (AuditWriteException $failure) {
            self::assertSame($original, $failure);
        }

        self::assertCount(0, $actions);
        self::assertFalse($subject->isActive());
    }

    #[Test]
    public function aNestedMutationCannotBorrowOwnershipAndRollsBackTheOuterAttempt(): void
    {
        $connection = $this->sqliteConnectionForAttempts();
        $connection->expects(self::never())->method('commit');
        $subject = $this->subject($connection);
        $actions = new ArrayObject();

        try {
            $subject->run(
                static function () use ($subject, $actions): void {
                    $subject->afterCommit(
                        static function () use ($actions): void {
                            $actions->append('outer publication');
                        },
                    );
                    $subject->run(
                        static function () use ($actions): void {
                            $actions->append('nested mutation');
                        },
                    );
                },
            );
            self::fail('A nested mutation must be refused.');
        } catch (AuditWriteException $failure) {
            self::assertSame(1793180001, $failure->getCode());
        }

        self::assertCount(0, $actions);
        self::assertFalse($connection->isTransactionActive());
        self::assertFalse($subject->isActive());
    }

    #[Test]
    public function anUnsupportedDatabaseCannotStartAMutationOrAcquireALock(): void
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('isTransactionActive')->willReturn(false);
        $connection
            ->method('getDatabasePlatform')
            ->willReturn(new PostgreSQLPlatform());
        $connection->expects(self::never())->method('beginTransaction');
        $connection->expects(self::never())->method('executeQuery');
        $subject = $this->subject($connection);

        $this->expectException(AuditWriteException::class);
        $this->expectExceptionCode(1793180003);
        $subject->run(
            static function (): never {
                self::fail(
                    'Unsupported databases must fail before any mutation.',
                );
            },
        );
    }

    #[Test]
    public function aFailedRollbackClosesTheConnectionAndPreservesTheOriginalFailure(): void
    {
        $connection = $this->sqliteConnectionForAttempts(
            new AuditWriteException('Rollback became unavailable.', 1793180202),
        );
        $connection->expects(self::once())->method('close');
        $connection->expects(self::never())->method('commit');
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())->method('error');
        $subject  = $this->subject($connection, $logger);
        $original = new AuditWriteException(self::FIRST_FAILURE, 1793180203);

        try {
            $subject->run(
                static function () use ($original): never {
                    throw $original;
                },
            );
            self::fail('The original failure must propagate.');
        } catch (AuditWriteException $failure) {
            self::assertSame($original, $failure);
        }

        self::assertFalse($subject->isActive());
    }

    #[Test]
    public function aFailedLockReleaseClosesItsSessionBeforePublishingCommittedEffects(): void
    {
        $actions    = new ArrayObject();
        $connection = $this->createMock(Connection::class);
        $connection
            ->method('getDatabasePlatform')
            ->willReturn(new MySQLPlatform());
        $connection->method('isTransactionActive')->willReturn(false);
        $lock = self::createStub(Result::class);
        $lock->method('fetchOne')->willReturn(1);
        $connection->method('executeQuery')->willReturn($lock);
        $connection
            ->expects(self::once())
            ->method('commit')
            ->willReturnCallback(
                static function () use ($actions): void {
                    $actions->append('committed');
                },
            );
        $connection
            ->expects(self::once())
            ->method('executeStatement')
            ->willThrowException(
                new AuditWriteException(
                    'Lock release acknowledgement failed.',
                    1793180204,
                ),
            );
        $connection
            ->expects(self::once())
            ->method('close')
            ->willReturnCallback(
                static function () use ($actions): void {
                    $actions->append('closed');
                },
            );
        $connection->expects(self::never())->method('rollBack');
        $subject = $this->subject($connection);

        $subject->run(
            static function () use ($subject, $actions): void {
                $subject->afterCommit(
                    static function () use ($actions): void {
                        $actions->append('published');
                    },
                );
            },
        );

        self::assertSame(
            ['committed', 'closed', 'published'],
            $actions->getArrayCopy(),
        );
        self::assertFalse($subject->isActive());
    }

    #[Test]
    public function anUnrecordedDenialSurfacesEvenWhenTheDiagnosticLoggerIsBroken(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger
            ->expects(self::once())
            ->method('error')
            ->willThrowException(
                new LoggerInvalidArgumentException(
                    'The diagnostic context was rejected.',
                    1793180205,
                ),
            );
        $subject       = $this->subject($this->sqliteConnectionForAttempts(), $logger);
        $original      = new AuditWriteException(self::FIRST_FAILURE, 1793180206);
        $replayFailure = new AuditWriteException(
            'Denied-audit replay was unavailable.',
            1793180207,
        );

        try {
            $subject->run(
                static function () use ($subject, $original, $replayFailure): never {
                    $subject->afterRollback(
                        static function () use ($replayFailure): never {
                            throw $replayFailure;
                        },
                    );

                    throw $original;
                },
            );
            self::fail(self::DENIAL_MUST_SURFACE);
        } catch (AuditWriteException $failure) {
            self::assertSame($replayFailure, $failure);
        }

        self::assertFalse($subject->isActive());
    }

    #[Test]
    public function aDenialReplayFailureOtherThanAnAuditWriteFailureIsWrapped(): void
    {
        $subject       = $this->subject($this->sqliteConnectionForAttempts());
        $replayFailure = new RuntimeException('connection lost', 1793180210);

        try {
            $subject->run(
                static function () use ($subject, $replayFailure): never {
                    $subject->afterRollback(
                        static function () use ($replayFailure): never {
                            throw $replayFailure;
                        },
                    );

                    throw new AuditWriteException(self::FIRST_FAILURE, 1793180211);
                },
            );
            self::fail(self::DENIAL_MUST_SURFACE);
        } catch (AuditWriteException $failure) {
            self::assertSame(1754038801, $failure->getCode());
            self::assertSame($replayFailure, $failure->getPrevious());
        }
    }

    #[Test]
    public function everyDenialIsReplayedEvenAfterAnEarlierReplayFailed(): void
    {
        $subject       = $this->subject($this->sqliteConnectionForAttempts());
        $actions       = new ArrayObject();
        $replayFailure = new AuditWriteException('First denial unavailable.', 1793180212);

        try {
            $subject->run(
                static function () use ($subject, $actions, $replayFailure): never {
                    $subject->afterRollback(
                        static function () use ($replayFailure): never {
                            throw $replayFailure;
                        },
                    );
                    $subject->afterRollback(
                        static function () use ($actions): void {
                            $actions->append('second denial recorded');
                        },
                    );

                    throw new AuditWriteException(self::FIRST_FAILURE, 1793180213);
                },
            );
            self::fail(self::DENIAL_MUST_SURFACE);
        } catch (AuditWriteException $failure) {
            self::assertSame($replayFailure, $failure);
        }

        self::assertSame(['second denial recorded'], $actions->getArrayCopy());
    }

    #[Test]
    public function sqliteTakesItsWriteLockBeforeTheMutationReads(): void
    {
        $connection = $this->sqliteConnectionForAttempts();
        $locked     = false;
        $connection
            ->expects(self::once())
            ->method('executeStatement')
            ->with('UPDATE tx_nrvault_audit_log SET uid = uid WHERE 1 = 0')
            ->willReturnCallback(
                static function () use ($connection, &$locked): int {
                    self::assertTrue($connection->isTransactionActive());
                    $locked = true;

                    return 0;
                },
            );

        $this->subject($connection)->run(
            static function () use (&$locked): void {
                self::assertTrue(
                    $locked,
                    'A deferred transaction must not reach the lookup without the RESERVED lock',
                );
            },
        );
    }

    #[Test]
    public function aSqliteWriteLockTimeoutRollsBackAndNeverRunsTheMutation(): void
    {
        $connection = $this->sqliteConnectionForAttempts();
        $busy       = new RuntimeException('database is locked', 1793180214);
        $connection
            ->expects(self::once())
            ->method('executeStatement')
            ->willThrowException($busy);
        $connection->expects(self::once())->method('rollBack');
        $subject = $this->subject($connection);

        try {
            $subject->run(
                static function (): never {
                    self::fail('The mutation must not run without the write lock.');
                },
            );
            self::fail('The lock timeout must surface.');
        } catch (AuditWriteException $failure) {
            self::assertSame(1754038801, $failure->getCode());
            self::assertSame($busy, $failure->getPrevious());
        }

        self::assertFalse($connection->isTransactionActive());
        self::assertFalse($subject->isActive());
    }

    #[Test]
    public function callbacksBelongOnlyToTheAttemptThatRegisteredThem(): void
    {
        $subject      = $this->subject($this->sqliteConnectionForAttempts());
        $actions      = new ArrayObject();
        $firstFailure = new AuditWriteException('The first attempt failed.', 1793180208);

        try {
            $subject->run(
                static function () use ($subject, $actions, $firstFailure): never {
                    $subject->afterCommit(
                        static function () use ($actions): void {
                            $actions->append('failed attempt publication');
                        },
                    );
                    $subject->afterRollback(
                        static function () use ($actions): void {
                            $actions->append('first rollback');
                        },
                    );

                    throw $firstFailure;
                },
            );
            self::fail('The first attempt must fail.');
        } catch (AuditWriteException $failure) {
            self::assertSame($firstFailure, $failure);
        }

        $subject->run(
            static function () use ($subject, $actions): void {
                $subject->afterCommit(
                    static function () use ($actions): void {
                        $actions->append('second committed');
                    },
                );
                $subject->afterRollback(
                    static function () use ($actions): void {
                        $actions->append('successful attempt rollback');
                    },
                );
            },
        );
        $thirdFailure = new AuditWriteException('The third attempt failed.', 1793180209);

        try {
            $subject->run(
                static function () use ($subject, $actions, $thirdFailure): never {
                    $subject->afterCommit(
                        static function () use ($actions): void {
                            $actions->append('third attempt publication');
                        },
                    );

                    throw $thirdFailure;
                },
            );
            self::fail('The third attempt must fail.');
        } catch (AuditWriteException $failure) {
            self::assertSame($thirdFailure, $failure);
        }

        // A failed attempt's commit actions are dropped even when the next
        // successful attempt commits right after it.
        $subject->run(
            static function () use ($subject, $actions): void {
                $subject->afterCommit(
                    static function () use ($actions): void {
                        $actions->append('fourth committed');
                    },
                );
            },
        );

        self::assertSame(
            ['first rollback', 'second committed', 'fourth committed'],
            $actions->getArrayCopy(),
        );
        self::assertFalse($subject->isActive());
    }

    private function subject(Connection $connection, ?LoggerInterface $logger = null): VaultMutationTransaction
    {
        $pool = self::createStub(ConnectionPool::class);
        $pool->method('getConnectionForTable')->willReturn($connection);

        return new VaultMutationTransaction($pool, $logger);
    }

    /**
     * @return Connection&MockObject
     */
    private function sqliteConnectionForAttempts(
        ?AuditWriteException $rollbackFailure = null,
    ): Connection {
        /** @var ArrayObject<string, bool> $state */
        $state      = new ArrayObject(['active' => false]);
        $connection = $this->createMock(Connection::class);
        $connection
            ->method('getDatabasePlatform')
            ->willReturn(new SQLitePlatform());
        $connection
            ->method('isTransactionActive')
            ->willReturnCallback(static fn (): bool => $state['active'] ?? false);
        $connection->expects(self::atLeastOnce())->method('beginTransaction')
            ->willReturnCallback(
                static function () use ($state): void {
                    $state['active'] = true;
                },
            );
        $connection
            ->method('commit')
            ->willReturnCallback(
                static function () use ($state): void {
                    $state['active'] = false;
                },
            );
        if ($rollbackFailure instanceof AuditWriteException) {
            $connection
                ->method('rollBack')
                ->willThrowException($rollbackFailure);
        } else {
            $connection
                ->method('rollBack')
                ->willReturnCallback(
                    static function () use ($state): void {
                        $state['active'] = false;
                    },
                );
        }

        return $connection;
    }
}
