<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use ArrayObject;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Doctrine\DBAL\Result;
use Netresearch\NrVault\Audit\VaultMutationTransaction;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

#[CoversClass(VaultMutationTransaction::class)]
final class VaultMutationTransactionTest extends TestCase
{
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
                        static function () use ($subject, &$replayed, &$active): never {
                            self::assertFalse($active);
                            self::assertFalse($subject->isActive());
                            $replayed = true;

                            throw new RuntimeException(
                                'denial replay failed',
                                1793180102,
                            );
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
        $connection->expects(self::never())->method('beginTransaction');
        $connection->expects(self::never())->method('commit');
        $connection->expects(self::never())->method('rollBack');
        $subject = $this->subject($connection);

        $this->expectException(AuditWriteException::class);
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

    private function subject(Connection $connection): VaultMutationTransaction
    {
        $pool = self::createStub(ConnectionPool::class);
        $pool->method('getConnectionForTable')->willReturn($connection);

        return new VaultMutationTransaction($pool);
    }
}
