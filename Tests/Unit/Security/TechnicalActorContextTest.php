<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Security;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Exception\TechnicalActorException;
use Netresearch\NrVault\Security\TechnicalActor;
use Netresearch\NrVault\Security\TechnicalActorContext;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\EventDispatcher\EventDispatcherInterface;
use RuntimeException;
use TYPO3\CMS\Core\Authentication\GroupResolver;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\DefaultRestrictionContainer;

#[CoversClass(TechnicalActorContext::class)]
#[AllowMockObjectsWithoutExpectations]
final class TechnicalActorContextTest extends TestCase
{
    #[Test]
    public function runAsRejectsZeroUidWithoutTouchingTheDatabase(): void
    {
        $connectionPool = $this->createMock(ConnectionPool::class);
        $connectionPool->expects(self::never())->method('getQueryBuilderForTable');

        $subject = new TechnicalActorContext($connectionPool, $this->createGroupResolver([]));

        $called = false;

        try {
            $subject->runAs(0, static function () use (&$called): void {
                $called = true;
            });
            self::fail('Expected TechnicalActorException');
        } catch (TechnicalActorException $exception) {
            self::assertSame(1784000001, $exception->getCode());
        }

        self::assertFalse($called);
    }

    #[Test]
    public function runAsRejectsNegativeUid(): void
    {
        $connectionPool = $this->createMock(ConnectionPool::class);
        $connectionPool->expects(self::never())->method('getQueryBuilderForTable');

        $subject = new TechnicalActorContext($connectionPool, $this->createGroupResolver([]));

        $this->expectException(TechnicalActorException::class);
        $this->expectExceptionCode(1784000001);

        $subject->runAs(-5, static fn (): bool => true);
    }

    #[Test]
    public function runAsRejectsUnknownOrDeletedUid(): void
    {
        $subject = $this->createSubject([false]);

        $called = false;

        try {
            $subject->runAs(42, static function () use (&$called): void {
                $called = true;
            });
            self::fail('Expected TechnicalActorException');
        } catch (TechnicalActorException $exception) {
            self::assertSame(1784000002, $exception->getCode());
        }

        self::assertFalse($called);
    }

    #[Test]
    public function runAsRejectsDisabledUser(): void
    {
        $subject = $this->createSubject([$this->userRow(uid: 42, disable: 1)]);

        $this->expectException(TechnicalActorException::class);
        $this->expectExceptionCode(1784000003);

        $subject->runAs(42, static fn (): bool => true);
    }

    #[Test]
    public function runAsRejectsUserBeforeStarttime(): void
    {
        $subject = $this->createSubject([$this->userRow(uid: 42, starttime: time() + 3600)]);

        $this->expectException(TechnicalActorException::class);
        $this->expectExceptionCode(1784000004);

        $subject->runAs(42, static fn (): bool => true);
    }

    #[Test]
    public function runAsRejectsUserAfterEndtime(): void
    {
        $subject = $this->createSubject([$this->userRow(uid: 42, endtime: time() - 3600)]);

        $this->expectException(TechnicalActorException::class);
        $this->expectExceptionCode(1784000004);

        $subject->runAs(42, static fn (): bool => true);
    }

    #[Test]
    public function runAsReturnsTheCallableResult(): void
    {
        $subject = $this->createSubject([$this->userRow(uid: 42)]);

        $result = $subject->runAs(42, static fn (): string => 'secret-value');

        self::assertSame('secret-value', $result);
    }

    #[Test]
    public function getCurrentActorIsNullOutsideAnyScope(): void
    {
        $subject = $this->createSubject([]);

        self::assertNull($subject->getCurrentActor());
    }

    #[Test]
    public function runAsExposesTheValidatedActorInsideTheScope(): void
    {
        $subject = $this->createSubject([
            $this->userRow(uid: 42, username: 'tech_indexer', admin: 1),
        ]);

        $subject->runAs(42, static function () use ($subject): void {
            $actor = $subject->getCurrentActor();

            self::assertInstanceOf(TechnicalActor::class, $actor);
            self::assertSame(42, $actor->uid);
            self::assertSame('tech_indexer', $actor->username);
            self::assertTrue($actor->admin);
            self::assertSame([], $actor->groupIds);
        });

        self::assertNull($subject->getCurrentActor());
    }

    #[Test]
    public function runAsResolvesGroupIdsViaCoreGroupResolution(): void
    {
        $subject = $this->createSubject(
            [$this->userRow(uid: 42, usergroup: '5,7')],
            [
                ['uid' => 5, 'subgroup' => ''],
                ['uid' => 7, 'subgroup' => ''],
            ],
        );

        $subject->runAs(42, static function () use ($subject): void {
            $actor = $subject->getCurrentActor();

            self::assertInstanceOf(TechnicalActor::class, $actor);
            self::assertSame([5, 7], $actor->groupIds);
        });
    }

    #[Test]
    public function runAsRestoresThePreviousStateWhenTheCallableThrows(): void
    {
        $subject = $this->createSubject([$this->userRow(uid: 42)]);

        try {
            $subject->runAs(42, static function (): never {
                throw new RuntimeException('boom', 1234);
            });
            self::fail('Expected RuntimeException');
        } catch (RuntimeException $exception) {
            self::assertSame('boom', $exception->getMessage());
        }

        self::assertNull($subject->getCurrentActor());
    }

    #[Test]
    public function runAsNestsWithInnermostActorWinningAndOuterRestored(): void
    {
        $subject = $this->createSubject([
            $this->userRow(uid: 42, username: 'outer'),
            $this->userRow(uid: 43, username: 'inner'),
        ]);

        $subject->runAs(42, static function () use ($subject): void {
            $outer = $subject->getCurrentActor();
            self::assertInstanceOf(TechnicalActor::class, $outer);
            self::assertSame(42, $outer->uid);

            $subject->runAs(43, static function () use ($subject): void {
                $inner = $subject->getCurrentActor();
                self::assertInstanceOf(TechnicalActor::class, $inner);
                self::assertSame(43, $inner->uid);
            });

            $restored = $subject->getCurrentActor();
            self::assertInstanceOf(TechnicalActor::class, $restored);
            self::assertSame(42, $restored->uid);
        });

        self::assertNull($subject->getCurrentActor());
    }

    /**
     * Build a context whose be_users lookups return the given rows in order
     * and whose group resolution sees the given be_groups rows.
     *
     * @param list<array<string, mixed>|false> $userRows
     * @param list<array<string, mixed>> $groupRows
     */
    private function createSubject(array $userRows, array $groupRows = []): TechnicalActorContext
    {
        $userResult = $this->createMock(Result::class);
        if ($userRows !== []) {
            $userResult->method('fetchAssociative')->willReturnOnConsecutiveCalls(...$userRows);
        }

        $connectionPool = $this->createMock(ConnectionPool::class);
        $connectionPool
            ->method('getQueryBuilderForTable')
            ->with('be_users')
            ->willReturn($this->createQueryBuilderMock($userResult));

        return new TechnicalActorContext($connectionPool, $this->createGroupResolver($groupRows));
    }

    /**
     * Real core GroupResolver over a mocked be_groups table: the resolution
     * logic (subgroup recursion, event dispatch) runs for real, only the DB
     * and the event dispatcher are doubles.
     *
     * @param list<array<string, mixed>> $groupRows
     */
    private function createGroupResolver(array $groupRows): GroupResolver
    {
        $groupResult = $this->createMock(Result::class);
        $groupResult
            ->method('fetchAssociative')
            ->willReturnOnConsecutiveCalls(...[...$groupRows, false]);

        $connectionPool = $this->createMock(ConnectionPool::class);
        $connectionPool
            ->method('getQueryBuilderForTable')
            ->with('be_groups')
            ->willReturn($this->createQueryBuilderMock($groupResult));

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->method('dispatch')->willReturnArgument(0);

        // @internal core class; see TechnicalActorContext::resolveGroupIds().
        return new GroupResolver($eventDispatcher, $connectionPool);
    }

    private function createQueryBuilderMock(Result&MockObject $result): QueryBuilder&MockObject
    {
        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('field = :value');
        $expressionBuilder->method('in')->willReturn('field IN (:value)');

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('getRestrictions')->willReturn($this->createMock(DefaultRestrictionContainer::class));
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $queryBuilder->method('executeQuery')->willReturn($result);

        return $queryBuilder;
    }

    /**
     * @return array<string, mixed>
     */
    private function userRow(
        int $uid,
        string $username = 'technical_user',
        int $admin = 0,
        int $disable = 0,
        int $starttime = 0,
        int $endtime = 0,
        string $usergroup = '',
    ): array {
        return [
            'uid' => $uid,
            'username' => $username,
            'admin' => $admin,
            'disable' => $disable,
            'starttime' => $starttime,
            'endtime' => $endtime,
            'usergroup' => $usergroup,
        ];
    }
}
