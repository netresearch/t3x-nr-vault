<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Sink;

use Netresearch\NrVault\Audit\Sink\SinkDeliveryState;
use Netresearch\NrVault\Audit\Sink\SinkDeliveryStateRepository;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;
use RuntimeException;
use TYPO3\CMS\Core\Registry;

#[CoversClass(SinkDeliveryStateRepository::class)]
#[CoversClass(SinkDeliveryState::class)]
final class SinkDeliveryStateRepositoryTest extends TestCase
{
    /** @var array<string, mixed> Simulated sys_registry storage. */
    private array $storage = [];

    #[Test]
    public function firstSuccessIsPersisted(): void
    {
        $subject = $this->createSubject();

        $subject->recordSuccess('webhook');

        $state = $subject->getState('webhook');
        self::assertTrue($state->hasEverSucceeded());
        self::assertFalse($state->isFailing());
        self::assertSame(0, $state->consecutiveFailures);
    }

    #[Test]
    public function failureIncrementsConsecutiveAndTotalCounters(): void
    {
        $subject = $this->createSubject();

        $subject->recordFailure('webhook', 'collector unreachable');
        $subject->recordFailure('webhook', 'still unreachable');

        $state = $subject->getState('webhook');
        self::assertTrue($state->isFailing());
        self::assertSame(2, $state->consecutiveFailures);
        self::assertSame(2, $state->totalFailures);
        self::assertSame('still unreachable', $state->lastError);
        self::assertGreaterThan(0, $state->lastFailureAt);
    }

    #[Test]
    public function successAfterFailuresResetsTheConsecutiveCounterButKeepsTheTotal(): void
    {
        $subject = $this->createSubject();

        $subject->recordFailure('file', 'disk full');
        $subject->recordSuccess('file');

        $state = $subject->getState('file');
        self::assertFalse($state->isFailing());
        self::assertSame(0, $state->consecutiveFailures);
        self::assertSame(1, $state->totalFailures, 'lifetime counter must survive the recovery');
        self::assertTrue($state->hasEverSucceeded());
        self::assertSame('', $state->lastError);
    }

    #[Test]
    public function healthySuccessesAreThrottledToOneWritePerInterval(): void
    {
        $writes = 0;
        $subject = $this->createSubject($writes);

        $subject->recordSuccess('syslog');
        $subject->recordSuccess('syslog');
        $subject->recordSuccess('syslog');

        self::assertSame(1, $writes, 'repeated healthy successes must not write per audit entry');
    }

    #[Test]
    public function unknownSinkYieldsAPristineState(): void
    {
        $state = $this->createSubject()->getState('never-seen');

        self::assertFalse($state->hasEverSucceeded());
        self::assertFalse($state->isFailing());
        self::assertSame(0, $state->totalFailures);
    }

    #[Test]
    public function aThrowingRegistryIsSwallowedFailSafe(): void
    {
        $registry = $this->createMock(Registry::class);
        $registry->method('get')->willThrowException(new RuntimeException('sys_registry broken'));
        $registry->method('set')->willThrowException(new RuntimeException('sys_registry broken'));

        $subject = new SinkDeliveryStateRepository($registry, new NullLogger());

        // Bookkeeping must never fail the audited operation.
        $subject->recordSuccess('webhook');
        $subject->recordFailure('webhook', 'boom');

        $state = $subject->getState('webhook');
        self::assertFalse($state->hasEverSucceeded());
    }

    #[Test]
    public function overlongErrorMessagesAreTruncated(): void
    {
        $subject = $this->createSubject();

        $subject->recordFailure('webhook', str_repeat('x', 2000));

        self::assertSame(500, mb_strlen($subject->getState('webhook')->lastError));
    }

    private function createSubject(?int &$writes = null): SinkDeliveryStateRepository
    {
        $registry = $this->createMock(Registry::class);
        $registry->method('get')->willReturnCallback(
            fn (string $namespace, string $key): mixed => $this->storage[$namespace . '/' . $key] ?? null,
        );
        $registry->method('set')->willReturnCallback(
            function (string $namespace, string $key, mixed $value) use (&$writes): void {
                $this->storage[$namespace . '/' . $key] = $value;
                if ($writes !== null) {
                    ++$writes;
                }
            },
        );

        return new SinkDeliveryStateRepository($registry, new NullLogger());
    }
}
