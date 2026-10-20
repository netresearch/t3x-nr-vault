<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Sink;

use Error;
use IteratorAggregate;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\Sink\AuditSinkInterface;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistry;
use Netresearch\NrVault\Audit\Sink\SinkDeliveryStateRepositoryInterface;
use Netresearch\NrVault\Event\AuditIntegrityAlertEvent;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Stringable;
use Throwable;
use Traversable;

#[CoversClass(AuditSinkRegistry::class)]
final class AuditSinkContractTest extends TestCase
{
    /**
     * @param 'entry'|'anchor'|'alert'|'enablement'|'identifiers'|'success-state' $operation
     * @param class-string<Throwable> $failureClass
     */
    #[Test]
    #[DataProvider('identifierFailures')]
    public function sinkIdentifierFailureCannotEscapeTheRegistry(
        string $operation,
        string $failureClass,
    ): void {
        $failure = new $failureClass('https://user:password@example.test/private/file');
        $identityCalls = 0;
        $brokenCalls = 0;
        $healthyCalls = 0;
        $broken = self::createStub(AuditSinkInterface::class);
        $broken
            ->method('getIdentifier')
            ->willReturnCallback(
                static function () use ($failure, &$identityCalls): string {
                    ++$identityCalls;

                    throw $failure;
                },
            );
        if ($operation === 'enablement') {
            $broken
                ->method('isEnabled')
                ->willThrowException(new RuntimeException('enablement failed'));
        } else {
            $broken->method('isEnabled')->willReturn(true);
        }

        $publishMethod = match ($operation) {
            'anchor' => 'publishAnchor',
            'alert' => 'publishAlert',
            default => 'publish',
        };
        $broken
            ->method($publishMethod)
            ->willReturnCallback(
                static function () use ($operation, &$brokenCalls): void {
                    ++$brokenCalls;
                    if ($operation !== 'success-state') {
                        throw new RuntimeException(
                            'https://user:password@example.test/publish',
                            692441199,
                        );
                    }
                },
            );
        $healthy = self::createStub(AuditSinkInterface::class);
        $healthy->method('getIdentifier')->willReturn('healthy');
        $healthy->method('isEnabled')->willReturn(true);
        $healthy
            ->method($publishMethod)
            ->willReturnCallback(
                static function () use (&$healthyCalls): void {
                    ++$healthyCalls;
                },
            );
        $successes = [];
        $failures = [];
        $state = self::createStub(SinkDeliveryStateRepositoryInterface::class);
        $state
            ->method('recordSuccess')
            ->willReturnCallback(
                static function (string $id) use (&$successes): void {
                    $successes[] = $id;
                },
            );
        $state
            ->method('recordFailure')
            ->willReturnCallback(
                static function (
                    string $id,
                    string $message,
                ) use (&$failures): void {
                    $failures[] = [$id, $message];
                },
            );
        $logs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger
            ->method('error')
            ->willReturnCallback(
                static function (
                    string|Stringable $message,
                    array $context,
                ) use (&$logs): void {
                    $logs[] = $context;
                },
            );
        $alerts = [];
        $dispatcher = self::createStub(EventDispatcherInterface::class);
        $dispatcher
            ->method('dispatch')
            ->willReturnCallback(
                static function (object $event) use (&$alerts): object {
                    $alerts[] = $event;

                    return $event;
                },
            );
        $subject = new AuditSinkRegistry([$broken, $healthy], $logger, $dispatcher, $state);
        $delivering = \in_array(
            $operation,
            ['entry', 'anchor', 'alert', 'success-state'],
            true,
        );
        $failuresPerCall = \in_array($operation, ['entry', 'anchor', 'alert', 'enablement'], true) ? 2 : 1;
        $expected = match ($operation) {
            'identifiers' => ['healthy'],
            'enablement' => true,
            'success-state' => 2,
            default => 1,
        };
        for ($call = 1; $call <= 2; ++$call) {
            $thrown = null;
            $result = null;

            try {
                $result = $this->invoke($subject, $operation);
            } catch (Throwable $caught) {
                $thrown = $caught;
            }

            self::assertNull(
                $thrown,
                'Registry never-throws contract: ' . $operation,
            );
            self::assertSame($expected, $result);
            self::assertSame(
                $call,
                $identityCalls,
                'A failed identity must be resolved only once per visit.',
            );
            self::assertSame($delivering ? $call : 0, $brokenCalls);
            self::assertSame($delivering ? $call : 0, $healthyCalls);
            self::assertSame(
                $call * $failuresPerCall,
                $subject->getFailureCount(),
            );
            self::assertSame([], $subject->getFailureCountsBySink());
            self::assertSame(
                [],
                $failures,
                'An unknown identity must not create a persisted destination.',
            );
            self::assertSame(
                $delivering ? array_fill(0, $call, 'healthy') : [],
                $successes,
            );
            self::assertCount($call * $failuresPerCall, $logs);
            self::assertCount(
                $operation === 'alert' ? 0 : $call * $failuresPerCall,
                $alerts,
            );
        }

        foreach ($logs as $context) {
            self::assertArrayNotHasKey('sink', $context);
            self::assertArrayNotHasKey('error', $context);
            self::assertArrayHasKey('record', $context);
            self::assertArrayHasKey('exception', $context);
            self::assertStringNotContainsString(
                'password',
                json_encode($context, JSON_THROW_ON_ERROR),
            );
        }

        foreach ($alerts as $event) {
            self::assertInstanceOf(AuditIntegrityAlertEvent::class, $event);
            self::assertSame(
                AuditIntegrityReason::SinkFailure,
                $event->getReason(),
            );
            self::assertArrayNotHasKey('sink', $event->getAlert()->context);
            self::assertStringNotContainsString(
                'password',
                json_encode($event->getAlert(), JSON_THROW_ON_ERROR),
            );
        }
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>}>
     */
    public static function identifierFailures(): iterable
    {
        foreach ([
            'entry',
            'anchor',
            'alert',
            'enablement',
            'identifiers',
            'success-state',
        ] as $operation) {
            foreach ([RuntimeException::class, Error::class] as $failureClass) {
                yield $operation . '/' . $failureClass => [$operation, $failureClass];
            }
        }
    }

    /**
     * @param 'entry'|'anchor'|'alert'|'external'|'identifiers' $operation
     * @param class-string<Throwable> $failureClass
     */
    #[Test]
    #[DataProvider('iteratorFailures')]
    public function taggedIteratorFailureCannotEscapeTheRegistry(
        string $operation,
        string $failureClass,
        bool $prefix,
    ): void {
        $healthy = self::createStub(AuditSinkInterface::class);
        $healthy->method('getIdentifier')->willReturn('healthy');
        $healthy->method('isEnabled')->willReturn(true);
        $acceptedCalls = 0;
        $method = match ($operation) {
            'anchor' => 'publishAnchor',
            'alert' => 'publishAlert',
            default => 'publish',
        };
        $healthy
            ->method($method)
            ->willReturnCallback(
                static function () use (&$acceptedCalls): void {
                    ++$acceptedCalls;
                },
            );
        $sinks = (static function () use ($failureClass, $healthy, $prefix): iterable {
            if ($prefix) {
                yield $healthy;
            }

            throw new $failureClass('https://user:password@example.test/iterator', 694456012);
        })();
        $subject = $this->subject($sinks);
        $thrown = null;
        $result = null;

        try {
            $result = $this->invoke($subject, $operation);
        } catch (Throwable $caught) {
            $thrown = $caught;
        }

        self::assertNull(
            $thrown,
            'Registry never-throws contract: ' . $operation,
        );
        $expected = match ($operation) {
            'external' => $prefix,
            'identifiers' => $prefix ? ['healthy'] : [],
            default => $prefix ? 1 : 0,
        };
        self::assertSame(
            $expected,
            $result,
            'Previously accepted evidence must survive a later iterator failure.',
        );
        self::assertSame(
            $prefix && !\in_array($operation, ['external', 'identifiers'], true) ? 1 : 0,
            $acceptedCalls,
        );
        self::assertSame(
            $prefix && $operation === 'external' ? 0 : 1,
            $subject->getFailureCount(),
        );
        self::assertSame([], $subject->getFailureCountsBySink());
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>, bool}>
     */
    public static function iteratorFailures(): iterable
    {
        foreach (['entry', 'anchor', 'alert', 'external', 'identifiers'] as $operation) {
            foreach ([RuntimeException::class, Error::class] as $failureClass) {
                foreach ([false, true] as $prefix) {
                    yield $operation . '/' . $failureClass . '/' . (int) $prefix => [$operation, $failureClass, $prefix];
                }
            }
        }
    }

    #[Test]
    public function iteratorFailureDuringReentrantAlertDeliveryPreservesPrefixAndReleasesGuard(): void
    {
        $healthy = self::createStub(AuditSinkInterface::class);
        $healthy->method('getIdentifier')->willReturn('healthy');
        $healthy->method('isEnabled')->willReturn(true);
        $entries = 0;
        $alerts = 0;
        $healthy
            ->method('publish')
            ->willReturnCallback(
                static function () use (&$entries): void {
                    ++$entries;
                },
            );
        $healthy
            ->method('publishAlert')
            ->willReturnCallback(
                static function () use (&$alerts): void {
                    ++$alerts;
                },
            );
        $sinks = new class ($healthy) implements IteratorAggregate {
            public function __construct(
                private readonly AuditSinkInterface $healthy,
            ) {}

            /**
             * @return Traversable<int, AuditSinkInterface>
             */
            public function getIterator(): Traversable
            {
                yield $this->healthy;

                throw new Error(
                    'https://user:password@example.test/iterator',
                    621950835,
                );
            }
        };
        $nestedResults = [];
        $dispatcher = self::createStub(EventDispatcherInterface::class);
        $subject = new AuditSinkRegistry($sinks, new NullLogger(), $dispatcher);
        $dispatcher
            ->method('dispatch')
            ->willReturnCallback(
                static function (
                    object $event,
                ) use ($subject, &$nestedResults): object {
                    if ($event instanceof AuditIntegrityAlertEvent) {
                        $nestedResults[] = $subject->dispatchAlert($event->getAlert());
                    }

                    return $event;
                },
            );
        for ($call = 1; $call <= 2; ++$call) {
            $thrown = null;
            $result = null;

            try {
                $result = $subject->dispatch($this->createEntry(), 'tip');
            } catch (Throwable $caught) {
                $thrown = $caught;
            }

            self::assertNull($thrown);
            self::assertSame(1, $result);
            self::assertSame($call, $entries);
            self::assertSame($call, $alerts);
            self::assertSame(array_fill(0, $call, 1), $nestedResults);
            self::assertSame(2 * $call, $subject->getFailureCount());
            self::assertSame([], $subject->getFailureCountsBySink());
        }
    }

    /**
     * @param iterable<AuditSinkInterface> $sinks
     */
    private function subject(iterable $sinks): AuditSinkRegistry
    {
        $dispatcher = self::createStub(EventDispatcherInterface::class);
        $dispatcher
            ->method('dispatch')
            ->willReturnCallback(static fn (object $event): object => $event);

        return new AuditSinkRegistry(
            $sinks,
            new NullLogger(),
            $dispatcher,
            self::createStub(SinkDeliveryStateRepositoryInterface::class),
        );
    }

    /**
     * @param 'entry'|'success-state'|'anchor'|'alert'|'enablement'|'external'|'identifiers' $operation
     */
    private function invoke(
        AuditSinkRegistry $subject,
        string $operation,
    ): mixed {
        return match ($operation) {
            'entry', 'success-state' => $subject->dispatch($this->createEntry(), 'tip'),
            'anchor' => $subject->dispatchAnchor(
                new ChainTipAnchor(
                    sequence: 7,
                    chainTip: 'tip',
                    timestamp: 1750000000,
                    hmacEpoch: 1,
                ),
            ),
            'alert' => $subject->dispatchAlert(
                AuditIntegrityAlert::create(
                    AuditIntegrityReason::TableReset,
                    'reset',
                ),
            ),
            'enablement', 'external' => $subject->hasExternalAuditSink(),
            'identifiers' => $subject->getEnabledSinkIdentifiers(),
        };
    }

    private function createEntry(int $uid = 1): AuditLogEntry
    {
        return new AuditLogEntry(
            uid: $uid,
            secretIdentifier: 'api/stripe',
            action: 'read',
            success: true,
            errorMessage: null,
            reason: null,
            actorUid: 7,
            actorType: 'be_user',
            actorUsername: 'editor',
            actorRole: 'groups:1',
            ipAddress: '203.0.113.7',
            userAgent: 'Mozilla/5.0',
            requestId: 'req-1',
            previousHash: 'prev',
            entryHash: 'hash-' . $uid,
            hashBefore: '',
            hashAfter: '',
            crdate: 1750000000,
            context: [],
        );
    }
}
