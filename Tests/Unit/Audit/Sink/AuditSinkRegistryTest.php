<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Sink;

use Error;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\Sink\AuditSinkInterface;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistry;
use Netresearch\NrVault\Audit\Sink\SinkDeliveryState;
use Netresearch\NrVault\Audit\Sink\SinkDeliveryStateRepositoryInterface;
use Netresearch\NrVault\Event\AuditIntegrityAlertEvent;
use Netresearch\NrVault\Exception\AuditSinkException;
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

#[CoversClass(AuditSinkRegistry::class)]
final class AuditSinkRegistryTest extends TestCase
{
    #[Test]
    public function dispatchDeliversToEveryEnabledSink(): void
    {
        $first = new SpyAuditSink('first');
        $second = new SpyAuditSink('second');

        $accepted = $this->createSubject([$first, $second])->dispatch($this->createEntry(), 'tip');

        self::assertSame(2, $accepted);
        self::assertSame(1, $first->publishCalls);
        self::assertSame(1, $second->publishCalls);
    }

    #[Test]
    public function disabledSinksAreSkipped(): void
    {
        $enabled = new SpyAuditSink('enabled');
        $disabled = new SpyAuditSink('disabled', enabled: false);

        $accepted = $this->createSubject([$enabled, $disabled])->dispatch($this->createEntry(), 'tip');

        self::assertSame(1, $accepted);
        self::assertSame(0, $disabled->publishCalls);
    }

    #[Test]
    public function dispatchPassesTheChainTipThrough(): void
    {
        $sink = new SpyAuditSink('spy');

        $this->createSubject([$sink])->dispatch($this->createEntry(), 'tip-abc');

        self::assertSame(['tip-abc'], $sink->chainTips);
    }

    /**
     * The central guarantee: one broken destination must not blind the others.
     * Partial external evidence beats none.
     */
    #[Test]
    public function aThrowingSinkDoesNotPreventTheRemainingSinksFromReceivingTheEntry(): void
    {
        $broken = new SpyAuditSink('broken', throwOnPublish: AuditSinkException::writeFailed('broken', 'disk full'));
        $healthy = new SpyAuditSink('healthy');

        $accepted = $this->createSubject([$broken, $healthy])->dispatch($this->createEntry(), 'tip');

        self::assertSame(1, $accepted, 'only the healthy sink accepted the record');
        self::assertSame(1, $healthy->publishCalls, 'the healthy sink was still called');
    }

    /**
     * The audited vault operation must survive any sink failure, so no method on
     * the registry may throw.
     */
    #[Test]
    public function dispatchNeverThrowsEvenWhenEverySinkFails(): void
    {
        $registry = $this->createSubject([
            new SpyAuditSink('a', throwOnPublish: new RuntimeException('boom')),
            new SpyAuditSink('b', throwOnPublish: new Error('fatal-ish')),
        ]);

        self::assertSame(0, $registry->dispatch($this->createEntry(), 'tip'));
    }

    #[Test]
    public function failuresAreCountedGloballyAndPerSink(): void
    {
        $registry = $this->createSubject([
            new SpyAuditSink('broken', throwOnPublish: new RuntimeException('boom')),
            new SpyAuditSink('healthy'),
        ]);

        $registry->dispatch($this->createEntry(), 'tip');
        $registry->dispatch($this->createEntry(), 'tip');

        self::assertSame(2, $registry->getFailureCount());
        self::assertSame(['broken' => 2], $registry->getFailureCountsBySink());
    }

    #[Test]
    public function failureIsLoggedWithTheSinkIdentifier(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with(
                self::stringContains('audit sink delivery failed'),
                self::callback(static fn (array $context): bool => ($context['sink'] ?? null) === 'broken'),
            );

        $this->createSubject(
            [new SpyAuditSink('broken', throwOnPublish: new RuntimeException('boom'))],
            logger: $logger,
        )->dispatch($this->createEntry(), 'tip');
    }

    /**
     * The log line must not name the secret's value or any credential; the uid
     * and action are enough to correlate with the database row.
     */
    #[Test]
    public function failureLogContextCarriesOnlyNonSensitiveRecordFacts(): void
    {
        $captured = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('error')->willReturnCallback(
            static function (string|Stringable $message, array $context) use (&$captured): void {
                $captured = $context;
            },
        );

        $this->createSubject(
            [new SpyAuditSink('broken', throwOnPublish: new RuntimeException('boom'))],
            logger: $logger,
        )->dispatch($this->createEntry(uid: 9), 'tip');

        self::assertSame(9, $captured['uid']);
        self::assertSame('read', $captured['action']);
        self::assertSame('broken', $captured['sink']);
    }

    #[Test]
    public function failureRaisesASinkFailureIntegrityAlert(): void
    {
        $dispatcher = new RecordingEventDispatcher();

        $this->createSubject(
            [new SpyAuditSink('broken', throwOnPublish: new RuntimeException('boom'))],
            eventDispatcher: $dispatcher,
        )->dispatch($this->createEntry(), 'tip');

        self::assertCount(1, $dispatcher->events);
        self::assertSame(AuditIntegrityReason::SinkFailure, $dispatcher->events[0]->getReason());
        self::assertFalse($dispatcher->events[0]->isTamperEvidence());
        self::assertSame('broken', $dispatcher->events[0]->getAlert()->context['sink']);
    }

    #[Test]
    public function successfulDispatchRaisesNoAlert(): void
    {
        $dispatcher = new RecordingEventDispatcher();

        $this->createSubject([new SpyAuditSink('healthy')], eventDispatcher: $dispatcher)
            ->dispatch($this->createEntry(), 'tip');

        self::assertSame([], $dispatcher->events);
    }

    /**
     * A sink whose `isEnabled()` throws must be treated as disabled, not allowed
     * to take the audited operation down from outside the per-call try/catch.
     */
    #[Test]
    public function aSinkThatThrowsFromIsEnabledIsTreatedAsDisabledAndCounted(): void
    {
        $registry = $this->createSubject([
            new SpyAuditSink('probe-breaker', throwOnIsEnabled: new RuntimeException('config exploded')),
            new SpyAuditSink('healthy'),
        ]);

        self::assertSame(1, $registry->dispatch($this->createEntry(), 'tip'));
        self::assertSame(['probe-breaker' => 1], $registry->getFailureCountsBySink());
    }

    #[Test]
    public function dispatchAnchorDeliversTheAnchorToEveryEnabledSink(): void
    {
        $sink = new SpyAuditSink('spy');
        $anchor = new ChainTipAnchor(42, 'tip', 1_750_000_000, 3);

        $accepted = $this->createSubject([$sink])->dispatchAnchor($anchor);

        self::assertSame(1, $accepted);
        self::assertSame([$anchor], $sink->anchors);
    }

    #[Test]
    public function dispatchAnchorReturnsZeroWhenNoSinkIsEnabled(): void
    {
        $registry = $this->createSubject([new SpyAuditSink('off', enabled: false)]);

        self::assertSame(0, $registry->dispatchAnchor(new ChainTipAnchor(1, 'tip', 1, 3)));
    }

    #[Test]
    public function dispatchAlertDeliversTheAlertToEveryEnabledSink(): void
    {
        $sink = new SpyAuditSink('spy');
        $alert = AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'chain shrank');

        $accepted = $this->createSubject([$sink])->dispatchAlert($alert);

        self::assertSame(1, $accepted);
        self::assertSame([$alert], $sink->alerts);
    }

    /**
     * Without the reentrancy guard, a sink that fails while delivering an alert
     * raises a SINK_FAILURE alert, which the listener sends back through
     * dispatchAlert(), which fails again — unbounded recursion.
     */
    #[Test]
    public function aSinkFailingDuringAlertDeliveryRaisesNoFurtherAlert(): void
    {
        $dispatcher = new RecordingEventDispatcher();
        $registry = $this->createSubject(
            [new SpyAuditSink('broken', throwOnAlert: new RuntimeException('boom'))],
            eventDispatcher: $dispatcher,
        );

        $registry->dispatchAlert(AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'reset'));

        self::assertSame([], $dispatcher->events, 'no nested SINK_FAILURE alert was raised');
        self::assertSame(1, $registry->getFailureCount(), 'the failure was still counted');
    }

    /**
     * Simulates the real wiring: the listener forwards the alert back into the
     * registry. The guard must break the cycle rather than recursing.
     */
    #[Test]
    public function alertDeliveryTerminatesWhenTheListenerForwardsBackIntoTheRegistry(): void
    {
        $sink = new SpyAuditSink('broken', throwOnPublish: new RuntimeException('boom'));

        // The listener needs the registry that constructs the dispatcher, so the
        // cycle is closed through a mutable holder rather than a captured local
        // (which would still be null when the closure is built).
        $holder = new RegistryHolder();
        $dispatcher = new ForwardingEventDispatcher(static function (AuditIntegrityAlertEvent $event) use ($holder): void {
            $holder->registry?->dispatchAlert($event->getAlert());
        });

        $registry = $this->createSubject([$sink], eventDispatcher: $dispatcher);
        $holder->registry = $registry;

        $registry->dispatch($this->createEntry(), 'tip');

        // publish failed once; the forwarded alert reached publishAlert exactly
        // once and its own failure did not trigger another round.
        self::assertSame(1, $sink->publishCalls);
        self::assertSame(1, $sink->alertCalls);
    }

    /**
     * A throwing listener must not escalate into the audited operation.
     */
    #[Test]
    public function aThrowingEventListenerDoesNotBreakTheDispatch(): void
    {
        $dispatcher = new ForwardingEventDispatcher(static function (): never {
            throw new RuntimeException('listener exploded', 6282578635);
        });

        $registry = $this->createSubject(
            [new SpyAuditSink('broken', throwOnPublish: new RuntimeException('boom'))],
            eventDispatcher: $dispatcher,
        );

        self::assertSame(0, $registry->dispatch($this->createEntry(), 'tip'));
    }

    #[Test]
    public function hasExternalAuditSinkIsFalseWithoutSinks(): void
    {
        self::assertFalse($this->createSubject([])->hasExternalAuditSink());
    }

    #[Test]
    public function hasExternalAuditSinkIsFalseWhenEverySinkIsDisabled(): void
    {
        $registry = $this->createSubject([
            new SpyAuditSink('a', enabled: false),
            new SpyAuditSink('b', enabled: false),
        ]);

        self::assertFalse($registry->hasExternalAuditSink());
    }

    #[Test]
    public function hasExternalAuditSinkIsTrueWhenAtLeastOneSinkIsEnabled(): void
    {
        $registry = $this->createSubject([
            new SpyAuditSink('a', enabled: false),
            new SpyAuditSink('b'),
        ]);

        self::assertTrue($registry->hasExternalAuditSink());
    }

    #[Test]
    public function enabledSinkIdentifiersListOnlyTheUsableSinks(): void
    {
        $registry = $this->createSubject([
            new SpyAuditSink('syslog'),
            new SpyAuditSink('file', enabled: false),
            new SpyAuditSink('webhook'),
        ]);

        self::assertSame(['syslog', 'webhook'], $registry->getEnabledSinkIdentifiers());
    }

    #[Test]
    public function failureCountsStartAtZero(): void
    {
        $registry = $this->createSubject([new SpyAuditSink('a')]);

        self::assertSame(0, $registry->getFailureCount());
        self::assertSame([], $registry->getFailureCountsBySink());
    }

    /**
     * The tagged collection is iterated by several methods, so it must survive
     * repeated traversal.
     */
    #[Test]
    public function theSinkCollectionCanBeIteratedMoreThanOnce(): void
    {
        $registry = $this->createSubject([new SpyAuditSink('a'), new SpyAuditSink('b')]);

        self::assertTrue($registry->hasExternalAuditSink());
        self::assertSame(['a', 'b'], $registry->getEnabledSinkIdentifiers());
        self::assertSame(2, $registry->dispatch($this->createEntry(), 'tip'));
        self::assertSame(2, $registry->dispatchAnchor(new ChainTipAnchor(1, 't', 1, 3)));
    }

    /**
     * The guard has a second entry point: a sink that re-enters `dispatchAlert()`
     * from inside its own `publishAlert()` — what happens when a sink implementation
     * (or a listener it invokes synchronously) reports its own trouble as an alert.
     * That call must be dropped, not fanned out again, or the first alert delivery
     * recurses until the stack runs out.
     */
    #[Test]
    public function reEnteringAlertDispatchFromInsideASinkIsDroppedRatherThanRecursed(): void
    {
        $holder = new RegistryHolder();
        $sink = new ReentrantAlertSink('reentrant', $holder);

        $registry = $this->createSubject([$sink]);
        $holder->registry = $registry;

        $accepted = $registry->dispatchAlert(
            AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'chain shrank'),
        );

        self::assertSame(1, $accepted, 'the outer delivery still succeeds');
        self::assertSame(1, $sink->alertCalls, 'the sink must be asked exactly once');
        self::assertSame([0], $sink->reentrantResults, 'the nested delivery reports zero sinks reached');
    }

    /**
     * …and the guard is released afterwards: a one-off re-entry must not leave the
     * registry permanently unable to deliver alerts.
     */
    #[Test]
    public function theReentrancyGuardIsReleasedAfterTheOuterDeliveryCompletes(): void
    {
        $holder = new RegistryHolder();
        $sink = new ReentrantAlertSink('reentrant', $holder);

        $registry = $this->createSubject([$sink]);
        $holder->registry = $registry;

        $alert = AuditIntegrityAlert::create(AuditIntegrityReason::SinkFailure, 'first');
        $registry->dispatchAlert($alert);

        self::assertSame(1, $registry->dispatchAlert($alert), 'a later alert must still be delivered');
        self::assertSame(2, $sink->alertCalls);
    }

    #[Test]
    public function successfulDeliveryIsRecordedInThePersistentState(): void
    {
        $deliveryState = new RecordingDeliveryState();

        $this->createSubject([new SpyAuditSink('healthy')], deliveryState: $deliveryState)
            ->dispatch($this->createEntry(), 'tip');

        self::assertSame(['healthy'], $deliveryState->successes);
        self::assertSame([], $deliveryState->failures);
    }

    #[Test]
    public function failedDeliveryIsRecordedInThePersistentState(): void
    {
        $deliveryState = new RecordingDeliveryState();
        $broken = new SpyAuditSink('broken', throwOnPublish: new RuntimeException('collector unreachable'));

        $this->createSubject([$broken], deliveryState: $deliveryState)
            ->dispatch($this->createEntry(), 'tip');

        self::assertSame([], $deliveryState->successes);
        self::assertSame([['broken', 'collector unreachable']], $deliveryState->failures);
    }

    /**
     * @param class-string<Throwable> $loggerFailureClass
     */
    #[Test]
    #[DataProvider('throwingDiagnosticOperations')]
    public function throwingLoggerCannotInterruptHealthySinkDelivery(
        string $operation,
        string $loggerFailureClass,
    ): void {
        $sinkFailure = new RuntimeException('synthetic sink unavailable');
        $loggerFailure = new $loggerFailureClass('synthetic logger unavailable');
        $listenerFailure = new Error('synthetic listener unavailable');
        $broken = new SpyAuditSink(
            'broken',
            throwOnPublish: \in_array($operation, ['entry', 'listener'], true) ? $sinkFailure : null,
            throwOnAnchor: $operation === 'anchor' ? $sinkFailure : null,
            throwOnAlert: $operation === 'alert' ? $sinkFailure : null,
            throwOnIsEnabled: \in_array($operation, ['enabled', 'identifiers'], true) ? $sinkFailure : null,
        );
        $healthy = new SpyAuditSink('healthy');
        $diagnostics = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger
            ->method('error')
            ->willReturnCallback(
                static function (
                    string|Stringable $message,
                    array $context,
                ) use (&$diagnostics, $operation, $loggerFailure): void {
                    $diagnostics[] = ['message' => (string) $message, 'context' => $context];
                    if ($operation !== 'listener' || \count($diagnostics) % 2 === 0) {
                        throw $loggerFailure;
                    }
                },
            );
        $events = [];
        $dispatcher = new ForwardingEventDispatcher(
            static function (
                AuditIntegrityAlertEvent $event,
            ) use (&$events, $operation, $listenerFailure): void {
                $events[] = $event;
                if ($operation === 'listener') {
                    throw $listenerFailure;
                }
            },
        );
        $state = new RecordingDeliveryState();
        $subject = $this->createSubject([$broken, $healthy], $logger, $dispatcher, $state);
        $caught = null;
        $results = [];

        try {
            // A second call also proves alert delivery releases its reentrancy guard.
            for ($attempt = 0; $attempt < 2; ++$attempt) {
                $results[] = match ($operation) {
                    'anchor' => $subject->dispatchAnchor(
                        new ChainTipAnchor(42, 'tip', 1750000000, 3),
                    ),
                    'alert' => $subject->dispatchAlert(
                        AuditIntegrityAlert::create(
                            AuditIntegrityReason::TableReset,
                            'synthetic reset',
                        ),
                    ),
                    'enabled' => $subject->hasExternalAuditSink(),
                    'identifiers' => $subject->getEnabledSinkIdentifiers(),
                    default => $subject->dispatch($this->createEntry(), 'tip'),
                };
            }
        } catch (Throwable $failure) {
            $caught = $failure;
        }

        // Assertions belong outside every deliberately contained callback.
        self::assertNull(
            $caught,
            'Diagnostics must not escape the never-throws registry contract.',
        );
        $expected = match ($operation) {
            'enabled' => true,
            'identifiers' => ['healthy'],
            default => 1,
        };
        self::assertSame([$expected, $expected], $results);
        self::assertSame(2, $subject->getFailureCount());
        self::assertSame(['broken' => 2], $subject->getFailureCountsBySink());
        self::assertCount($operation === 'alert' ? 0 : 2, $events);
        foreach ($events as $event) {
            self::assertSame(
                AuditIntegrityReason::SinkFailure,
                $event->getReason(),
            );
            self::assertSame('broken', $event->getAlert()->context['sink']);
        }

        self::assertCount($operation === 'listener' ? 4 : 2, $diagnostics);
        $record = match ($operation) {
            'anchor' => 'anchor',
            'alert' => 'alert',
            'enabled', 'identifiers' => 'enablement-probe',
            default => 'entry',
        };
        $facts = match ($record) {
            'entry' => ['uid' => 1, 'action' => 'read'],
            'anchor' => ['sequence' => 42],
            'alert' => ['reason' => AuditIntegrityReason::TableReset->value],
            default => [],
        };
        foreach ($diagnostics as $index => $diagnostic) {
            if ($operation === 'listener' && $index % 2 === 1) {
                self::assertSame(
                    'nr-vault could not dispatch the audit sink failure alert.',
                    $diagnostic['message'],
                );
                self::assertSame(
                    [
                        'sink' => 'broken',
                        'error' => $listenerFailure->getMessage(),
                    ],
                    $diagnostic['context'],
                );
            } else {
                self::assertSame(
                    'nr-vault audit sink delivery failed; the database chain entry is unaffected.',
                    $diagnostic['message'],
                );
                self::assertSame(
                    [
                        'sink' => 'broken',
                        'record' => $record,
                        'error' => $sinkFailure->getMessage(),
                        'exception' => $sinkFailure::class,
                    ] + $facts,
                    $diagnostic['context'],
                );
            }
        }

        self::assertSame(
            [
                ['broken', $sinkFailure->getMessage()],
                ['broken', $sinkFailure->getMessage()],
            ],
            $state->failures,
        );
        $delivering = \in_array($operation, ['entry', 'listener', 'anchor', 'alert'], true);
        self::assertSame(
            $delivering ? ['healthy', 'healthy'] : [],
            $state->successes,
        );
        self::assertSame(
            \in_array($operation, ['entry', 'listener'], true) ? 2 : 0,
            $healthy->publishCalls,
        );
        self::assertSame($operation === 'anchor' ? 2 : 0, $healthy->anchorCalls);
        self::assertSame($operation === 'alert' ? 2 : 0, $healthy->alertCalls);
    }

    /**
     * @return iterable<string, array{string, class-string<Throwable>}>
     */
    public static function throwingDiagnosticOperations(): iterable
    {
        foreach (['entry', 'anchor', 'alert', 'enabled', 'identifiers', 'listener'] as $operation) {
            yield $operation . '/RuntimeException' => [$operation, RuntimeException::class];
            yield $operation . '/Error' => [$operation, Error::class];
        }
    }

    /**
     * @param list<AuditSinkInterface> $sinks
     */
    private function createSubject(
        array $sinks,
        ?LoggerInterface $logger = null,
        ?EventDispatcherInterface $eventDispatcher = null,
        ?SinkDeliveryStateRepositoryInterface $deliveryState = null,
    ): AuditSinkRegistry {
        return new AuditSinkRegistry(
            $sinks,
            $logger ?? new NullLogger(),
            $eventDispatcher ?? new RecordingEventDispatcher(),
            $deliveryState,
        );
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
            crdate: 1_750_000_000,
            context: [],
        );
    }
}

/**
 * A sink that records what it received and optionally fails on demand.
 *
 * Hand-written rather than a PHPUnit mock: the tests assert call ORDER and
 * CUMULATIVE counts across several dispatches, which reads far more clearly as
 * plain counters than as chained `expects()` constraints.
 *
 * @internal test helper
 */
final class SpyAuditSink implements AuditSinkInterface
{
    public int $publishCalls = 0;

    public int $anchorCalls = 0;

    public int $alertCalls = 0;

    /** @var list<string> */
    public array $chainTips = [];

    /** @var list<ChainTipAnchor> */
    public array $anchors = [];

    /** @var list<AuditIntegrityAlert> */
    public array $alerts = [];

    public function __construct(
        private readonly string $identifier,
        private readonly bool $enabled = true,
        private readonly ?Throwable $throwOnPublish = null,
        private readonly ?Throwable $throwOnAnchor = null,
        private readonly ?Throwable $throwOnAlert = null,
        private readonly ?Throwable $throwOnIsEnabled = null,
    ) {}

    public function publish(AuditLogEntry $entry, string $chainTip): void
    {
        ++$this->publishCalls;
        $this->chainTips[] = $chainTip;

        if ($this->throwOnPublish instanceof Throwable) {
            throw $this->throwOnPublish;
        }
    }

    public function publishAnchor(ChainTipAnchor $anchor): void
    {
        ++$this->anchorCalls;
        $this->anchors[] = $anchor;

        if ($this->throwOnAnchor instanceof Throwable) {
            throw $this->throwOnAnchor;
        }
    }

    public function publishAlert(AuditIntegrityAlert $alert): void
    {
        ++$this->alertCalls;
        $this->alerts[] = $alert;

        if ($this->throwOnAlert instanceof Throwable) {
            throw $this->throwOnAlert;
        }
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function isEnabled(): bool
    {
        if ($this->throwOnIsEnabled instanceof Throwable) {
            throw $this->throwOnIsEnabled;
        }

        return $this->enabled;
    }
}

/**
 * @internal test helper
 */
final class RecordingEventDispatcher implements EventDispatcherInterface
{
    /** @var list<AuditIntegrityAlertEvent> */
    public array $events = [];

    public function dispatch(object $event): object
    {
        if ($event instanceof AuditIntegrityAlertEvent) {
            $this->events[] = $event;
        }

        return $event;
    }
}

/**
 * Dispatcher that runs a single listener closure — used to model the real
 * listener forwarding alerts back into the registry.
 *
 * @internal test helper
 */
final class ForwardingEventDispatcher implements EventDispatcherInterface
{
    /** @var callable(AuditIntegrityAlertEvent): void */
    private $listener;

    /**
     * @param callable(AuditIntegrityAlertEvent): void $listener
     */
    public function __construct(callable $listener)
    {
        $this->listener = $listener;
    }

    public function dispatch(object $event): object
    {
        if ($event instanceof AuditIntegrityAlertEvent) {
            ($this->listener)($event);
        }

        return $event;
    }
}

/**
 * Mutable holder that lets a listener closure reach the registry that owns the
 * dispatcher it is registered on.
 *
 * @internal test helper
 */
final class RegistryHolder
{
    public ?AuditSinkRegistry $registry = null;
}

/**
 * A sink that calls `dispatchAlert()` back on the registry currently delivering
 * to it — the reentrancy the guard in `dispatchAlert()` exists to break.
 *
 * @internal test helper
 */
final class ReentrantAlertSink implements AuditSinkInterface
{
    public int $alertCalls = 0;

    /** @var list<int> Return values of the nested dispatchAlert() calls */
    public array $reentrantResults = [];

    public function __construct(
        private readonly string $identifier,
        private readonly RegistryHolder $holder,
    ) {}

    public function publish(AuditLogEntry $entry, string $chainTip): void {}

    public function publishAnchor(ChainTipAnchor $anchor): void {}

    public function publishAlert(AuditIntegrityAlert $alert): void
    {
        ++$this->alertCalls;

        $registry = $this->holder->registry;
        if ($registry instanceof AuditSinkRegistry) {
            $this->reentrantResults[] = $registry->dispatchAlert($alert);
        }
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function isEnabled(): bool
    {
        return true;
    }
}

/**
 * Records delivery-state bookkeeping calls for assertion.
 *
 * @internal test helper
 */
final class RecordingDeliveryState implements SinkDeliveryStateRepositoryInterface
{
    /** @var list<string> */
    public array $successes = [];

    /** @var list<array{0: string, 1: string}> */
    public array $failures = [];

    public function recordSuccess(string $sinkIdentifier): void
    {
        $this->successes[] = $sinkIdentifier;
    }

    public function recordFailure(string $sinkIdentifier, string $errorMessage): void
    {
        $this->failures[] = [$sinkIdentifier, $errorMessage];
    }

    public function getState(string $sinkIdentifier): SinkDeliveryState
    {
        return new SinkDeliveryState(sinkIdentifier: $sinkIdentifier);
    }
}
