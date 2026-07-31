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
use Netresearch\NrVault\Event\AuditIntegrityAlertEvent;
use Netresearch\NrVault\Exception\AuditSinkException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
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
     * @param list<AuditSinkInterface> $sinks
     */
    private function createSubject(
        array $sinks,
        ?LoggerInterface $logger = null,
        ?EventDispatcherInterface $eventDispatcher = null,
    ): AuditSinkRegistry {
        return new AuditSinkRegistry(
            $sinks,
            $logger ?? new NullLogger(),
            $eventDispatcher ?? new RecordingEventDispatcher(),
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
