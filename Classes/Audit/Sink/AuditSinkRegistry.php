<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Sink;

use Generator;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Event\AuditIntegrityAlertEvent;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Default {@see AuditSinkRegistryInterface} implementation.
 *
 * Sinks arrive as a tagged iterator (`nr_vault.audit_sink`, wired in
 * `Services.yaml`), so a consuming extension can add its own destination by
 * implementing {@see AuditSinkInterface} and tagging it — no change here.
 *
 * ## Failure containment
 *
 * Every sink call is wrapped individually. A throwing sink is logged, counted,
 * and does NOT stop the remaining sinks: partial external evidence beats none,
 * and one broken destination must not blind the others.
 *
 * ## Why this class is not readonly
 *
 * The failure counters are the point: the health surface needs to report "the
 * audit pipeline stopped flowing" and the only place that observes every
 * delivery is here. The class holds no configuration state — just counters and
 * the reentrancy flag below.
 *
 * ## Alert reentrancy
 *
 * A failed delivery raises a `SINK_FAILURE` alert, and the alert listener sends
 * alerts back through {@see dispatchAlert()}. Without a guard, one broken sink
 * would recurse until the stack ran out. `$dispatchingAlert` makes alert
 * delivery non-reentrant: failures observed while delivering an alert are logged
 * and counted but raise no further alert.
 */
final class AuditSinkRegistry implements AuditSinkRegistryInterface
{
    /** @var array<string, int> */
    private array $failuresBySink = [];

    private int $failureCount = 0;

    /** Guards against alert-delivery failures raising further alerts. */
    private bool $dispatchingAlert = false;

    /**
     * @param iterable<AuditSinkInterface> $sinks Tagged sink collection
     */
    public function __construct(
        private readonly iterable $sinks,
        private readonly LoggerInterface $logger,
        private readonly EventDispatcherInterface $eventDispatcher,
        /**
         * Persisted per-sink delivery health. Optional so pre-existing test
         * constructions keep working; without it only the in-process
         * counters exist (and `vault:doctor` reports the evidence gap).
         */
        private readonly ?SinkDeliveryStateRepositoryInterface $deliveryState = null,
    ) {}

    public function dispatch(AuditLogEntry $entry, string $chainTip): int
    {
        return $this->fanOut(
            static fn (AuditSinkInterface $sink): null => $sink->publish($entry, $chainTip),
            'entry',
            ['uid' => $entry->uid, 'action' => $entry->action],
        );
    }

    public function dispatchAnchor(ChainTipAnchor $anchor): int
    {
        return $this->fanOut(
            static fn (AuditSinkInterface $sink): null => $sink->publishAnchor($anchor),
            'anchor',
            ['sequence' => $anchor->sequence],
        );
    }

    public function dispatchAlert(AuditIntegrityAlert $alert): int
    {
        if ($this->dispatchingAlert) {
            // Re-entered from a SINK_FAILURE raised while delivering an alert.
            // Drop the nested delivery rather than recurse; the failure that
            // triggered it was already logged and counted.
            return 0;
        }

        $this->dispatchingAlert = true;

        try {
            return $this->fanOut(
                static fn (AuditSinkInterface $sink): null => $sink->publishAlert($alert),
                'alert',
                ['reason' => $alert->reason->value],
            );
        } finally {
            $this->dispatchingAlert = false;
        }
    }

    public function hasExternalAuditSink(): bool
    {
        return $this->enabledSinks()->valid();
    }

    public function getEnabledSinkIdentifiers(): array
    {
        $identifiers = [];
        foreach ($this->enabledSinks() as $sink) {
            $identifier = $this->getIdentifierSafely($sink);
            if ($identifier !== null) {
                $identifiers[] = $identifier;
            }
        }

        return $identifiers;
    }

    public function getFailureCount(): int
    {
        return $this->failureCount;
    }

    public function getFailureCountsBySink(): array
    {
        return $this->failuresBySink;
    }

    /**
     * Run $publish against every enabled sink, containing failures per sink.
     *
     * @param callable(AuditSinkInterface): void $publish
     * @param array<string, bool|int|string> $logContext Non-sensitive record facts
     *
     * @return int Number of sinks that physically accepted the record
     */
    private function fanOut(
        callable $publish,
        string $recordKind,
        array $logContext,
    ): int {
        $accepted = 0;
        foreach ($this->enabledSinks() as $sink) {
            // Resolve once, outside delivery handling. Metadata failure must
            // neither prevent publication nor turn acceptance into a failure.
            $identifier = $this->getIdentifierSafely($sink);

            try {
                $publish($sink);
                ++$accepted;
                if ($identifier !== null) {
                    $this->deliveryState?->recordSuccess($identifier);
                }
            } catch (Throwable $e) {
                $this->recordFailure($identifier, $recordKind, $e, $logContext);
            }
        }

        return $accepted;
    }

    /**
     * A throwing enablement probe is treated as disabled.
     */
    private function isEnabledSafely(AuditSinkInterface $sink): bool
    {
        try {
            return $sink->isEnabled();
        } catch (Throwable $e) {
            $this->recordFailure(
                $this->getIdentifierSafely($sink),
                'enablement-probe',
                $e,
                [],
            );

            return false;
        }
    }

    /**
     * Count every external evidence failure; attribute only known identifiers.
     *
     * @param array<string, bool|int|string> $logContext
     */
    private function recordFailure(
        ?string $sinkIdentifier,
        string $recordKind,
        Throwable $e,
        array $logContext,
    ): void {
        ++$this->failureCount;
        if ($sinkIdentifier !== null) {
            $this->failuresBySink[$sinkIdentifier] = ($this->failuresBySink[$sinkIdentifier] ?? 0) + 1;
            $this->deliveryState?->recordFailure(
                $sinkIdentifier,
                $e->getMessage(),
            );
            $context = [
                'sink' => $sinkIdentifier,
                'record' => $recordKind,
                'error' => $e->getMessage(),
                'exception' => $e::class,
            ] + $logContext;
        } else {
            // No invented health destination and no raw discovery diagnostics:
            // an iterator or identity exception can carry configuration data.
            $context = ['record' => $recordKind, 'exception' => $e::class] + $logContext;
        }

        $this->logErrorSafely(
            'nr-vault audit sink delivery failed; the database chain entry is unaffected.',
            $context,
        );
        if ($this->dispatchingAlert) {
            return;
        }

        $this->raiseSinkFailureAlert($sinkIdentifier, $recordKind, $logContext);
    }

    /**
     * @param array<string, bool|int|string> $logContext
     */
    private function raiseSinkFailureAlert(
        ?string $sinkIdentifier,
        string $recordKind,
        array $logContext,
    ): void {
        $detail = $sinkIdentifier !== null ? \sprintf(
            'External audit sink "%s" failed to accept a %s record.',
            $sinkIdentifier,
            $recordKind,
        ) : \sprintf(
            'External audit evidence failed during a %s operation.',
            $recordKind,
        );
        $context = ['record' => $recordKind] + $logContext;
        if ($sinkIdentifier !== null) {
            $context = ['sink' => $sinkIdentifier] + $context;
        }

        $alert = AuditIntegrityAlert::create(
            AuditIntegrityReason::SinkFailure,
            $detail,
            $context,
        );

        try {
            $this->eventDispatcher->dispatch(
                new AuditIntegrityAlertEvent($alert),
            );
        } catch (Throwable $dispatchError) {
            $context = $sinkIdentifier !== null ? ['sink' => $sinkIdentifier, 'error' => $dispatchError->getMessage()] : ['record' => $recordKind, 'exception' => $dispatchError::class];
            $this->logErrorSafely(
                'nr-vault could not dispatch the audit sink failure alert.',
                $context,
            );
        }
    }

    /**
     * @param array<string, bool|int|string> $context
     */
    private function logErrorSafely(string $message, array $context): void
    {
        try {
            $this->logger->error($message, $context);
        } catch (Throwable) {
            // Diagnostics must not blind the remaining audit destinations.
        }
    }

    /**
     * Preserve the visited prefix when enumeration fails; the unseen suffix cannot be recovered.
     *
     * @return Generator<int, AuditSinkInterface, void, void>
     */
    private function enabledSinks(): Generator
    {
        try {
            foreach ($this->sinks as $sink) {
                if ($this->isEnabledSafely($sink)) {
                    yield $sink;
                }
            }
        } catch (Throwable $e) {
            $this->recordFailure(null, 'sink-iterator', $e, []);
        }
    }

    /**
     * An unavailable identity is not a fabricated persisted destination.
     */
    private function getIdentifierSafely(AuditSinkInterface $sink): ?string
    {
        try {
            return $sink->getIdentifier();
        } catch (Throwable $e) {
            $this->recordFailure(null, 'identifier-probe', $e, []);

            return null;
        }
    }
}
