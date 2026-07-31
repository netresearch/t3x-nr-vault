<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Sink;

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
        foreach ($this->sinks as $sink) {
            if ($this->isEnabledSafely($sink)) {
                return true;
            }
        }

        return false;
    }

    public function getEnabledSinkIdentifiers(): array
    {
        $identifiers = [];
        foreach ($this->sinks as $sink) {
            if ($this->isEnabledSafely($sink)) {
                $identifiers[] = $sink->getIdentifier();
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
     * Run `$publish` against every enabled sink, containing failures per sink.
     *
     * @param callable(AuditSinkInterface): void $publish
     * @param array<string, bool|int|string> $logContext Record-identifying facts
     *                                                   for the failure log and the SINK_FAILURE alert.
     *                                                   Never carries secret material — the audit entry's
     *                                                   uid and action, not its payload
     *
     * @return int Number of sinks that accepted the record
     */
    private function fanOut(callable $publish, string $recordKind, array $logContext): int
    {
        $accepted = 0;

        foreach ($this->sinks as $sink) {
            if (!$this->isEnabledSafely($sink)) {
                continue;
            }

            try {
                $publish($sink);
                ++$accepted;
            } catch (Throwable $e) {
                $this->recordFailure($sink->getIdentifier(), $recordKind, $e, $logContext);
            }
        }

        return $accepted;
    }

    /**
     * A sink whose own `isEnabled()` throws is treated as disabled.
     *
     * Without this, a misconfigured sink could throw during the enablement probe
     * — outside the per-call try/catch — and take the audited operation down,
     * which is exactly the outcome this registry exists to prevent.
     */
    private function isEnabledSafely(AuditSinkInterface $sink): bool
    {
        try {
            return $sink->isEnabled();
        } catch (Throwable $e) {
            $this->recordFailure($sink->getIdentifier(), 'enablement-probe', $e, []);

            return false;
        }
    }

    /**
     * Log, count, and (unless already delivering an alert) raise a
     * `SINK_FAILURE` integrity alert.
     *
     * @param array<string, bool|int|string> $logContext
     */
    private function recordFailure(string $sinkIdentifier, string $recordKind, Throwable $e, array $logContext): void
    {
        ++$this->failureCount;
        $this->failuresBySink[$sinkIdentifier] = ($this->failuresBySink[$sinkIdentifier] ?? 0) + 1;

        $this->logger->error(
            'nr-vault audit sink delivery failed; the database chain entry is unaffected.',
            [
                'sink' => $sinkIdentifier,
                'record' => $recordKind,
                'error' => $e->getMessage(),
                'exception' => $e::class,
            ] + $logContext,
        );

        if ($this->dispatchingAlert) {
            return;
        }

        $this->raiseSinkFailureAlert($sinkIdentifier, $recordKind, $logContext);
    }

    /**
     * @param array<string, bool|int|string> $logContext
     */
    private function raiseSinkFailureAlert(string $sinkIdentifier, string $recordKind, array $logContext): void
    {
        $alert = AuditIntegrityAlert::create(
            AuditIntegrityReason::SinkFailure,
            \sprintf('External audit sink "%s" failed to accept a %s record.', $sinkIdentifier, $recordKind),
            ['sink' => $sinkIdentifier, 'record' => $recordKind] + $logContext,
        );

        try {
            $this->eventDispatcher->dispatch(new AuditIntegrityAlertEvent($alert));
        } catch (Throwable $dispatchError) {
            // A throwing listener must not escalate into the audited operation.
            $this->logger->error(
                'nr-vault could not dispatch the audit sink failure alert.',
                ['sink' => $sinkIdentifier, 'error' => $dispatchError->getMessage()],
            );
        }
    }
}
