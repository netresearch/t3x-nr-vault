<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Sink;

use Psr\Log\LoggerInterface;
use Throwable;
use TYPO3\CMS\Core\Registry;

/**
 * sys_registry-backed {@see SinkDeliveryStateRepositoryInterface}.
 *
 * sys_registry rather than a bespoke table: the state is a handful of scalars
 * per sink, survives process restarts and deployments, and needs no schema of
 * its own. It deliberately lives in the SAME database as the audit chain — it
 * is operational health telemetry, not tamper-evident evidence; the evidence
 * is what the sinks carry OUT of the database.
 *
 * Success writes are throttled (one registry UPDATE per sink per
 * SUCCESS_WRITE_INTERVAL seconds) so an audit-heavy installation does not pay
 * a bookkeeping write per audit entry; a success after observed failures is
 * always persisted immediately so a recovery is visible. Failure writes are
 * never throttled.
 */
final class SinkDeliveryStateRepository implements SinkDeliveryStateRepositoryInterface
{
    private const REGISTRY_NAMESPACE = 'tx_nrvault';

    private const REGISTRY_KEY_PREFIX = 'sink_delivery_';

    private const SUCCESS_WRITE_INTERVAL = 60;

    private const ERROR_MESSAGE_MAX_LENGTH = 500;

    /** @var array<string, int> In-process timestamp of the last persisted success per sink. */
    private array $lastPersistedSuccess = [];

    public function __construct(
        private readonly Registry $registry,
        private readonly LoggerInterface $logger,
    ) {}

    public function recordSuccess(string $sinkIdentifier): void
    {
        $now = time();
        $lastPersisted = $this->lastPersistedSuccess[$sinkIdentifier] ?? 0;

        try {
            $state = $this->getState($sinkIdentifier);

            // Throttle: skip the write while healthy and recently persisted.
            if (!$state->isFailing() && ($now - $lastPersisted) < self::SUCCESS_WRITE_INTERVAL && $state->hasEverSucceeded()) {
                return;
            }

            $this->persist(new SinkDeliveryState(
                sinkIdentifier: $sinkIdentifier,
                lastSuccessAt: $now,
                lastFailureAt: $state->lastFailureAt,
                consecutiveFailures: 0,
                totalFailures: $state->totalFailures,
                lastError: '',
            ));
            $this->lastPersistedSuccess[$sinkIdentifier] = $now;
        } catch (Throwable $e) {
            $this->logFailedBookkeeping($sinkIdentifier, $e);
        }
    }

    public function recordFailure(string $sinkIdentifier, string $errorMessage): void
    {
        try {
            $state = $this->getState($sinkIdentifier);

            $this->persist(new SinkDeliveryState(
                sinkIdentifier: $sinkIdentifier,
                lastSuccessAt: $state->lastSuccessAt,
                lastFailureAt: time(),
                consecutiveFailures: $state->consecutiveFailures + 1,
                totalFailures: $state->totalFailures + 1,
                lastError: mb_substr($errorMessage, 0, self::ERROR_MESSAGE_MAX_LENGTH),
            ));
        } catch (Throwable $e) {
            $this->logFailedBookkeeping($sinkIdentifier, $e);
        }
    }

    public function getState(string $sinkIdentifier): SinkDeliveryState
    {
        try {
            $row = $this->registry->get(
                self::REGISTRY_NAMESPACE,
                self::REGISTRY_KEY_PREFIX . $sinkIdentifier,
            );
        } catch (Throwable $e) {
            $this->logFailedBookkeeping($sinkIdentifier, $e);
            $row = null;
        }

        if (!\is_array($row)) {
            return new SinkDeliveryState(sinkIdentifier: $sinkIdentifier);
        }

        // Keep only string keys: sys_registry stores what persist() wrote,
        // but the value is unserialized data and typed defensively.
        $stringKeyed = array_filter($row, is_string(...), ARRAY_FILTER_USE_KEY);

        return SinkDeliveryState::fromArray($sinkIdentifier, $stringKeyed);
    }

    private function persist(SinkDeliveryState $state): void
    {
        $this->registry->set(
            self::REGISTRY_NAMESPACE,
            self::REGISTRY_KEY_PREFIX . $state->sinkIdentifier,
            $state->toArray(),
        );
    }

    private function logFailedBookkeeping(string $sinkIdentifier, Throwable $e): void
    {
        // Fail-safe: bookkeeping must never fail the audited operation.
        $this->logger->warning(
            'nr-vault could not read/write the persisted sink delivery state.',
            ['sink' => $sinkIdentifier, 'error' => $e->getMessage()],
        );
    }
}
