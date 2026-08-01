<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Sink;

/**
 * Persisted delivery health of one external audit sink.
 *
 * A per-process failure counter answers "did anything fail since this PHP
 * process started" — which for a freshly started `vault:doctor` is always
 * "no". This state is persisted (sys_registry) so the readiness surface can
 * answer the question that matters for external evidence: WHEN did this sink
 * last demonstrably accept a record, and has it been failing since.
 */
final readonly class SinkDeliveryState
{
    public function __construct(
        public string $sinkIdentifier,
        /** Unix timestamp of the last accepted record, 0 = never observed. */
        public int $lastSuccessAt = 0,
        /** Unix timestamp of the last failed delivery, 0 = none recorded. */
        public int $lastFailureAt = 0,
        /** Failures since the last success (0 while the sink is healthy). */
        public int $consecutiveFailures = 0,
        /** Failures over the whole recorded lifetime. */
        public int $totalFailures = 0,
        /** Last failure's exception message (truncated, never secret material). */
        public string $lastError = '',
    ) {}

    public function hasEverSucceeded(): bool
    {
        return $this->lastSuccessAt > 0;
    }

    public function isFailing(): bool
    {
        return $this->consecutiveFailures > 0;
    }

    /**
     * @return array{sinkIdentifier: string, lastSuccessAt: int, lastFailureAt: int, consecutiveFailures: int, totalFailures: int, lastError: string}
     */
    public function toArray(): array
    {
        return [
            'sinkIdentifier' => $this->sinkIdentifier,
            'lastSuccessAt' => $this->lastSuccessAt,
            'lastFailureAt' => $this->lastFailureAt,
            'consecutiveFailures' => $this->consecutiveFailures,
            'totalFailures' => $this->totalFailures,
            'lastError' => $this->lastError,
        ];
    }

    /**
     * @param array<string, mixed> $row
     */
    public static function fromArray(string $sinkIdentifier, array $row): self
    {
        return new self(
            sinkIdentifier: $sinkIdentifier,
            lastSuccessAt: is_numeric($row['lastSuccessAt'] ?? null) ? (int) $row['lastSuccessAt'] : 0,
            lastFailureAt: is_numeric($row['lastFailureAt'] ?? null) ? (int) $row['lastFailureAt'] : 0,
            consecutiveFailures: is_numeric($row['consecutiveFailures'] ?? null) ? (int) $row['consecutiveFailures'] : 0,
            totalFailures: is_numeric($row['totalFailures'] ?? null) ? (int) $row['totalFailures'] : 0,
            lastError: \is_string($row['lastError'] ?? null) ? $row['lastError'] : '',
        );
    }
}
