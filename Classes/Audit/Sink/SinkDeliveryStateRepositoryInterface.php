<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Sink;

/**
 * Persistence for {@see SinkDeliveryState}.
 *
 * Implementations MUST be fail-safe on write: delivery bookkeeping must never
 * fail (or slow down) the audited operation it accompanies. A write error is
 * logged and swallowed.
 */
interface SinkDeliveryStateRepositoryInterface
{
    /**
     * Record an accepted delivery. Implementations may throttle the write
     * (an audit-heavy install would otherwise pay one registry UPDATE per
     * audit entry), but MUST persist immediately when the sink was failing —
     * the recovery must be visible.
     */
    public function recordSuccess(string $sinkIdentifier): void;

    /**
     * Record a failed delivery. Always persisted.
     */
    public function recordFailure(string $sinkIdentifier, string $errorMessage): void;

    public function getState(string $sinkIdentifier): SinkDeliveryState;
}
