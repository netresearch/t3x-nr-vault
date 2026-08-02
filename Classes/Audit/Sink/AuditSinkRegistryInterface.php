<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Sink;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditLogEntry;

/**
 * Fans audit evidence out to every enabled external sink.
 *
 * The single guarantee every method makes: **it never throws**. Callers are the
 * audit write path and the verification command; neither may be taken down by a
 * full disk or an unreachable collector. Failures are logged, counted
 * ({@see getFailureCount()}) and raised as `SINK_FAILURE` integrity alerts, so
 * "never throws" does not mean "fails silently".
 */
interface AuditSinkRegistryInterface
{
    /**
     * Publish a committed audit entry to every enabled sink.
     *
     * @return int Number of sinks that accepted the entry
     */
    public function dispatch(AuditLogEntry $entry, string $chainTip): int;

    /**
     * Publish a chain-tip anchor to every enabled sink.
     *
     * @return int Number of sinks that accepted the anchor. Zero means the
     *             anchor exists nowhere outside the database and provides no
     *             reset protection — callers should treat that as a failure of
     *             the anchoring operation
     */
    public function dispatchAnchor(ChainTipAnchor $anchor): int;

    /**
     * Publish an integrity alert to every enabled sink.
     *
     * @return int Number of sinks that accepted the alert
     */
    public function dispatchAlert(AuditIntegrityAlert $alert): int;

    /**
     * Whether at least one external sink is enabled and usable.
     *
     * The hardened security profile treats a false here as a finding: a vault
     * whose only audit copy lives in the database it is meant to protect has no
     * external tamper evidence at all.
     */
    public function hasExternalAuditSink(): bool;

    /**
     * Identifiers of the currently enabled sinks, for status output.
     *
     * @return list<string>
     */
    public function getEnabledSinkIdentifiers(): array;

    /**
     * Number of sink delivery failures observed in this process.
     *
     * Read by the health/status surface. Per-process rather than persisted: a
     * sink failure is an availability signal for the current runtime, and
     * persisting it would mean writing to the very storage a sink failure may
     * indicate is broken.
     */
    public function getFailureCount(): int;

    /**
     * Per-sink failure counts, keyed by sink identifier.
     *
     * @return array<string, int>
     */
    public function getFailureCountsBySink(): array;
}
