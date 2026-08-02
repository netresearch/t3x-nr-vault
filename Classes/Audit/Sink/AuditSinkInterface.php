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
 * An external destination for audit evidence.
 *
 * The database table `tx_nrvault_audit_log` is the ONE chain-authoritative sink
 * and is deliberately NOT modelled as an implementation of this interface: it is
 * written transactionally, its failure aborts the audited operation, and it owns
 * the hash chain. Everything here is a *copy* whose only job is to put evidence
 * somewhere a database-write attacker cannot reach.
 *
 * Contract:
 *
 *  - Implementations MAY throw. The caller is
 *    {@see AuditSinkRegistryInterface}, which catches per sink, logs, counts the
 *    failure, and moves on — a broken sink must never fail a vault operation.
 *    Do not swallow errors internally; a silent sink is worse than a failing one
 *    because nothing tells the operator that the evidence stopped flowing.
 *  - Implementations MUST NOT log secret material. They receive an
 *    {@see AuditLogEntry}, which carries the secret *identifier* and value
 *    checksums, never a plaintext value.
 *  - `isEnabled()` covers both "the operator turned it on" and "it is actually
 *    usable" (path safe and writable, URL configured). A sink that is configured
 *    but unusable MUST report false and explain why via the PSR-3 log, so it is
 *    never mistaken for working external evidence.
 *
 * All three publish methods live on one interface rather than being split into a
 * separate anchor/alert contract: every sink handles all three record kinds, the
 * enablement and configuration are shared, and
 * {@see AuditSinkRegistryInterface::hasExternalAuditSink()} can only be
 * meaningful — "there is a destination that can carry an anchor" — if anchor
 * support is structurally guaranteed rather than checked at runtime.
 */
interface AuditSinkInterface
{
    /**
     * Publish one committed audit entry.
     *
     * Called after the entry hash has been written and the audit lock released,
     * so `$chainTip` is the chain tip *including* `$entry` (identical to
     * `$entry->entryHash` for a live write; passed separately so a replay tool
     * can publish historical entries with the tip they belonged to).
     */
    public function publish(AuditLogEntry $entry, string $chainTip): void;

    /**
     * Publish a chain-tip anchor.
     *
     * Anchors are what make a full table reset detectable, so a sink that
     * accepts entries but silently drops anchors would give false confidence.
     */
    public function publishAnchor(ChainTipAnchor $anchor): void;

    /**
     * Publish an integrity finding (hash mismatch, uid gap, table reset, …).
     */
    public function publishAlert(AuditIntegrityAlert $alert): void;

    /**
     * Stable, log-safe identifier for this sink ('syslog', 'file', 'webhook').
     *
     * Appears in failure log messages and in the `SINK_FAILURE` alert context,
     * so it MUST NOT embed a URL, a path, or any credential.
     */
    public function getIdentifier(): string;

    /**
     * Whether this sink is enabled AND usable right now.
     */
    public function isEnabled(): bool;
}
