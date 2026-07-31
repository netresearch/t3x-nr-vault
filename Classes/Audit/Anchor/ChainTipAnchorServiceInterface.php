<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Anchor;

use Netresearch\NrVault\Audit\AuditIntegrityReport;

/**
 * Publishes and verifies external chain-tip anchors.
 *
 * Answers the one question the in-database hash chain structurally cannot: is
 * this still the same chain? See {@see ChainTipAnchor} for why that gap exists.
 */
interface ChainTipAnchorServiceInterface
{
    /**
     * Snapshot the current chain tip without publishing it.
     *
     * Read-only, so it is safe to call from a status/health surface.
     */
    public function capture(): ChainTipAnchor;

    /**
     * Publish an anchor to every enabled external sink.
     *
     * @return int Number of sinks that accepted it. **Zero means the anchor was
     *             not persisted anywhere outside the database and provides no
     *             reset protection** — callers must treat zero as a failed
     *             anchoring run, not as a no-op
     */
    public function publish(ChainTipAnchor $anchor): int;

    /**
     * Verify the chain against itself AND against the latest external anchor.
     *
     * Combines the full-range hash-chain pass with the anchor comparison and the
     * hardened-profile external-sink requirement, classifying every finding into
     * a machine-readable {@see \Netresearch\NrVault\Audit\AuditIntegrityReason}.
     * Findings are dispatched as
     * {@see \Netresearch\NrVault\Event\AuditIntegrityAlertEvent} so SIEM
     * listeners are notified even when nobody reads the command output.
     */
    public function verify(): AuditIntegrityReport;
}
