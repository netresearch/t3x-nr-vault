<?php

declare(strict_types=1);

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

namespace Netresearch\NrVault\Event;

use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;

/**
 * Dispatched whenever an audit-integrity finding is raised.
 *
 * The subscription point for SIEM forwarding, paging, and e-mail notification.
 * Reason codes are {@see AuditIntegrityReason}: `HASH_MISMATCH`, `UID_GAP`,
 * `TABLE_RESET`, `EPOCH_DOWNGRADE`, `SINK_FAILURE`, and the reserved
 * `BREAK_GLASS`.
 *
 * Dispatch sites:
 *  - {@see \Netresearch\NrVault\Audit\Sink\AuditSinkRegistry} — `SINK_FAILURE`,
 *    when an external sink refuses a record.
 *  - {@see \Netresearch\NrVault\Audit\Anchor\ChainTipAnchorService} — the four
 *    tamper-evidence codes, when verification fails.
 *
 * ## Listener contract
 *
 * The event is informational, not vetoable: there is nothing to cancel, the
 * finding has already happened. Listeners SHOULD be fast and MUST tolerate being
 * called from a CLI verification run as well as from a web request — the
 * `SINK_FAILURE` path fires inside the audit write path of a live vault
 * operation. A listener that throws is caught by the dispatch site and logged; it
 * never propagates into the audited operation.
 *
 * The built-in {@see \Netresearch\NrVault\EventListener\AuditIntegrityAlertSinkListener}
 * forwards every alert to the enabled external sinks.
 */
final readonly class AuditIntegrityAlertEvent
{
    public function __construct(
        private AuditIntegrityAlert $alert,
    ) {}

    public function getAlert(): AuditIntegrityAlert
    {
        return $this->alert;
    }

    public function getReason(): AuditIntegrityReason
    {
        return $this->alert->reason;
    }

    /**
     * Whether the finding is evidence of tampering rather than a delivery
     * problem — the usual discriminator between "page someone" and "log it".
     */
    public function isTamperEvidence(): bool
    {
        return $this->alert->reason->isTamperEvidence();
    }
}
