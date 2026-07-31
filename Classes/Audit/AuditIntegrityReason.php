<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

/**
 * Machine-readable reason codes for audit-integrity findings.
 *
 * These are the codes a SIEM / notification listener switches on, and the codes
 * `vault:audit-verify` prints and exits on. The backing strings are part of the
 * external contract (they appear in webhook payloads, syslog structured data and
 * the NDJSON anchor stream) — treat them as stable API, not as labels.
 */
enum AuditIntegrityReason: string
{
    /**
     * A stored `entry_hash` or `previous_hash` does not match the recomputed value.
     */
    case HashMismatch = 'HASH_MISMATCH';

    /**
     * The uid sequence is not contiguous — rows were deleted from the chain.
     */
    case UidGap = 'UID_GAP';

    /**
     * The chain no longer contains the externally anchored tip: either it is
     * shorter than the anchored sequence, or the row at that sequence hashes
     * differently. The signature of a truncate-and-rebuild.
     */
    case TableReset = 'TABLE_RESET';

    /**
     * The chain's `hmac_key_epoch` was relabelled downward — an attempt to move
     * rows onto a weaker (or keyless) verification algorithm.
     */
    case EpochDowngrade = 'EPOCH_DOWNGRADE';

    /**
     * An external sink could not be delivered to. Availability, not integrity.
     */
    case SinkFailure = 'SINK_FAILURE';

    /**
     * No external audit sink is enabled, so the audit trail exists only in the
     * database it is meant to protect and no anchor can be published. A finding
     * only under the hardened security profile; the standard profile treats
     * external sinks as opt-in.
     */
    case NoExternalSink = 'NO_EXTERNAL_SINK';

    /**
     * Reserved for the break-glass emergency-access flow, which raises an alert
     * of its own severity class. Declared here so listeners can be written
     * against the complete code set before that flow lands.
     */
    case BreakGlass = 'BREAK_GLASS';

    /**
     * Whether the code indicates evidence of tampering (as opposed to a
     * delivery/availability problem).
     *
     * Listeners use this to decide between "page someone now" and "log it".
     */
    public function isTamperEvidence(): bool
    {
        return match ($this) {
            self::HashMismatch, self::UidGap, self::TableReset, self::EpochDowngrade => true,
            self::SinkFailure, self::NoExternalSink, self::BreakGlass => false,
        };
    }

    /**
     * Human-readable label for CLI output and backend display.
     */
    public function label(): string
    {
        return ucwords(strtolower(str_replace('_', ' ', $this->value)));
    }
}
