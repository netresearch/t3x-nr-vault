<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

/**
 * Outcome of the audit chain tip-anchor check.
 *
 * Reported alongside the hash-chain walk in {@see HashChainVerificationResult}.
 * Only `Violated` and `Unreadable` are errors; everything else is either
 * informational or a warning, so pre-anchor installations keep verifying as
 * valid.
 */
enum AuditChainAnchorStatus: string
{
    /**
     * Not evaluated — bounded sub-range verification, which may legitimately exclude the tip.
     */
    case NotChecked = 'notChecked';

    /**
     * Audit HMAC epoch 0: keyless chain, no tamper evidence to anchor.
     */
    case Disabled = 'disabled';

    /**
     * No anchor recorded yet (pre-anchor install, wiped `sys_registry`, or a deleted anchor row).
     */
    case Unanchored = 'unanchored';

    /**
     * An anchor row exists but its format or MAC does not verify.
     */
    case Unreadable = 'unreadable';

    /**
     * A re-seal committed while the check was reading; the mismatch is not conclusive.
     */
    case InFlight = 'inFlight';

    /**
     * The anchored row exists and still carries the anchored hash.
     */
    case Ok = 'ok';

    /**
     * The anchored row is gone, or now carries a different hash.
     */
    case Violated = 'violated';
}
