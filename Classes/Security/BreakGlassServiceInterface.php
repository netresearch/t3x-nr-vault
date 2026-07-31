<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\ValidationException;

/**
 * Break-glass mode: a deliberate, justified, time-boxed restoration of the
 * admin bypass that `disableAdminOverride` removed.
 *
 * Honest framing: while a window is open, an admin has exactly the power they
 * had before the override was disabled — every operation permission and the
 * per-secret tiers on every secret. Break-glass does not PREVENT anything. Its
 * value is that using that power now requires a named actor, a typed
 * justification, an audit row sealed into the hash chain, a PSR-14 event
 * observers can alert on, a banner every backend user sees, and an expiry the
 * operator cannot forget to close.
 *
 * @see BreakGlassStateInterface for the read-only seam consumed by access control
 */
interface BreakGlassServiceInterface extends BreakGlassStateInterface
{
    /** Minutes a window stays open when the caller does not choose. */
    public const DEFAULT_TTL_MINUTES = 15;

    public const MIN_TTL_MINUTES = 1;

    /**
     * Hard ceiling. A break-glass window that can outlast a working day is not
     * an emergency measure, it is the override switched back on.
     */
    public const MAX_TTL_MINUTES = 60;

    /**
     * Open a break-glass window, replacing any window already open.
     *
     * @param string $reason Mandatory justification. Recorded verbatim in the
     *                       audit row and shown in the backend banner
     * @param int $minutes Requested TTL, clamped to
     *                     {@see self::MIN_TTL_MINUTES}..{@see self::MAX_TTL_MINUTES}
     *
     * @throws ValidationException if the reason is empty after trimming
     * @throws AccessDeniedException if the actor is neither a real backend
     *                               admin / system maintainer nor a real CLI
     *                               operator
     */
    public function activate(string $reason, int $minutes = self::DEFAULT_TTL_MINUTES): BreakGlassSession;

    /**
     * Close the open window early.
     *
     * A no-op when no window is open — closing an already-closed window is the
     * desired end state, not an error worth aborting a cleanup script for. No
     * audit row and no event are produced in that case, so the log never
     * implies a window existed.
     *
     * @param string $reason Mandatory justification (same policy as activation)
     *
     * @throws ValidationException
     * @throws AccessDeniedException
     */
    public function deactivate(string $reason): void;
}
