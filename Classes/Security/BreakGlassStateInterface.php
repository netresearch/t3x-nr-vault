<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

/**
 * Read-only view of the break-glass window.
 *
 * Deliberately narrower than {@see BreakGlassServiceInterface}: the access
 * control layer must be able to ASK whether a window is open without being
 * able to open one, and — the reason this seam exists at all — without pulling
 * the audit log into its own dependency graph.
 * {@see \Netresearch\NrVault\Audit\AuditLogService} already depends on
 * {@see AccessControlServiceInterface}, so an AccessControlService that
 * depended on the full break-glass service (which writes audit rows) would
 * close a DI cycle.
 */
interface BreakGlassStateInterface
{
    /**
     * The currently OPEN window, or null when none is open.
     *
     * Returns null for an expired window: expiry is evaluated at read time,
     * so a session can never outlive its TTL through a missed cleanup run.
     */
    public function getActiveSession(): ?BreakGlassSession;

    /**
     * Is a non-expired break-glass window open?
     */
    public function isActive(): bool;
}
