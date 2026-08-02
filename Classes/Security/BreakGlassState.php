<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use DateTimeImmutable;
use Throwable;
use TYPO3\CMS\Core\Registry;

/**
 * Break-glass state persisted in TYPO3's `sys_registry`.
 *
 * The registry is the right store here: the window must outlive the request
 * that opened it (an operator activates on the CLI and then works in the
 * backend), must NOT expire on its own like a cache entry, and must be a
 * single global fact rather than per-session state — a break-glass window is a
 * property of the installation, not of a browser session.
 *
 * Reads are pure: an expired entry is reported as "no session" and left in
 * place (the next activation overwrites it, `deactivate()` removes it). That
 * keeps `canRead()` — a hot path reached from the frontend — free of a DB
 * write, which a lazy-purge-on-read would introduce.
 */
final readonly class BreakGlassState implements BreakGlassStateInterface
{
    /**
     * Registry namespace. Matches the extension's table prefix so an auditor
     * grepping `sys_registry` for `tx_nrvault` finds this alongside the rest.
     */
    public const REGISTRY_NAMESPACE = 'tx_nrvault';

    public const REGISTRY_KEY = 'breakGlassSession';

    public function __construct(
        private Registry $registry,
    ) {}

    public function getActiveSession(): ?BreakGlassSession
    {
        $session = $this->readSession();
        if (!$session instanceof BreakGlassSession) {
            return null;
        }

        return $session->isExpiredAt(new DateTimeImmutable()) ? null : $session;
    }

    public function isActive(): bool
    {
        return $this->getActiveSession() instanceof BreakGlassSession;
    }

    /**
     * Persist a window, replacing any previous one.
     *
     * Internal to the Security namespace — activation policy and the audit
     * trail live in {@see BreakGlassService}, which is the only intended
     * caller. Writing here directly would produce an unaudited window.
     *
     * @internal
     */
    public function store(BreakGlassSession $session): void
    {
        $this->registry->set(self::REGISTRY_NAMESPACE, self::REGISTRY_KEY, $session->toArray());
    }

    /**
     * Drop the stored window (whether or not it had already expired).
     *
     * @internal
     */
    public function clear(): void
    {
        $this->registry->remove(self::REGISTRY_NAMESPACE, self::REGISTRY_KEY);
    }

    /**
     * The stored window regardless of expiry, or null when nothing valid is
     * stored.
     *
     * A registry read hits the database. It is wrapped because this runs on
     * every access-control decision, including bootstrap-time ones (install
     * tool, upgrade wizards) and CLI contexts where `sys_registry` may not
     * exist yet: an unreadable registry must mean "no break-glass window", not
     * a fatal error in an unrelated code path. Fail-closed — an unreadable
     * store never grants the bypass.
     */
    private function readSession(): ?BreakGlassSession
    {
        try {
            $raw = $this->registry->get(self::REGISTRY_NAMESPACE, self::REGISTRY_KEY);
        } catch (Throwable) {
            return null;
        }

        return \is_array($raw) ? BreakGlassSession::fromArray($raw) : null;
    }
}
