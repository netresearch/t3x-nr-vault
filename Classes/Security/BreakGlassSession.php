<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use DateTimeImmutable;

/**
 * An active (or expired) break-glass window.
 *
 * The record of a deliberate, time-boxed restoration of the admin bypass that
 * {@see \Netresearch\NrVault\Configuration\ExtensionConfigurationInterface::isAdminOverrideDisabled()}
 * removed. It is evidence first and mechanism second: who opened the window,
 * the justification they typed, when it opened and when it closes.
 *
 * Persisted as scalars in TYPO3's `sys_registry` (see {@see BreakGlassState}),
 * never as a serialized object graph — the stored shape must stay readable by
 * an auditor with SQL access and survive a class rename.
 */
final readonly class BreakGlassSession
{
    public function __construct(
        public int $activatedByUid,
        public string $activatedByUsername,
        public string $reason,
        public DateTimeImmutable $activatedAt,
        public DateTimeImmutable $expiresAt,
    ) {}

    /**
     * Rehydrate from the registry payload, or null when the payload is not a
     * complete session.
     *
     * Fail-closed on anything unexpected: a half-written or hand-edited
     * registry row must read as "no break-glass session", never as an
     * open-ended one.
     *
     * @param array<array-key, mixed> $payload
     */
    public static function fromArray(array $payload): ?self
    {
        $uid = $payload['activatedByUid'] ?? null;
        $username = $payload['activatedByUsername'] ?? null;
        $reason = $payload['reason'] ?? null;
        $activatedAt = $payload['activatedAt'] ?? null;
        $expiresAt = $payload['expiresAt'] ?? null;

        if (!is_numeric($uid) || !\is_string($username) || !\is_string($reason)) {
            return null;
        }

        if (!is_numeric($activatedAt) || !is_numeric($expiresAt)) {
            return null;
        }

        return new self(
            activatedByUid: (int) $uid,
            activatedByUsername: $username,
            reason: $reason,
            activatedAt: (new DateTimeImmutable())->setTimestamp((int) $activatedAt),
            expiresAt: (new DateTimeImmutable())->setTimestamp((int) $expiresAt),
        );
    }

    /**
     * The registry payload — scalars only.
     *
     * @return array{activatedByUid: int, activatedByUsername: string, reason: string, activatedAt: int, expiresAt: int}
     */
    public function toArray(): array
    {
        return [
            'activatedByUid' => $this->activatedByUid,
            'activatedByUsername' => $this->activatedByUsername,
            'reason' => $this->reason,
            'activatedAt' => $this->activatedAt->getTimestamp(),
            'expiresAt' => $this->expiresAt->getTimestamp(),
        ];
    }

    /**
     * Has the window closed as of $now?
     *
     * Expiry is a read-time comparison — no cron, no scheduled task, and no
     * way for a stalled cleanup job to silently extend an operator's bypass.
     */
    public function isExpiredAt(DateTimeImmutable $now): bool
    {
        return $this->expiresAt->getTimestamp() <= $now->getTimestamp();
    }

    /**
     * Seconds left in the window (0 once expired).
     */
    public function remainingSeconds(DateTimeImmutable $now): int
    {
        return max(0, $this->expiresAt->getTimestamp() - $now->getTimestamp());
    }
}
