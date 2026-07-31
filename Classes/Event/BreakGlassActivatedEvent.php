<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Event;

use DateTimeImmutable;

/**
 * Event dispatched when a break-glass window is opened.
 *
 * Dispatched AFTER the window is persisted and its audit row written, so a
 * listener never announces a window that failed to open. This is the hook for
 * out-of-band alerting — paging the security channel, opening an incident
 * ticket, mailing the compliance mailbox: the vault's own audit log proves what
 * happened, but a listener is what makes someone LOOK.
 */
final readonly class BreakGlassActivatedEvent
{
    public function __construct(
        private int $actorUid,
        private string $actorUsername,
        private string $reason,
        private DateTimeImmutable $expiresAt,
    ) {}

    public function getActorUid(): int
    {
        return $this->actorUid;
    }

    public function getActorUsername(): string
    {
        return $this->actorUsername;
    }

    /**
     * The operator's mandatory justification.
     */
    public function getReason(): string
    {
        return $this->reason;
    }

    /**
     * When the window closes on its own, with no further action.
     */
    public function getExpiresAt(): DateTimeImmutable
    {
        return $this->expiresAt;
    }
}
