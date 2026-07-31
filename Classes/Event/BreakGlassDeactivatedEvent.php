<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Event;

use DateTimeImmutable;

/**
 * Event dispatched when a break-glass window is closed early.
 *
 * Only an explicit `deactivate()` dispatches this. A window that simply runs
 * out does NOT — expiry is evaluated at read time and involves no code running
 * at the moment it lapses, so there is nothing to dispatch from. Listeners that
 * need to know a window is no longer open must compare
 * {@see BreakGlassActivatedEvent::getExpiresAt()} against the clock rather than
 * wait for this event.
 */
final readonly class BreakGlassDeactivatedEvent
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
     * The mandatory justification given for closing the window.
     */
    public function getReason(): string
    {
        return $this->reason;
    }

    /**
     * When the closed window WOULD have expired on its own.
     */
    public function getExpiresAt(): DateTimeImmutable
    {
        return $this->expiresAt;
    }
}
