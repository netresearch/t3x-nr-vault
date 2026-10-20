<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Event;

/**
 * Event dispatched when a secret value is updated (not rotated).
 */
final readonly class SecretUpdatedEvent
{
    public function __construct(
        private string $identifier,
        private int $newVersion,
        private int $actorUid,
    ) {}

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getNewVersion(): int
    {
        return $this->newVersion;
    }

    public function getActorUid(): int
    {
        return $this->actorUid;
    }
}
