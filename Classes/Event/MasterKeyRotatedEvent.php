<?php

declare(strict_types=1);

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

namespace Netresearch\NrVault\Event;

use DateTimeImmutable;

/**
 * Event dispatched after master key rotation completes.
 *
 * Dispatched by `vault:rotate-master-key` AFTER the rotation transaction
 * commits, so a listener never sees a rotation that was rolled back.
 */
final readonly class MasterKeyRotatedEvent
{
    public function __construct(
        private int $secretsReEncrypted,
        private int $actorUid,
        private DateTimeImmutable $rotatedAt,
        /**
         * Envelopes re-wrapped on behalf of consuming extensions via a
         * {@see \Netresearch\NrVault\Crypto\ForeignEnvelopeRotatorInterface}
         * (ADR-033). Defaults to 0 so existing constructor calls keep working.
         */
        private int $foreignEnvelopesReEncrypted = 0,
    ) {}

    public function getSecretsReEncrypted(): int
    {
        return $this->secretsReEncrypted;
    }

    public function getActorUid(): int
    {
        return $this->actorUid;
    }

    public function getRotatedAt(): DateTimeImmutable
    {
        return $this->rotatedAt;
    }

    public function getForeignEnvelopesReEncrypted(): int
    {
        return $this->foreignEnvelopesReEncrypted;
    }
}
