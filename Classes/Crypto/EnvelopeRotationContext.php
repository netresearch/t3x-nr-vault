<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\EnvelopeFormatException;
use SensitiveParameter;

/**
 * The re-wrapping capability handed to a {@see ForeignEnvelopeRotatorInterface}
 * during a master-key rotation (ADR-033).
 *
 * A rotator needs to re-wrap envelopes with the new master key, which requires
 * both the old and the new key — but it has no business holding either. This
 * object closes over them and exposes only the operation, so a consumer moves
 * envelopes from one key to the other without ever seeing key material.
 *
 * It is valid only for the duration of the rotation call. Both keys carry
 * `#[\SensitiveParameter]`, so a stack trace unwinding through the constructor
 * shows them redacted.
 */
final readonly class EnvelopeRotationContext
{
    public function __construct(
        private EnvelopeCodecInterface $codec,
        #[SensitiveParameter]
        private string $oldMasterKey,
        #[SensitiveParameter]
        private string $newMasterKey,
    ) {}

    /**
     * Re-wrap one sealed envelope's DEK from the old master key to the new one.
     *
     * The payload ciphertext is untouched — nothing is decrypted.
     *
     * @param string $identifier The identifier the envelope was sealed with (its AAD)
     *
     * @throws EnvelopeFormatException If the value is not a well-formed envelope
     * @throws EncryptionException If the DEK cannot be unwrapped with the old key
     */
    public function rewrap(string $sealed, string $identifier): string
    {
        return $this->codec->rewrap($sealed, $identifier, $this->oldMasterKey, $this->newMasterKey);
    }

    /**
     * Whether a stored value is a sealed envelope at all — for skipping rows
     * written before the consumer started sealing.
     */
    public function isSealed(string $value): bool
    {
        return $this->codec->isSealed($value);
    }
}
