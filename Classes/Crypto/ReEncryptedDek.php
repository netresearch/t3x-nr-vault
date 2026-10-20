<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

/**
 * Value object representing a re-encrypted DEK after master key rotation.
 *
 * Contains the new encrypted DEK and its nonce, both base64-encoded.
 */
final readonly class ReEncryptedDek
{
    public function __construct(
        /** Base64-encoded encrypted DEK with new master key */
        public string $encryptedDek,
        /** Base64-encoded nonce for new DEK encryption */
        public string $nonce,
    ) {}

    /**
     * Create from raw encryption output.
     *
     * @param string $encryptedDek Raw encrypted DEK bytes
     * @param string $nonce        Raw nonce bytes
     */
    public static function fromRaw(string $encryptedDek, string $nonce): self
    {
        return new self(
            encryptedDek: base64_encode($encryptedDek),
            nonce: base64_encode($nonce),
        );
    }

    /**
     * Convert to array for database update.
     *
     * @return array{encrypted_dek: string, nonce: string}
     */
    public function toArray(): array
    {
        return [
            'encrypted_dek' => $this->encryptedDek,
            'nonce'         => $this->nonce,
        ];
    }
}
