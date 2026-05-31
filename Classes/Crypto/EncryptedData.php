<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

/**
 * Value object representing encrypted data from envelope encryption.
 *
 * Contains the encrypted value, encrypted DEK, nonces, and checksum.
 * The value/DEK/nonce fields are base64-encoded for safe storage/transport;
 * the checksum is a hex-encoded keyed HMAC-SHA-256 over the ciphertext.
 */
final readonly class EncryptedData
{
    public function __construct(
        /** Base64-encoded ciphertext */
        public string $encryptedValue,
        /** Base64-encoded encrypted Data Encryption Key */
        public string $encryptedDek,
        /** Base64-encoded nonce used for DEK encryption */
        public string $dekNonce,
        /** Base64-encoded nonce used for value encryption */
        public string $valueNonce,
        /** Hex-encoded keyed HMAC-SHA-256 over the ciphertext (per-secret MAC key derived from the DEK) for change detection */
        public string $valueChecksum,
    ) {}

    /**
     * Create from raw encryption output.
     *
     * @param string $encryptedValue Raw ciphertext bytes
     * @param string $encryptedDek Raw encrypted DEK bytes
     * @param string $dekNonce Raw DEK nonce bytes
     * @param string $valueNonce Raw value nonce bytes
     * @param string $valueChecksum Hex-encoded keyed HMAC-SHA-256 over the ciphertext
     */
    public static function fromRaw(
        string $encryptedValue,
        string $encryptedDek,
        string $dekNonce,
        string $valueNonce,
        string $valueChecksum,
    ): self {
        return new self(
            encryptedValue: base64_encode($encryptedValue),
            encryptedDek: base64_encode($encryptedDek),
            dekNonce: base64_encode($dekNonce),
            valueNonce: base64_encode($valueNonce),
            valueChecksum: $valueChecksum,
        );
    }

    /**
     * Convert to array for database storage.
     *
     * @return array{
     *     encrypted_value: string,
     *     encrypted_dek: string,
     *     dek_nonce: string,
     *     value_nonce: string,
     *     value_checksum: string,
     * }
     */
    public function toArray(): array
    {
        return [
            'encrypted_value' => $this->encryptedValue,
            'encrypted_dek' => $this->encryptedDek,
            'dek_nonce' => $this->dekNonce,
            'value_nonce' => $this->valueNonce,
            'value_checksum' => $this->valueChecksum,
        ];
    }
}
