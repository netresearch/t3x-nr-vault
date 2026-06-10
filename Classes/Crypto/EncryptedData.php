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
 * Contains the encrypted value, encrypted DEK, nonces, checksum, and the
 * encryption version/algorithm marker recorded at encrypt time.
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
        /**
         * Encryption version marker. The defaults describe what the current
         * `EncryptionService::encrypt()` produces; legacy (version-1)
         * envelopes must pass their marker explicitly.
         */
        public int $encryptionVersion = EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT,
        /** AEAD algorithm both envelope layers (DEK wrap + value) were encrypted with */
        public EncryptionAlgorithm $encryptionAlgorithm = EncryptionAlgorithm::XChaCha20Poly1305,
    ) {}

    /**
     * Create from raw encryption output.
     *
     * @param string $encryptedValue Raw ciphertext bytes
     * @param string $encryptedDek Raw encrypted DEK bytes
     * @param string $dekNonce Raw DEK nonce bytes
     * @param string $valueNonce Raw value nonce bytes
     * @param string $valueChecksum Hex-encoded keyed HMAC-SHA-256 over the ciphertext
     * @param int $encryptionVersion Encryption version marker
     * @param EncryptionAlgorithm $encryptionAlgorithm AEAD algorithm used for both envelope layers
     */
    public static function fromRaw(
        string $encryptedValue,
        string $encryptedDek,
        string $dekNonce,
        string $valueNonce,
        string $valueChecksum,
        int $encryptionVersion = EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT,
        EncryptionAlgorithm $encryptionAlgorithm = EncryptionAlgorithm::XChaCha20Poly1305,
    ): self {
        return new self(
            encryptedValue: base64_encode($encryptedValue),
            encryptedDek: base64_encode($encryptedDek),
            dekNonce: base64_encode($dekNonce),
            valueNonce: base64_encode($valueNonce),
            valueChecksum: $valueChecksum,
            encryptionVersion: $encryptionVersion,
            encryptionAlgorithm: $encryptionAlgorithm,
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
     *     encryption_version: int,
     *     encryption_algorithm: string,
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
            'encryption_version' => $this->encryptionVersion,
            'encryption_algorithm' => $this->encryptionAlgorithm->value,
        ];
    }
}
