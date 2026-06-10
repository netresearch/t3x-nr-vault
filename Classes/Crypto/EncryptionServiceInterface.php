<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Exception\EncryptionException;
use SensitiveParameter;

/**
 * Interface for encryption operations.
 */
interface EncryptionServiceInterface
{
    /**
     * Encryption version 1 (legacy): no per-secret algorithm marker is
     * stored; the algorithm is derived from host capabilities + extension
     * configuration at decrypt time. Rows created before the marker existed
     * implicitly carry this version.
     */
    public const ENCRYPTION_VERSION_LEGACY = 1;

    /**
     * Encryption version 2: the AEAD algorithm is recorded explicitly per
     * secret at encrypt time ({@see EncryptionAlgorithm}) and decryption
     * dispatches on the stored marker, never on host capabilities.
     */
    public const ENCRYPTION_VERSION_CURRENT = 2;

    /**
     * Encrypt a secret value with a unique DEK.
     *
     * Always produces {@see self::ENCRYPTION_VERSION_CURRENT} envelopes with
     * an explicit algorithm marker recorded in the returned DTO.
     *
     * @param string $plaintext The value to encrypt
     * @param string $identifier Secret identifier (used as AAD)
     *
     * @throws EncryptionException If encryption fails
     */
    public function encrypt(#[SensitiveParameter] string $plaintext, string $identifier): EncryptedData;

    /**
     * Decrypt a secret value.
     *
     * For encryption version 2+ the algorithm is taken from the stored
     * per-secret marker; for version 1 (legacy, the default) it is derived
     * from host capabilities + configuration exactly as before the marker
     * existed.
     *
     * @param string $encryptedValue Base64-encoded ciphertext
     * @param string $encryptedDek Base64-encoded encrypted DEK
     * @param string $dekNonce Base64-encoded DEK nonce
     * @param string $valueNonce Base64-encoded value nonce
     * @param string $identifier Secret identifier (used as AAD)
     * @param int $encryptionVersion Stored per-secret encryption version
     * @param string $encryptionAlgorithm Stored per-secret algorithm marker
     *                                    ({@see EncryptionAlgorithm} value);
     *                                    required for version 2+, must be ''
     *                                    for version 1
     *
     * @throws EncryptionException If decryption fails or the marker is
     *                             unknown/unavailable on this host
     *
     * @return string The decrypted plaintext
     */
    public function decrypt(
        #[SensitiveParameter]
        string $encryptedValue,
        #[SensitiveParameter]
        string $encryptedDek,
        string $dekNonce,
        string $valueNonce,
        string $identifier,
        int $encryptionVersion = self::ENCRYPTION_VERSION_LEGACY,
        string $encryptionAlgorithm = '',
    ): string;

    /**
     * Generate a new Data Encryption Key.
     *
     * @return string 32-byte random key
     */
    public function generateDek(): string;

    /**
     * Calculate value checksum for change detection.
     *
     * @param string $plaintext The secret value
     *
     * @return string SHA-256 hash (64 hex characters)
     */
    public function calculateChecksum(#[SensitiveParameter] string $plaintext): string;

    /**
     * Re-encrypt a DEK with a new master key.
     *
     * The DEK envelope is unwrapped and re-wrapped with the SAME algorithm
     * the secret was encrypted with: the stored marker for version 2+, the
     * legacy host-derived algorithm for version 1. The secret's version and
     * algorithm marker are unchanged by this operation.
     *
     * @param string $encryptedDek Current encrypted DEK
     * @param string $dekNonce Current DEK nonce
     * @param string $identifier Secret identifier
     * @param string $oldMasterKey Previous master key
     * @param string $newMasterKey New master key
     * @param int $encryptionVersion Stored per-secret encryption version
     * @param string $encryptionAlgorithm Stored per-secret algorithm marker
     *                                    (required for version 2+, '' for
     *                                    version 1)
     */
    public function reEncryptDek(
        #[SensitiveParameter]
        string $encryptedDek,
        string $dekNonce,
        string $identifier,
        #[SensitiveParameter]
        string $oldMasterKey,
        #[SensitiveParameter]
        string $newMasterKey,
        int $encryptionVersion = self::ENCRYPTION_VERSION_LEGACY,
        string $encryptionAlgorithm = '',
    ): ReEncryptedDek;
}
