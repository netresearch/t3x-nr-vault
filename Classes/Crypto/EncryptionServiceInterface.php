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
     * Encrypt a secret value with a unique DEK.
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
     * @param string $encryptedValue Base64-encoded ciphertext
     * @param string $encryptedDek Base64-encoded encrypted DEK
     * @param string $dekNonce Base64-encoded DEK nonce
     * @param string $valueNonce Base64-encoded value nonce
     * @param string $identifier Secret identifier (used as AAD)
     *
     * @throws EncryptionException If decryption fails
     *
     * @return string The decrypted plaintext
     */
    public function decrypt(
        #[SensitiveParameter] string $encryptedValue,
        #[SensitiveParameter] string $encryptedDek,
        string $dekNonce,
        string $valueNonce,
        string $identifier,
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
     * @param string $encryptedDek Current encrypted DEK
     * @param string $dekNonce Current DEK nonce
     * @param string $identifier Secret identifier
     * @param string $oldMasterKey Previous master key
     * @param string $newMasterKey New master key
     */
    public function reEncryptDek(
        #[SensitiveParameter] string $encryptedDek,
        string $dekNonce,
        string $identifier,
        #[SensitiveParameter] string $oldMasterKey,
        #[SensitiveParameter] string $newMasterKey,
    ): ReEncryptedDek;
}
