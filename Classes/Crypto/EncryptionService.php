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

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\EncryptionException;
use SensitiveParameter;
use SodiumException;

/**
 * Envelope encryption service using AES-256-GCM or XChaCha20-Poly1305.
 */
final readonly class EncryptionService implements EncryptionServiceInterface
{
    public function __construct(
        private MasterKeyProviderInterface $masterKeyProvider,
        private ExtensionConfigurationInterface $configuration,
    ) {}

    public function encrypt(#[SensitiveParameter] string $plaintext, string $identifier): EncryptedData
    {
        $masterKey = $this->masterKeyProvider->getMasterKey();

        try {
            // Generate unique DEK for this secret
            $dek = $this->generateDek();

            // Generate nonces with algorithm-appropriate length
            $nonceLength = $this->getNonceLength();
            $dekNonce = random_bytes($nonceLength);
            $valueNonce = random_bytes($nonceLength);

            // Encrypt the DEK with master key
            $encryptedDek = $this->encryptWithKey($dek, $masterKey, $dekNonce, $identifier);

            // Encrypt the value with DEK
            $encryptedValue = $this->encryptWithKey($plaintext, $dek, $valueNonce, $identifier);

            // Calculate checksum for change detection
            $checksum = $this->calculateChecksum($plaintext);

            // Securely wipe sensitive data
            sodium_memzero($dek);
            sodium_memzero($masterKey);
            sodium_memzero($plaintext);

            return EncryptedData::fromRaw(
                encryptedValue: $encryptedValue,
                encryptedDek: $encryptedDek,
                dekNonce: $dekNonce,
                valueNonce: $valueNonce,
                valueChecksum: $checksum,
            );
        } catch (SodiumException) {
            throw EncryptionException::encryptionFailed('Encryption operation failed');
        }
    }

    public function decrypt(
        #[SensitiveParameter] string $encryptedValue,
        #[SensitiveParameter] string $encryptedDek,
        string $dekNonce,
        string $valueNonce,
        string $identifier,
    ): string {
        $masterKey = $this->masterKeyProvider->getMasterKey();

        try {
            // Decode base64
            $encryptedValueBytes = base64_decode($encryptedValue, true);
            $encryptedDekBytes = base64_decode($encryptedDek, true);
            $dekNonceBytes = base64_decode($dekNonce, true);
            $valueNonceBytes = base64_decode($valueNonce, true);

            if ($encryptedValueBytes === false || $encryptedDekBytes === false
                || $dekNonceBytes === false || $valueNonceBytes === false) {
                throw EncryptionException::decryptionFailed('Invalid base64 encoding');
            }

            // Decrypt the DEK with master key
            $dek = $this->decryptWithKey($encryptedDekBytes, $masterKey, $dekNonceBytes, $identifier);

            // Decrypt the value with DEK
            $plaintext = $this->decryptWithKey($encryptedValueBytes, $dek, $valueNonceBytes, $identifier);

            // Securely wipe sensitive data
            sodium_memzero($dek);
            sodium_memzero($masterKey);

            return $plaintext;
        } catch (SodiumException) {
            throw EncryptionException::decryptionFailed('Decryption operation failed');
        }
    }

    public function generateDek(): string
    {
        if ($this->useAes256Gcm()) {
            return random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);
        }

        return random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
    }

    public function calculateChecksum(#[SensitiveParameter] string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }

    public function reEncryptDek(
        #[SensitiveParameter] string $encryptedDek,
        string $dekNonce,
        string $identifier,
        #[SensitiveParameter] string $oldMasterKey,
        #[SensitiveParameter] string $newMasterKey,
    ): ReEncryptedDek {
        try {
            // Decode
            $encryptedDekBytes = base64_decode($encryptedDek, true);
            $dekNonceBytes = base64_decode($dekNonce, true);

            if ($encryptedDekBytes === false || $dekNonceBytes === false) {
                throw EncryptionException::decryptionFailed('Invalid base64 encoding');
            }

            // Decrypt DEK with old master key
            $dek = $this->decryptWithKey($encryptedDekBytes, $oldMasterKey, $dekNonceBytes, $identifier);

            // Generate new nonce with algorithm-appropriate length
            $newNonce = random_bytes($this->getNonceLength());

            // Encrypt DEK with new master key
            $newEncryptedDek = $this->encryptWithKey($dek, $newMasterKey, $newNonce, $identifier);

            return ReEncryptedDek::fromRaw(
                encryptedDek: $newEncryptedDek,
                nonce: $newNonce,
            );
        } catch (SodiumException) {
            throw EncryptionException::encryptionFailed('Re-encryption operation failed');
        } finally {
            // Securely wipe key material from local copies
            if (isset($dek)) {
                sodium_memzero($dek);
            }
            sodium_memzero($oldMasterKey);
            sodium_memzero($newMasterKey);
        }
    }

    /**
     * Encrypt data with a key using the configured algorithm.
     */
    private function encryptWithKey(#[SensitiveParameter] string $plaintext, #[SensitiveParameter] string $key, string $nonce, string $aad): string
    {
        if ($this->useAes256Gcm()) {
            return sodium_crypto_aead_aes256gcm_encrypt($plaintext, $aad, $nonce, $key);
        }

        return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
    }

    /**
     * Decrypt data with a key using the configured algorithm.
     */
    private function decryptWithKey(#[SensitiveParameter] string $ciphertext, #[SensitiveParameter] string $key, string $nonce, string $aad): string
    {
        if ($this->useAes256Gcm()) {
            $result = sodium_crypto_aead_aes256gcm_decrypt($ciphertext, $aad, $nonce, $key);
        } else {
            $result = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $key);
        }

        if ($result === false) {
            throw EncryptionException::decryptionFailed('Authentication failed - data may have been tampered with');
        }

        return $result;
    }

    /**
     * Get the nonce length for the current algorithm.
     *
     * @return int<1, max>
     */
    private function getNonceLength(): int
    {
        // Constants are always positive, but we ensure it for type safety
        return max(1, $this->useAes256Gcm()
            ? SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES
            : SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    }

    /**
     * Determine if AES-256-GCM should be used.
     */
    private function useAes256Gcm(): bool
    {
        if ($this->configuration->preferXChaCha20()) {
            return false;
        }

        return sodium_crypto_aead_aes256gcm_is_available();
    }
}
