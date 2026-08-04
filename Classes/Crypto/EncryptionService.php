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
    /**
     * HKDF domain-separation context for deriving the per-secret checksum MAC
     * key from the DEK. Distinct from any other HKDF use in the codebase.
     */
    private const CHECKSUM_HKDF_INFO = 'nr-vault-checksum';

    /** Length (bytes) of the derived checksum MAC key. */
    private const CHECKSUM_MAC_KEY_LENGTH = 32;

    public function __construct(
        private MasterKeyProviderInterface $masterKeyProvider,
        private ExtensionConfigurationInterface $configuration,
    ) {}

    public function encrypt(#[SensitiveParameter] string $plaintext, string $identifier): EncryptedData
    {
        // Select and RECORD the algorithm: new envelopes are version 2, so
        // decryption dispatches on the stored marker instead of re-deriving
        // the algorithm from the capabilities of whatever host decrypts.
        $algorithm = $this->algorithmForNewSecrets();

        $masterKey = $this->masterKeyProvider->getMasterKey();

        try {
            // Generate unique DEK for this secret
            $dek = random_bytes($algorithm->keyLength());

            // Generate nonces with algorithm-appropriate length
            $nonceLength = $algorithm->nonceLength();
            $dekNonce = random_bytes($nonceLength);
            $valueNonce = random_bytes($nonceLength);

            // Encrypt the DEK with master key
            $encryptedDek = $this->encryptWithKey($dek, $masterKey, $dekNonce, $identifier, $algorithm);

            // Encrypt the value with DEK
            $encryptedValue = $this->encryptWithKey($plaintext, $dek, $valueNonce, $identifier, $algorithm);

            // Change-detection token: a KEYED MAC over the ciphertext, never the
            // plaintext. The MAC key is derived per-secret from the DEK via HKDF,
            // so the stored checksum is not an offline-computable function of the
            // plaintext (no guess-confirmation oracle) and identical plaintexts in
            // different secrets yield different checksums (no equality leakage).
            // Integrity itself comes from the AEAD tag; this is solely a change
            // detector / audit before-after token. See SEC-CRYPTO-1 / ADR-002.
            $macKey = hash_hkdf('sha256', $dek, self::CHECKSUM_MAC_KEY_LENGTH, self::CHECKSUM_HKDF_INFO);
            $checksum = hash_hmac('sha256', $encryptedValue, $macKey);

            // Securely wipe sensitive data. The master key is deliberately NOT
            // wiped here (or in the finally block): it is the provider's shared
            // request-lifetime cache entry — see the equivalent note in decrypt().
            sodium_memzero($dek);
            sodium_memzero($macKey);
            sodium_memzero($plaintext);

            return EncryptedData::fromRaw(
                encryptedValue: $encryptedValue,
                encryptedDek: $encryptedDek,
                dekNonce: $dekNonce,
                valueNonce: $valueNonce,
                valueChecksum: $checksum,
                encryptionVersion: EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT,
                encryptionAlgorithm: $algorithm,
            );
        } catch (SodiumException) {
            throw EncryptionException::encryptionFailed('Encryption operation failed');
        } finally {
            // Wipe key material on every path, including the SodiumException
            // error path that bypasses the in-try wipes above. sodium_memzero()
            // sets the wiped variable to null, so isset() distinguishes
            // already-wiped buffers (skip) from un-wiped ones (wipe now);
            // calling it again on a wiped (null) variable would throw.
            if (isset($dek)) {
                sodium_memzero($dek);
            }

            if (isset($macKey)) {
                sodium_memzero($macKey);
            }

            if (isset($plaintext)) {
                sodium_memzero($plaintext);
            }

            // The master key is deliberately NOT wiped: it is the provider's
            // shared request-lifetime cache entry (see decrypt()); the provider
            // owns its lifecycle and wipes it on destruction.
        }
    }

    public function decrypt(
        #[SensitiveParameter]
        string $encryptedValue,
        #[SensitiveParameter]
        string $encryptedDek,
        string $dekNonce,
        string $valueNonce,
        string $identifier,
        int $encryptionVersion = EncryptionServiceInterface::ENCRYPTION_VERSION_LEGACY,
        string $encryptionAlgorithm = '',
    ): string {
        // Resolve the algorithm BEFORE touching key material: version 2+
        // dispatches on the stored marker, version 1 derives from host
        // capabilities exactly as before the marker existed.
        $algorithm = $this->resolveAlgorithm($encryptionVersion, $encryptionAlgorithm);

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
            $dek = $this->decryptWithKey($encryptedDekBytes, $masterKey, $dekNonceBytes, $identifier, $algorithm);

            // Decrypt the value with DEK
            $plaintext = $this->decryptWithKey($encryptedValueBytes, $dek, $valueNonceBytes, $identifier, $algorithm);

            // Securely wipe the per-secret DEK. The master key is deliberately
            // NOT wiped here: getMasterKey() returns the provider's shared
            // request-lifetime cache entry, so wiping the local reference would
            // either be a no-op (PHP's sodium_memzero skips refcount>1 strings)
            // or corrupt the cached key for every later vault operation in the
            // request. The provider wipes its cache on destruction.
            sodium_memzero($dek);

            return $plaintext;
        } catch (SodiumException) {
            throw EncryptionException::decryptionFailed('Decryption operation failed');
        } finally {
            // Wipe the freshly unwrapped DEK on every path, including the
            // SodiumException error path reachable via tampered ciphertext that
            // bypasses the in-try wipe above. The master key is the provider's
            // request-cached value and is handled by the in-try wipe only (see
            // SEC-CRYPTO-2 / ADR-002), to avoid clobbering the shared cache.
            if (isset($dek)) {
                sodium_memzero($dek);
            }
        }
    }

    public function generateDek(): string
    {
        return random_bytes($this->algorithmForNewSecrets()->keyLength());
    }

    public function calculateChecksum(#[SensitiveParameter] string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }

    public function reEncryptDek(
        #[SensitiveParameter]
        string $encryptedDek,
        string $dekNonce,
        string $identifier,
        #[SensitiveParameter]
        string $oldMasterKey,
        #[SensitiveParameter]
        string $newMasterKey,
        int $encryptionVersion = EncryptionServiceInterface::ENCRYPTION_VERSION_LEGACY,
        string $encryptionAlgorithm = '',
    ): ReEncryptedDek {
        // The DEK envelope must be unwrapped AND re-wrapped with the secret's
        // own algorithm: marker for version 2+, host-derived for version 1.
        $algorithm = $this->resolveAlgorithm($encryptionVersion, $encryptionAlgorithm);

        try {
            // Decode
            $encryptedDekBytes = base64_decode($encryptedDek, true);
            $dekNonceBytes = base64_decode($dekNonce, true);

            if ($encryptedDekBytes === false || $dekNonceBytes === false) {
                throw EncryptionException::decryptionFailed('Invalid base64 encoding');
            }

            // Decrypt DEK with old master key
            $dek = $this->decryptWithKey($encryptedDekBytes, $oldMasterKey, $dekNonceBytes, $identifier, $algorithm);

            // Generate new nonce with algorithm-appropriate length
            $newNonce = random_bytes($algorithm->nonceLength());

            // Encrypt DEK with new master key
            $newEncryptedDek = $this->encryptWithKey($dek, $newMasterKey, $newNonce, $identifier, $algorithm);

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
     * Encrypt data with a key using the given algorithm.
     */
    private function encryptWithKey(#[SensitiveParameter] string $plaintext, #[SensitiveParameter] string $key, string $nonce, string $aad, EncryptionAlgorithm $algorithm): string
    {
        return match ($algorithm) {
            EncryptionAlgorithm::Aes256Gcm => sodium_crypto_aead_aes256gcm_encrypt($plaintext, $aad, $nonce, $key),
            EncryptionAlgorithm::XChaCha20Poly1305 => sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key),
        };
    }

    /**
     * Decrypt data with a key using the given algorithm.
     */
    private function decryptWithKey(#[SensitiveParameter] string $ciphertext, #[SensitiveParameter] string $key, string $nonce, string $aad, EncryptionAlgorithm $algorithm): string
    {
        $result = match ($algorithm) {
            EncryptionAlgorithm::Aes256Gcm => sodium_crypto_aead_aes256gcm_decrypt($ciphertext, $aad, $nonce, $key),
            EncryptionAlgorithm::XChaCha20Poly1305 => sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $key),
        };

        if ($result === false) {
            throw EncryptionException::decryptionFailed('Authentication failed - data may have been tampered with');
        }

        return $result;
    }

    /**
     * Resolve the algorithm to use for an existing envelope.
     *
     * Unknown versions are a hard error: a version this reader does not
     * implement may change framing, key derivation or the authenticated
     * data, so opening it under version-2 rules would decrypt with the
     * wrong recipe rather than refuse. Forward compatibility must be a
     * deliberate code change, never an accident of a `>=` comparison.
     *
     * Version 2: the stored marker is authoritative. An unknown or empty
     * marker is a hard error — guessing an algorithm for a version-2 row
     * could silently decrypt with the wrong primitive on a different host,
     * which is exactly the implicitness the marker exists to remove.
     *
     * Version 1 (legacy): no marker exists; derive from host capabilities +
     * configuration, byte-identical to the pre-marker behaviour, so existing
     * rows keep decrypting exactly as before.
     */
    private function resolveAlgorithm(int $encryptionVersion, string $encryptionAlgorithm): EncryptionAlgorithm
    {
        if (
            $encryptionVersion < EncryptionServiceInterface::ENCRYPTION_VERSION_LEGACY
            || $encryptionVersion > EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT
        ) {
            throw EncryptionException::decryptionFailed(\sprintf(
                'Unsupported encryption version %d (this reader implements %d..%d)',
                $encryptionVersion,
                EncryptionServiceInterface::ENCRYPTION_VERSION_LEGACY,
                EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT,
            ));
        }

        if ($encryptionVersion >= EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT) {
            $algorithm = EncryptionAlgorithm::tryFrom($encryptionAlgorithm);
            if (!$algorithm instanceof EncryptionAlgorithm) {
                throw EncryptionException::decryptionFailed(\sprintf(
                    'Unknown encryption algorithm marker for encryption version %d',
                    $encryptionVersion,
                ));
            }

            if (!$algorithm->isAvailable()) {
                throw EncryptionException::decryptionFailed(\sprintf(
                    'Encryption algorithm "%s" is not available on this host',
                    $algorithm->value,
                ));
            }

            return $algorithm;
        }

        return $this->useAes256Gcm()
            ? EncryptionAlgorithm::Aes256Gcm
            : EncryptionAlgorithm::XChaCha20Poly1305;
    }

    /**
     * Algorithm recorded for NEW envelopes (encryption version 2).
     *
     * Defaults to XChaCha20-Poly1305 ({@see EncryptionAlgorithm::forNewSecrets()});
     * a site can pin a different algorithm via the `encryptionAlgorithm`
     * extension setting. Unknown or host-unavailable configuration values
     * fail loudly instead of silently falling back — for a vault, refusing
     * to encrypt beats encrypting with an algorithm the operator did not
     * choose.
     */
    private function algorithmForNewSecrets(): EncryptionAlgorithm
    {
        $configured = $this->configuration->getEncryptionAlgorithm();
        if ($configured === '') {
            return EncryptionAlgorithm::forNewSecrets();
        }

        $algorithm = EncryptionAlgorithm::tryFrom($configured);
        if (!$algorithm instanceof EncryptionAlgorithm) {
            throw EncryptionException::encryptionFailed(\sprintf(
                'Unknown encryptionAlgorithm "%s" configured for the nr_vault extension',
                $configured,
            ));
        }

        if (!$algorithm->isAvailable()) {
            throw EncryptionException::encryptionFailed(\sprintf(
                'Configured encryption algorithm "%s" is not available on this host',
                $algorithm->value,
            ));
        }

        return $algorithm;
    }

    /**
     * Determine if AES-256-GCM should be used (LEGACY/version-1 envelopes
     * only — must stay byte-identical to the pre-marker selection logic).
     */
    private function useAes256Gcm(): bool
    {
        if ($this->configuration->preferXChaCha20()) {
            return false;
        }

        return sodium_crypto_aead_aes256gcm_is_available();
    }
}
