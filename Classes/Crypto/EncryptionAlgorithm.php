<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

/**
 * AEAD algorithms supported for envelope encryption.
 *
 * The backing string values are persisted per secret in
 * `tx_nrvault_secret.encryption_algorithm` (for encryption version 2+) and
 * MUST remain byte-for-byte stable: changing a value would make every stored
 * secret carrying the old string undecryptable.
 *
 * @see EncryptionService for how the marker is written and dispatched on
 */
enum EncryptionAlgorithm: string
{
    case XChaCha20Poly1305 = 'xchacha20poly1305';
    case Aes256Gcm = 'aes256gcm';

    /**
     * Default algorithm recorded for newly encrypted secrets when no explicit
     * algorithm is configured.
     *
     * XChaCha20-Poly1305 is the deliberate default: it is available in every
     * libsodium build (AES-256-GCM requires hardware support) and its 24-byte
     * nonce makes random-nonce collisions a non-concern, so vault contents
     * stay portable across hosts with differing CPU capabilities.
     */
    public static function forNewSecrets(): self
    {
        return self::XChaCha20Poly1305;
    }

    /**
     * Whether the current host can encrypt/decrypt with this algorithm.
     */
    public function isAvailable(): bool
    {
        return match ($this) {
            self::XChaCha20Poly1305 => true,
            self::Aes256Gcm => sodium_crypto_aead_aes256gcm_is_available(),
        };
    }

    /**
     * Nonce length (bytes) for this algorithm.
     *
     * @return int<1, max>
     */
    public function nonceLength(): int
    {
        // Constants are always positive, but we ensure it for type safety.
        return max(1, match ($this) {
            self::XChaCha20Poly1305 => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
            self::Aes256Gcm => SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES,
        });
    }

    /**
     * Key length (bytes) for this algorithm.
     *
     * @return int<1, max>
     */
    public function keyLength(): int
    {
        // Constants are always positive, but we ensure it for type safety.
        return max(1, match ($this) {
            self::XChaCha20Poly1305 => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            self::Aes256Gcm => SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES,
        });
    }
}
