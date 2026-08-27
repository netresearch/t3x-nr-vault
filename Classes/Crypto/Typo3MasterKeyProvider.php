<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\MasterKeyException;
use SensitiveParameter;

/**
 * TYPO3 encryption key-based master key provider.
 *
 * Derives the master key from TYPO3's encryption key using HKDF-SHA256.
 * This is the default provider as it requires no additional configuration.
 *
 * Note: the strength of the derived master key equals the strength of
 * TYPO3's encryption key. For production use,
 * prefer FileMasterKeyProvider or EnvironmentMasterKeyProvider (see ADR-003).
 */
final class Typo3MasterKeyProvider extends AbstractMasterKeyProvider
{
    private const KEY_LENGTH = 32; // 256 bits

    private const HKDF_INFO = 'nr-vault-master-key';

    /**
     * Minimum length of the source TYPO3 encryption key. Anything shorter than
     * this provides far less than 256 bits of entropy to HKDF and would produce
     * a weak master key. TYPO3 generates 96-character keys by default; legacy
     * installs may still carry shorter strings.
     */
    private const MIN_SOURCE_KEY_LENGTH = 32;

    /**
     * The request-lifetime cache lives in {@see AbstractMasterKeyProvider} and
     * is cleared via the inherited static {@see clearCachedKey()}. This provider
     * deliberately defines NO `__destruct`: its cache slot is keyed by class and
     * shared across instances, so wiping it when one instance is garbage-
     * collected would break the rest of the request. PHP zeroes the static at
     * script shutdown anyway; long-running processes (scheduler tasks, daemons)
     * should call {@see clearCachedKey()} explicitly when they need to observe a
     * rotated TYPO3 `encryptionKey`. See ADR-020.
     */
    public function __construct(
        private readonly ExtensionConfigurationInterface $configuration,
    ) {}

    public function getIdentifier(): string
    {
        return 'typo3';
    }

    public function isAvailable(): bool
    {
        return $this->getEncryptionKey() !== '';
    }

    public function storeMasterKey(#[SensitiveParameter] string $key): void
    {
        // Cannot store - the key is derived from TYPO3's encryption key
        throw MasterKeyException::cannotStore(
            "TYPO3 provider derives the key from encryptionKey. To change it, rotate TYPO3's encryption key.",
        );
    }

    public function generateMasterKey(): string
    {
        return random_bytes(self::KEY_LENGTH);
    }

    protected function loadRawKey(): string
    {
        $encryptionKey = $this->getEncryptionKey();

        if ($encryptionKey === '') {
            throw MasterKeyException::notFound('TYPO3 encryption key is not set');
        }

        if (\strlen($encryptionKey) < self::MIN_SOURCE_KEY_LENGTH) {
            throw MasterKeyException::invalidLength(
                self::MIN_SOURCE_KEY_LENGTH,
                \strlen($encryptionKey),
            );
        }

        // Derive master key using HKDF-SHA256 with nr-vault-specific context
        return hash_hkdf(
            'sha256',
            $encryptionKey,
            self::KEY_LENGTH,
            self::HKDF_INFO,
        );
    }

    private function getEncryptionKey(): string
    {
        return $this->configuration->getTypo3EncryptionKey();
    }
}
