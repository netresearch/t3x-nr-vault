<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Exception\MasterKeyException;
use SensitiveParameter;

/**
 * TYPO3 encryption key-based master key provider.
 *
 * Derives the master key from TYPO3's encryption key using HKDF-SHA256.
 * This is the default provider as it requires no additional configuration.
 *
 * Note: the strength of the derived master key equals the strength of
 * `$GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey']`. For production use,
 * prefer FileMasterKeyProvider or EnvironmentMasterKeyProvider (see ADR-003).
 */
final class Typo3MasterKeyProvider implements MasterKeyProviderInterface
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

    /** @var string|null Request-lifetime cached master key (ADR-020) */
    private static ?string $cachedKey = null;

    public function __destruct()
    {
        self::clearCachedKey();
    }

    /**
     * Clear the cached master key from memory.
     */
    public static function clearCachedKey(): void
    {
        if (self::$cachedKey !== null) {
            sodium_memzero(self::$cachedKey);
            self::$cachedKey = null;
        }
    }

    public function getIdentifier(): string
    {
        return 'typo3';
    }

    public function isAvailable(): bool
    {
        return $this->getEncryptionKey() !== '';
    }

    public function getMasterKey(): string
    {
        if (self::$cachedKey !== null) {
            return self::$cachedKey;
        }

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
        self::$cachedKey = hash_hkdf(
            'sha256',
            $encryptionKey,
            self::KEY_LENGTH,
            self::HKDF_INFO,
        );

        return self::$cachedKey;
    }

    public function storeMasterKey(#[SensitiveParameter] string $key): void
    {
        // Cannot store - the key is derived from TYPO3's encryption key
        throw MasterKeyException::cannotStore(
            'TYPO3 provider derives the key from encryptionKey. To change it, rotate TYPO3\'s encryption key.',
        );
    }

    public function generateMasterKey(): string
    {
        return random_bytes(self::KEY_LENGTH);
    }

    private function getEncryptionKey(): string
    {
        $typo3ConfVars = $GLOBALS['TYPO3_CONF_VARS'] ?? [];
        if (!\is_array($typo3ConfVars)) {
            return '';
        }

        $sysConfig = $typo3ConfVars['SYS'] ?? [];
        if (!\is_array($sysConfig)) {
            return '';
        }

        $encryptionKey = $sysConfig['encryptionKey'] ?? '';

        return \is_string($encryptionKey) ? $encryptionKey : '';
    }
}
