<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Configuration\ExtensionConfiguration;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\MasterKeyException;
use SensitiveParameter;

/**
 * Environment variable-based master key provider.
 */
final class EnvironmentMasterKeyProvider implements MasterKeyProviderInterface
{
    private const KEY_LENGTH = 32; // 256 bits

    /** @var string|null Request-lifetime cached master key */
    private static ?string $cachedKey = null;

    public function __construct(
        private readonly ExtensionConfigurationInterface $configuration,
    ) {}

    public function __destruct()
    {
        self::clearCachedKey();
    }

    public function getIdentifier(): string
    {
        return 'env';
    }

    public function isAvailable(): bool
    {
        $varName = $this->getEnvVarName();
        $value = getenv($varName);

        return $value !== false && $value !== '';
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

    public function getMasterKey(): string
    {
        if (self::$cachedKey !== null) {
            return self::$cachedKey;
        }

        $varName = $this->getEnvVarName();
        $value = getenv($varName);

        if ($value === false || $value === '') {
            throw MasterKeyException::environmentVariableNotSet($varName);
        }

        // Handle base64-encoded keys
        if (\strlen($value) === self::KEY_LENGTH) {
            // Raw binary key - return directly (don't zero $value, it IS the key)
            self::$cachedKey = $value;

            return self::$cachedKey;
        }

        $decoded = base64_decode($value, true);
        if ($decoded !== false && \strlen($decoded) === self::KEY_LENGTH) {
            // Zero the raw base64 string, keep decoded key
            sodium_memzero($value);
            self::$cachedKey = $decoded;

            return self::$cachedKey;
        }

        // Neither raw nor valid base64
        $length = \strlen($value);
        sodium_memzero($value);

        throw MasterKeyException::invalidLength(self::KEY_LENGTH, $length);
    }

    public function storeMasterKey(#[SensitiveParameter] string $key): void
    {
        // Cannot store to environment variable at runtime
        throw MasterKeyException::cannotStore(
            'Environment variables cannot be persisted. Set the environment variable manually.',
        );
    }

    public function generateMasterKey(): string
    {
        return random_bytes(self::KEY_LENGTH);
    }

    private function getEnvVarName(): string
    {
        $source = $this->configuration->getMasterKeySource();

        // For env provider, source is the environment variable name
        return $source !== '' ? $source : ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE;
    }
}
