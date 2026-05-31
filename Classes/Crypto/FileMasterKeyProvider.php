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
 * File-based master key provider.
 */
final class FileMasterKeyProvider extends AbstractMasterKeyProvider
{
    private const KEY_LENGTH = 32; // 256 bits

    public function __construct(
        private readonly ExtensionConfigurationInterface $configuration,
    ) {}

    public function __destruct()
    {
        // File/Env providers wipe their request-lifetime cache on destruction;
        // the inherited static cache is keyed by class so this clears only this
        // provider's slot. See ADR-020.
        self::clearCachedKey();
    }

    public function getIdentifier(): string
    {
        return 'file';
    }

    public function isAvailable(): bool
    {
        $path = $this->getKeyPath();

        return $path !== '' && file_exists($path) && is_readable($path);
    }

    public function storeMasterKey(#[SensitiveParameter] string $key): void
    {
        if (\strlen($key) !== self::KEY_LENGTH) {
            throw MasterKeyException::invalidLength(self::KEY_LENGTH, \strlen($key));
        }

        $path = $this->getKeyPath();
        if ($path === '') {
            $path = $this->configuration->getAutoKeyPath();
        }

        $dir = \dirname($path);
        if (!is_dir($dir) && (!mkdir($dir, 0o700, true) && !is_dir($dir))) {
            throw MasterKeyException::cannotStore("Cannot create directory: {$dir}");
        }

        // Eliminate the umask race: tighten umask before write so the file is
        // created 0600, then chmod to the final 0400. The previous order
        // (file_put_contents → chmod 0400) left a brief window where the
        // freshly created file was world-readable on hosts with permissive
        // umasks.
        $previousUmask = umask(0o077);

        try {
            $result = file_put_contents($path, base64_encode($key));
        } finally {
            umask($previousUmask);
        }
        if ($result === false) {
            throw MasterKeyException::cannotStore("Cannot write to: {$path}");
        }

        // Secure the file permissions
        chmod($path, 0o400);
    }

    public function generateMasterKey(): string
    {
        return random_bytes(self::KEY_LENGTH);
    }

    protected function loadRawKey(): string
    {
        $path = $this->getKeyPath();

        if ($path === '') {
            throw MasterKeyException::notFound('No path configured');
        }

        if (!file_exists($path)) {
            // Try auto-generated key path for development
            $autoPath = $this->configuration->getAutoKeyPath();
            if (file_exists($autoPath) && is_readable($autoPath)) {
                $path = $autoPath;
            } else {
                throw MasterKeyException::notFound($path);
            }
        }

        if (!is_readable($path)) {
            throw MasterKeyException::notFound($path . ' (not readable)');
        }

        $raw = file_get_contents($path);
        if ($raw === false) {
            throw MasterKeyException::notFound($path);
        }

        // Trim whitespace first (handles trailing newlines from text editors)
        $trimmed = trim($raw);

        // Try trimmed value as raw binary key
        if (\strlen($trimmed) === self::KEY_LENGTH) {
            return $trimmed;
        }

        // Try base64 decode of trimmed value
        $decoded = base64_decode($trimmed, true);
        if ($decoded !== false && \strlen($decoded) === self::KEY_LENGTH) {
            return $decoded;
        }

        // Try raw file contents as binary (no trimming of binary data)
        if (\strlen($raw) === self::KEY_LENGTH) {
            return $raw;
        }

        throw MasterKeyException::invalidLength(self::KEY_LENGTH, \strlen($trimmed));
    }

    private function getKeyPath(): string
    {
        $source = $this->configuration->getMasterKeySource();
        // For file provider, source is the file path
        if ($source !== '' && $source !== ExtensionConfiguration::DEFAULT_MASTER_KEY_SOURCE) {
            return $source;
        }

        return '';
    }
}
