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
 * Interface for master key providers.
 */
interface MasterKeyProviderInterface
{
    /**
     * Get the provider identifier.
     *
     * @return string e.g., "file", "env", "derived"
     */
    public function getIdentifier(): string;

    /**
     * Check if the provider is configured and key is available.
     */
    public function isAvailable(): bool;

    /**
     * Get the master key.
     *
     * @throws MasterKeyException If key cannot be retrieved
     *
     * @return string 32-byte master key
     */
    public function getMasterKey(): string;

    /**
     * Store a new master key (for rotation).
     *
     * @param string $key The new 32-byte master key
     *
     * @throws MasterKeyException If key cannot be stored
     */
    public function storeMasterKey(#[SensitiveParameter] string $key): void;

    /**
     * Generate a new random master key.
     *
     * @return string 32-byte random key (not stored, just generated)
     */
    public function generateMasterKey(): string;
}
