<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Exception\ConfigurationException;

/**
 * Interface for master key provider factory.
 */
interface MasterKeyProviderFactoryInterface
{
    /**
     * Create a master key provider based on configuration.
     *
     * @throws ConfigurationException If the provider is invalid, or if the
     *                                hardened security profile forbids the
     *                                configured provider (e.g. 'typo3')
     */
    public function create(): MasterKeyProviderInterface;

    /**
     * Get the configured provider, falling back to auto-detection.
     *
     * Auto-detection applies to the Standard profile only. In the Hardened
     * profile this behaves exactly like {@see create()}: no fallback, no
     * auto-detection — configuration errors propagate (fail-closed).
     *
     * @throws ConfigurationException In the hardened profile, if the
     *                                configured provider is invalid or forbidden
     */
    public function getAvailableProvider(): MasterKeyProviderInterface;
}
