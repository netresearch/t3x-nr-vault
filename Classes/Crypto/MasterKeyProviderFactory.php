<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\ConfigurationException;

/**
 * Selects the master key provider named by `masterKeyProvider`.
 *
 * Resolution goes through {@see MasterKeyProviderRegistryInterface}, which
 * indexes every service tagged `nr_vault.master_key_provider` by its own
 * `getIdentifier()`. The four built-in providers are registered that way and
 * are constructed by the container, so the `transit` provider receives the
 * platform PSR-18 client and the PSR-17 factories through dependency injection
 * rather than from this class.
 *
 * This factory therefore holds exactly two decisions: which identifier is
 * configured, and whether the security profile permits it.
 */
final readonly class MasterKeyProviderFactory implements MasterKeyProviderFactoryInterface
{
    /**
     * Provider identifiers the hardened profile refuses, named explicitly.
     *
     * An explicit deny list, not an implicit allow list, and the difference is
     * the whole point of the extension point: the hardened profile's demand is
     * that the master key lives OUTSIDE `settings.php`, which the `typo3`
     * provider alone violates. A provider supplied by another extension — a
     * cloud KMS, an HSM bridge — is the case the profile asks for, so refusing
     * unknown identifiers by default would forbid exactly the deployments the
     * profile exists to serve.
     *
     * What this cannot police is what installed code does: a custom provider is
     * free to derive its key from the TYPO3 encryption key under another name.
     * The profile constrains configuration, not the trustworthiness of an
     * extension the operator installed.
     *
     * @var list<string>
     */
    private const FORBIDDEN_IN_HARDENED_PROFILE = ['typo3'];

    public function __construct(
        private ExtensionConfigurationInterface $configuration,
        private MasterKeyProviderRegistryInterface $registry,
    ) {}

    public function create(): MasterKeyProviderInterface
    {
        $provider = $this->configuration->getMasterKeyProvider();

        if (
            \in_array($provider, self::FORBIDDEN_IN_HARDENED_PROFILE, true)
            && $this->configuration->getSecurityProfile()->isHardened()
        ) {
            throw ConfigurationException::providerForbiddenInHardenedProfile($provider);
        }

        return $this->registry->get($provider);
    }

    /**
     * Get the configured provider, falling back to auto-detection.
     *
     * In the hardened profile there is NO auto-detection and NO fallback:
     * the explicitly configured provider is returned even when it is not
     * available (its getMasterKey() then fails loudly), and configuration
     * errors propagate. A misconfigured hardened vault must stop, never
     * silently continue on the TYPO3 encryption key.
     *
     * Auto-detection probes the three built-in local key sources and nothing
     * else — deliberately. A registered custom provider is reached only by
     * being configured by name: auto-detecting one would mean the vault chose
     * a key custody the operator never asked for, which is the opposite of
     * what this fallback is for (surviving an installation that has not been
     * configured yet).
     */
    public function getAvailableProvider(): MasterKeyProviderInterface
    {
        // Before the catch below, which swallows ConfigurationException to reach
        // the fallback chain: an ambiguous registration must not be answered by
        // quietly auto-detecting something else. See the registry's class
        // docblock for why a collision is fatal rather than resolved.
        $this->registry->assertNoIdentifierConflicts();

        if ($this->configuration->getSecurityProfile()->isHardened()) {
            return $this->create();
        }

        // Try configured provider first
        try {
            $provider = $this->create();
            if ($provider->isAvailable()) {
                return $provider;
            }
        } catch (ConfigurationException) {
            // Fall through to auto-detection
        }

        // Try TYPO3 encryption key (always available after installation)
        $typo3Provider = new Typo3MasterKeyProvider();
        if ($typo3Provider->isAvailable()) {
            return $typo3Provider;
        }

        // Try environment variable
        $envProvider = new EnvironmentMasterKeyProvider($this->configuration);
        if ($envProvider->isAvailable()) {
            return $envProvider;
        }

        // Try file-based (including auto-generated)
        $fileProvider = new FileMasterKeyProvider($this->configuration);
        if ($fileProvider->isAvailable()) {
            return $fileProvider;
        }

        // No provider available - return typo3 provider (will fail with clear error)
        return $typo3Provider;
    }
}
