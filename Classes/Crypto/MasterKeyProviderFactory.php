<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\ConfigurationException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Factory for creating master key providers.
 */
final readonly class MasterKeyProviderFactory implements MasterKeyProviderFactoryInterface
{
    private ClientInterface $httpClient;

    private RequestFactoryInterface $requestFactory;

    private StreamFactoryInterface $streamFactory;

    /**
     * The HTTP dependencies are only consumed by the `transit` provider; they are
     * optional so unit tests (and any caller that never selects `transit`) can
     * construct the factory with configuration alone.
     *
     * The PSR-18 client is the platform one (TYPO3 aliases
     * `Psr\Http\Client\ClientInterface` to its Guzzle client, so proxy, TLS and
     * timeout settings from `$TYPO3_CONF_VARS['HTTP']` apply). The Vault address
     * is operator-supplied extension configuration, not request input, so the
     * SSRF/private-IP gating of `SecureHttpClientFactory` is deliberately NOT
     * applied here: it would block the on-prem RFC1918 Vault addresses this
     * provider primarily targets, and the master-key path must not depend on an
     * `allowed_hosts` entry to work.
     */
    public function __construct(
        private ExtensionConfigurationInterface $configuration,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ) {
        $httpFactory = new HttpFactory();
        $this->httpClient = $httpClient ?? new Client(['http_errors' => false, 'allow_redirects' => false]);
        $this->requestFactory = $requestFactory ?? $httpFactory;
        $this->streamFactory = $streamFactory ?? $httpFactory;
    }

    public function create(): MasterKeyProviderInterface
    {
        $provider = $this->configuration->getMasterKeyProvider();

        if ($provider === 'typo3' && $this->configuration->getSecurityProfile()->isHardened()) {
            throw ConfigurationException::providerForbiddenInHardenedProfile($provider);
        }

        return match ($provider) {
            'typo3' => new Typo3MasterKeyProvider(),
            'file' => new FileMasterKeyProvider($this->configuration),
            'env' => new EnvironmentMasterKeyProvider($this->configuration),
            // Allowed in the hardened profile: external KMS custody is exactly
            // what that profile asks for.
            'transit' => new TransitMasterKeyProvider(
                $this->configuration,
                $this->httpClient,
                $this->requestFactory,
                $this->streamFactory,
            ),
            default => throw ConfigurationException::invalidProvider($provider),
        };
    }

    /**
     * Get the configured provider, falling back to auto-detection.
     *
     * In the hardened profile there is NO auto-detection and NO fallback:
     * the explicitly configured provider is returned even when it is not
     * available (its getMasterKey() then fails loudly), and configuration
     * errors propagate. A misconfigured hardened vault must stop, never
     * silently continue on the TYPO3 encryption key.
     */
    public function getAvailableProvider(): MasterKeyProviderInterface
    {
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
