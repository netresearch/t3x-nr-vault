<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Configuration;

use Netresearch\NrVault\Service\VaultServiceInterface;
use Psr\Log\LoggerInterface;
use Throwable;
use TYPO3\CMS\Core\Site\Entity\Site;

/**
 * Processor for resolving vault references in site configuration.
 *
 * Supports vault references in site configuration using the format:
 *
 *     someApiKey: '%vault(my_api_key)%'
 *     settings:
 *         secret: '%vault(site_payment_secret)%'
 *
 * Resolution is caller-driven and happens at read time. There is deliberately
 * NO event listener that resolves references when TYPO3 loads the site
 * configuration: TYPO3 persists the loaded configuration array into the shared,
 * on-disk `core` cache, so eager resolution would write decrypted secrets to
 * that cache file in cleartext (defeating encryption-at-rest) and would evaluate
 * the per-principal access check exactly once, at cache-warm time, instead of
 * for each reader. Callers therefore resolve explicitly, in their own request
 * context, and the resolved plaintext lives only for that request.
 *
 * Usage in site configuration (config/sites/<identifier>/config.yaml):
 *
 *     base: 'https://example.com/'
 *     languages: []
 *     settings:
 *         payment:
 *             apiKey: '%vault(payment_api_key)%'
 *             secret: '%vault(payment_secret)%'
 *
 * Then resolve in code, at the point of use:
 *
 *     $site = $request->getAttribute('site');
 *     $processor = GeneralUtility::makeInstance(SiteConfigurationVaultProcessor::class);
 *     $config = $processor->processConfiguration($site->getConfiguration(), $site);
 *     $apiKey = $config['settings']['payment']['apiKey']; // Resolved secret value
 */
final readonly class SiteConfigurationVaultProcessor implements SiteConfigurationVaultProcessorInterface
{
    private const VAULT_PATTERN = '/%vault\(([^)]+)\)%/';

    public function __construct(
        private VaultServiceInterface $vaultService,
        private LoggerInterface $logger,
    ) {}

    /**
     * Process site configuration and resolve vault references.
     *
     * @param array<string, mixed> $configuration
     *
     * @return array<string, mixed>
     */
    public function processConfiguration(array $configuration, ?Site $site = null): array
    {
        return $this->resolveVaultReferences($configuration, $site);
    }

    /**
     * Process a single configuration value.
     *
     * Returns the resolved secret if the value is a vault reference,
     * or the original value otherwise.
     */
    public function processValue(mixed $value, ?Site $site = null): mixed
    {
        if (!\is_string($value)) {
            return $value;
        }

        if (!$this->isVaultReference($value)) {
            return $value;
        }

        return $this->resolveVaultReference($value, $site);
    }

    /**
     * Check if a value is a vault reference.
     */
    public function isVaultReference(mixed $value): bool
    {
        return \is_string($value) && preg_match(self::VAULT_PATTERN, $value) === 1;
    }

    /**
     * Build a vault reference string for use in configuration.
     */
    public static function buildVaultReference(string $identifier): string
    {
        return \sprintf('%%vault(%s)%%', $identifier);
    }

    /**
     * Extract the vault identifier from a reference string.
     */
    public function extractIdentifier(string $reference): ?string
    {
        if (preg_match(self::VAULT_PATTERN, $reference, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * @param array<string, mixed> $configuration
     *
     * @return array<string, mixed>
     */
    private function resolveVaultReferences(array $configuration, ?Site $site): array
    {
        $resolved = [];

        foreach ($configuration as $key => $value) {
            $keyStr = \is_string($key) ? $key : (string) $key;
            if (\is_array($value)) {
                /** @var array<string, mixed> $value */
                $resolved[$keyStr] = $this->resolveVaultReferences($value, $site);
            } elseif (\is_string($value) && $this->isVaultReference($value)) {
                $resolved[$keyStr] = $this->resolveVaultReference($value, $site);
            } else {
                $resolved[$keyStr] = $value;
            }
        }

        return $resolved;
    }

    private function resolveVaultReference(string $value, ?Site $site): mixed
    {
        $identifier = $this->extractIdentifier($value);

        if ($identifier === null) {
            return $value;
        }

        // Support site-prefixed identifiers: site:{siteIdentifier}:{secretId}
        // Use exists() first to avoid full retrieval (decrypt + audit) on misses
        if ($site instanceof Site && !str_contains($identifier, ':')) {
            $siteIdentifier = \sprintf('site:%s:%s', $site->getIdentifier(), $identifier);

            if ($this->vaultService->exists($siteIdentifier)) {
                try {
                    $secret = $this->vaultService->retrieve($siteIdentifier);
                    if ($secret !== null) {
                        return $secret;
                    }
                } catch (Throwable) {
                    // Fall through to global identifier
                }
            }
        }

        try {
            $secret = $this->vaultService->retrieve($identifier);

            return $secret ?? $value;
        } catch (Throwable $e) {
            $this->logger->warning('Failed to resolve vault reference', [
                'site' => $site?->getIdentifier(),
                'error' => $e->getMessage(),
            ]);

            return $value;
        }
    }
}
