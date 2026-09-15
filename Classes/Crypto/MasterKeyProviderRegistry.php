<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Exception\ConfigurationException;

/**
 * Default {@see MasterKeyProviderRegistryInterface} implementation.
 *
 * Providers arrive as a tagged iterator (`nr_vault.master_key_provider`, wired
 * in `Services.yaml`), so a consuming extension adds its own key source by
 * implementing {@see MasterKeyProviderInterface} and tagging it — no change
 * here. The four built-in providers are tagged the same way and carry no
 * privilege the registry can see.
 *
 * ## Why an ambiguous registration is fatal rather than resolved
 *
 * Two providers answering the same identifier is a question about which key
 * source protects the vault, and every way of answering it silently is wrong:
 * last-one-wins lets an installed extension take over the master key by
 * choosing the name `file`, first-one-wins lets load order decide a custody
 * question. The registry therefore refuses to serve ANY lookup while a
 * collision exists, not merely a lookup of the colliding name — an operator
 * who sees the vault stop has an ambiguity to resolve, which is the accurate
 * description of the state.
 *
 * A blank identifier is refused for the same reason: `masterKeyProvider` is a
 * plain string setting, so a provider that names itself `''` would be selected
 * by an empty setting — the value an installation has before anybody chooses.
 *
 * ## Construction must be cheap
 *
 * The map is built by instantiating every tagged provider and asking for its
 * identifier, so a provider constructor runs on the first vault operation of a
 * request. It must not touch the network or the filesystem; reaching the key
 * source belongs in `isAvailable()` and `getMasterKey()`.
 */
final class MasterKeyProviderRegistry implements MasterKeyProviderRegistryInterface
{
    /**
     * Built once per request by {@see map()}; null until the first lookup.
     *
     * @var array<string, MasterKeyProviderInterface>|null
     */
    private ?array $byIdentifier = null;

    /**
     * @param iterable<MasterKeyProviderInterface> $providers Tagged provider collection
     */
    public function __construct(
        private readonly iterable $providers,
    ) {}

    public function get(string $identifier): MasterKeyProviderInterface
    {
        return $this->map()[$identifier] ?? throw ConfigurationException::invalidProvider($identifier);
    }

    public function has(string $identifier): bool
    {
        return isset($this->map()[$identifier]);
    }

    public function getIdentifiers(): array
    {
        return array_keys($this->map());
    }

    public function assertNoIdentifierConflicts(): void
    {
        $this->map();
    }

    /**
     * The identifier → provider index, built on first use.
     *
     * A collision or a blank identifier throws before the index is memoised, so
     * a later call re-runs the check and fails the same way rather than serving
     * a half-built map.
     *
     * @throws ConfigurationException
     *
     * @return array<string, MasterKeyProviderInterface>
     */
    private function map(): array
    {
        if ($this->byIdentifier !== null) {
            return $this->byIdentifier;
        }

        $map = [];

        foreach ($this->providers as $provider) {
            $identifier = $provider->getIdentifier();

            if (trim($identifier) === '') {
                throw ConfigurationException::blankProviderIdentifier($provider::class);
            }

            if (isset($map[$identifier])) {
                throw ConfigurationException::duplicateProviderIdentifier(
                    $identifier,
                    $map[$identifier]::class,
                    $provider::class,
                );
            }

            $map[$identifier] = $provider;
        }

        return $this->byIdentifier = $map;
    }
}
