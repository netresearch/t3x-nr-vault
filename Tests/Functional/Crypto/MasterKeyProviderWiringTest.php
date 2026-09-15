<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Crypto;

use Netresearch\NrVault\Crypto\MasterKeyProviderRegistry;
use Netresearch\NrVault\Crypto\MasterKeyProviderRegistryInterface;
use Netresearch\NrVault\Crypto\TransitMasterKeyProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use ReflectionProperty;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * The container, not a constructor fallback, supplies what the providers need.
 *
 * Two guarantees, both invisible to the unit suite:
 *
 *  - every built-in provider is tagged, so `masterKeyProvider` can select it.
 *    A tag dropped from `Services.yaml` would leave a provider documented and
 *    unreachable, which is exactly the defect this registry closes;
 *  - the transit provider's HTTP stack is the platform one, so the proxy, TLS
 *    and timeout settings from `$TYPO3_CONF_VARS['HTTP']` that the
 *    documentation promises actually apply to the master-key round trip.
 */
#[CoversClass(MasterKeyProviderRegistry::class)]
final class MasterKeyProviderWiringTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    #[Test]
    public function everyBuiltInProviderIsRegisteredUnderItsIdentifier(): void
    {
        $registry = $this->get(MasterKeyProviderRegistryInterface::class);
        self::assertInstanceOf(MasterKeyProviderRegistryInterface::class, $registry);

        // The SET is the contract, not the order: the container emits tagged
        // services in its own order, and nothing may depend on which provider
        // comes first — a registry that resolved by position instead of by
        // identifier is exactly what this design refuses.
        self::assertEqualsCanonicalizing(
            ['typo3', 'file', 'env', 'transit'],
            $registry->getIdentifiers(),
            'A built-in provider lost its nr_vault.master_key_provider tag; it can no longer be configured.',
        );
    }

    #[Test]
    public function theTransitProviderReceivesThePlatformHttpClientFromTheContainer(): void
    {
        $provider = $this->get(MasterKeyProviderRegistryInterface::class)->get('transit');
        self::assertInstanceOf(TransitMasterKeyProvider::class, $provider);

        self::assertSame(
            $this->get(ClientInterface::class),
            (new ReflectionProperty($provider, 'httpClient'))->getValue($provider),
        );
    }

    #[Test]
    public function theTransitProviderReceivesThePsr17FactoriesFromTheContainer(): void
    {
        $provider = $this->get(MasterKeyProviderRegistryInterface::class)->get('transit');
        self::assertInstanceOf(TransitMasterKeyProvider::class, $provider);

        self::assertSame(
            $this->get(RequestFactoryInterface::class),
            (new ReflectionProperty($provider, 'requestFactory'))->getValue($provider),
        );
        self::assertSame(
            $this->get(StreamFactoryInterface::class),
            (new ReflectionProperty($provider, 'streamFactory'))->getValue($provider),
        );
    }
}
