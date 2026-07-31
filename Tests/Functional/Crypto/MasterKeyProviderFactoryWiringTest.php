<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Crypto;

use Netresearch\NrVault\Crypto\MasterKeyProviderFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use ReflectionProperty;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * The transit provider's HTTP stack must come from the DI container, not from
 * the constructor fallbacks: only the platform client honours the
 * `$TYPO3_CONF_VARS['HTTP']` proxy / TLS / timeout settings the documentation
 * promises. The fallbacks exist for TYPO3 versions that do not alias the PSR-17
 * factories, so a silent fallback here would go unnoticed without this test.
 */
#[CoversClass(MasterKeyProviderFactory::class)]
final class MasterKeyProviderFactoryWiringTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    #[Test]
    public function factoryReceivesThePlatformHttpClientFromTheContainer(): void
    {
        $factory = $this->get(MasterKeyProviderFactory::class);
        self::assertInstanceOf(MasterKeyProviderFactory::class, $factory);

        self::assertSame(
            $this->get(ClientInterface::class),
            (new ReflectionProperty($factory, 'httpClient'))->getValue($factory),
        );
    }

    #[Test]
    public function factoryReceivesThePsr17FactoriesFromTheContainer(): void
    {
        $factory = $this->get(MasterKeyProviderFactory::class);
        self::assertInstanceOf(MasterKeyProviderFactory::class, $factory);

        self::assertSame(
            $this->get(RequestFactoryInterface::class),
            (new ReflectionProperty($factory, 'requestFactory'))->getValue($factory),
        );
        self::assertSame(
            $this->get(StreamFactoryInterface::class),
            (new ReflectionProperty($factory, 'streamFactory'))->getValue($factory),
        );
    }
}
