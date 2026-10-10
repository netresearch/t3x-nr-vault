<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Crypto\MasterKeyProviderFactory;
use Netresearch\NrVault\Crypto\MasterKeyProviderRegistry;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * Exact fallback precedence in the standard security profile with isolated key sources.
 */
#[CoversClass(MasterKeyProviderFactory::class)]
final class MasterKeyProviderFallbackTest extends TestCase
{
    #[Test]
    public function standardFallbackPrefersTypo3OverAvailableEnvironmentAndFile(): void
    {
        $this->withFallbackSources(
            true,
            true,
            true,
            static function (MasterKeyProviderFactory $factory): void {
                self::assertSame('typo3', $factory->getAvailableProvider()->getIdentifier());
            },
        );
    }

    #[Test]
    public function standardFallbackPrefersEnvironmentOverAnAvailableFile(): void
    {
        $this->withFallbackSources(
            false,
            true,
            true,
            static function (MasterKeyProviderFactory $factory): void {
                self::assertSame('env', $factory->getAvailableProvider()->getIdentifier());
            },
        );
    }

    #[Test]
    public function standardFallbackUsesFileWhenTypo3AndEnvironmentAreUnavailable(): void
    {
        $this->withFallbackSources(
            false,
            false,
            true,
            static function (MasterKeyProviderFactory $factory): void {
                self::assertSame('file', $factory->getAvailableProvider()->getIdentifier());
            },
        );
    }

    #[Test]
    public function standardFallbackReturnsAnUnavailableProviderWhenNoSourceIsAvailable(): void
    {
        $this->withFallbackSources(
            false,
            false,
            false,
            static function (MasterKeyProviderFactory $factory): void {
                $provider = $factory->getAvailableProvider();
                self::assertSame('typo3', $provider->getIdentifier());
                self::assertFalse($provider->isAvailable());
            },
        );
    }

    /**
     * The shared source setting is both an env name and a file path in fallback
     * detection. A virtual URL permits independent availability without using the
     * host filesystem. The environment value is restored even when an assertion fails.
     *
     * @param callable(MasterKeyProviderFactory): void $assertion
     */
    private function withFallbackSources(
        bool $typo3Available,
        bool $envAvailable,
        bool $fileAvailable,
        callable $assertion,
    ): void {
        $root = vfsStream::setup('factory-vault');
        $source = vfsStream::url('factory-vault/master.key');
        $previousValue = getenv($source);
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getMasterKeyProvider')->willReturn('unconfigured');
        $configuration->method('getSecurityProfile')->willReturn(SecurityProfile::Standard);
        $configuration->method('getMasterKeySource')->willReturn($source);
        $configuration
            ->method('getAutoKeyPath')
            ->willReturn(vfsStream::url('factory-vault/missing-auto.key'));

        try {
            $GLOBALS['TYPO3_CONF_VARS']['SYS']['encryptionKey'] = $typo3Available ? bin2hex(random_bytes(48)) : '';
            putenv($source . '=' . ($envAvailable ? base64_encode(random_bytes(32)) : ''));
            if ($fileAvailable) {
                vfsStream::newFile('master.key', 0o600)
                    ->at($root)
                    ->withContent(base64_encode(random_bytes(32)));
            }

            $assertion(
                new MasterKeyProviderFactory($configuration, new MasterKeyProviderRegistry([])),
            );
        } finally {
            putenv($previousValue === false ? $source : $source . '=' . $previousValue);
        }
    }
}
