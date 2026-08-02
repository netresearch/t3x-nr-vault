<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use GuzzleHttp\Psr7\HttpFactory;
use Netresearch\NrVault\Configuration\Dto\TransitConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Crypto\EnvironmentMasterKeyProvider;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Crypto\MasterKeyProviderFactory;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Crypto\TransitMasterKeyProvider;
use Netresearch\NrVault\Crypto\Typo3MasterKeyProvider;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Client\ClientInterface;

#[CoversClass(MasterKeyProviderFactory::class)]
#[AllowMockObjectsWithoutExpectations]
final class MasterKeyProviderFactoryTest extends TestCase
{
    private MasterKeyProviderFactory $subject;

    private ExtensionConfigurationInterface&MockObject $configuration;

    protected function setUp(): void
    {
        parent::setUp();

        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->configuration
            ->method('getSecurityProfile')
            ->willReturn(SecurityProfile::Standard);
        $this->subject = new MasterKeyProviderFactory($this->configuration);
    }

    #[Test]
    public function createReturnsFileMasterKeyProviderForFileType(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('file');

        $result = $this->subject->create();

        self::assertInstanceOf(FileMasterKeyProvider::class, $result);
    }

    #[Test]
    public function createReturnsEnvironmentMasterKeyProviderForEnvType(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('env');

        $result = $this->subject->create();

        self::assertInstanceOf(EnvironmentMasterKeyProvider::class, $result);
    }

    #[Test]
    public function createReturnsTypo3MasterKeyProviderForTypo3Type(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('typo3');

        $result = $this->subject->create();

        self::assertInstanceOf(Typo3MasterKeyProvider::class, $result);
    }

    #[Test]
    public function createReturnsTransitMasterKeyProviderForTransitType(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('transit');

        $result = $this->subject->create();

        self::assertInstanceOf(TransitMasterKeyProvider::class, $result);
    }

    #[Test]
    public function createAllowsTransitProviderInHardenedProfile(): void
    {
        // Transit is external-KMS key custody — exactly what the hardened
        // profile asks for, so it must NOT be rejected like the typo3 provider.
        $factory = $this->createHardenedFactory('transit');

        self::assertInstanceOf(TransitMasterKeyProvider::class, $factory->create());
    }

    #[Test]
    public function createPassesTheInjectedHttpStackToTheTransitProvider(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('transit');
        $this->configuration
            ->method('getTransitConfig')
            ->willReturn(new TransitConfig(address: 'https://vault.example.com', wrappedKeyPath: '/nonexistent/wrapped.key'));

        $httpFactory = new HttpFactory();
        // Never dispatched: provider construction alone must not touch the network.
        $client = $this->createMock(ClientInterface::class);
        $client->expects(self::never())->method('sendRequest');

        $factory = new MasterKeyProviderFactory($this->configuration, $client, $httpFactory, $httpFactory);
        $provider = $factory->create();

        self::assertInstanceOf(TransitMasterKeyProvider::class, $provider);
        self::assertFalse($provider->isAvailable());
    }

    #[Test]
    public function createThrowsExceptionForInvalidProvider(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('invalid');

        $this->expectException(ConfigurationException::class);

        $this->subject->create();
    }

    #[Test]
    public function getAvailableProviderReturnsProviderInstance(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('typo3');

        // getAvailableProvider always returns a provider instance
        // The specific type depends on availability, but it's always a MasterKeyProviderInterface
        $result = $this->subject->getAvailableProvider();

        self::assertInstanceOf(MasterKeyProviderInterface::class, $result);
    }

    #[Test]
    public function createThrowsWhenHardenedProfileUsesTypo3Provider(): void
    {
        $factory = $this->createHardenedFactory('typo3');

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1753900002);

        $factory->create();
    }

    #[Test]
    public function getAvailableProviderThrowsWhenHardenedProfileUsesTypo3Provider(): void
    {
        $factory = $this->createHardenedFactory('typo3');

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1753900002);

        $factory->getAvailableProvider();
    }

    #[Test]
    public function getAvailableProviderThrowsWhenHardenedProfileUsesUnknownProvider(): void
    {
        // Hardened: no auto-detection may paper over an invalid provider name.
        $factory = $this->createHardenedFactory('invalid');

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1703800015);

        $factory->getAvailableProvider();
    }

    #[Test]
    public function getAvailableProviderDoesNotFallBackWhenHardenedProviderIsUnavailable(): void
    {
        // The configured file provider points at a nonexistent key file. In the
        // hardened profile the factory must still return THAT provider (whose
        // getMasterKey() fails loudly) — never a typo3/env substitute.
        $factory = $this->createHardenedFactory('file');

        $result = $factory->getAvailableProvider();

        self::assertInstanceOf(FileMasterKeyProvider::class, $result);
        self::assertFalse($result->isAvailable());
    }

    #[Test]
    public function createAllowsFileProviderInHardenedProfile(): void
    {
        $factory = $this->createHardenedFactory('file');

        self::assertInstanceOf(FileMasterKeyProvider::class, $factory->create());
    }

    #[Test]
    public function createAllowsEnvProviderInHardenedProfile(): void
    {
        $factory = $this->createHardenedFactory('env');

        self::assertInstanceOf(EnvironmentMasterKeyProvider::class, $factory->create());
    }

    #[Test]
    public function createAllowsTypo3ProviderInStandardProfile(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('typo3');

        self::assertInstanceOf(Typo3MasterKeyProvider::class, $this->subject->create());
    }

    /**
     * Build a factory whose configuration uses the hardened profile.
     */
    private function createHardenedFactory(string $provider): MasterKeyProviderFactory
    {
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration
            ->method('getSecurityProfile')
            ->willReturn(SecurityProfile::Hardened);
        $configuration
            ->method('getMasterKeyProvider')
            ->willReturn($provider);
        $configuration
            ->method('getMasterKeySource')
            ->willReturn('/nonexistent/hardened-test.key');

        return new MasterKeyProviderFactory($configuration);
    }
}
