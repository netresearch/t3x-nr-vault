<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use GuzzleHttp\Psr7\HttpFactory;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Crypto\EnvironmentMasterKeyProvider;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Crypto\MasterKeyProviderFactory;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderRegistry;
use Netresearch\NrVault\Crypto\TransitMasterKeyProvider;
use Netresearch\NrVault\Crypto\Typo3MasterKeyProvider;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Client\ClientInterface;
use SensitiveParameter;

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
        $this->subject = new MasterKeyProviderFactory(
            $this->configuration,
            $this->createBuiltInRegistry($this->configuration),
        );
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
    public function createReturnsTheRegisteredProviderInstanceItself(): void
    {
        // The factory selects, it no longer constructs: the transit provider's
        // HTTP stack is injected into the provider by the container, so what
        // comes back must be the registered instance rather than a new one.
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('transit');

        $transit = new TransitMasterKeyProvider(
            $this->configuration,
            self::createStub(ClientInterface::class),
            new HttpFactory(),
            new HttpFactory(),
        );
        $factory = new MasterKeyProviderFactory(
            $this->configuration,
            new MasterKeyProviderRegistry([$transit]),
        );

        self::assertSame($transit, $factory->create());
    }

    #[Test]
    public function createThrowsExceptionForInvalidProvider(): void
    {
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('invalid');

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1703800015);

        $this->subject->create();
    }

    #[Test]
    public function createSelectsAProviderRegisteredByAnotherExtension(): void
    {
        // The defect this PR closes: before the registry, an identifier outside
        // the built-in four could never be selected, however it was registered.
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('acme_kms');

        $custom = $this->customProvider('acme_kms');
        $factory = new MasterKeyProviderFactory(
            $this->configuration,
            new MasterKeyProviderRegistry([new Typo3MasterKeyProvider(), $custom]),
        );

        self::assertSame($custom, $factory->create());
    }

    #[Test]
    public function createAllowsACustomProviderInHardenedProfile(): void
    {
        // The hardened profile's demand is that the key lives outside
        // settings.php. An extension-supplied provider is the case it asks for,
        // so the deny list names `typo3` and nothing else.
        $configuration = $this->hardenedConfiguration('acme_kms');
        $custom = $this->customProvider('acme_kms');

        $factory = new MasterKeyProviderFactory(
            $configuration,
            new MasterKeyProviderRegistry([new Typo3MasterKeyProvider(), $custom]),
        );

        self::assertSame($custom, $factory->create());
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
    public function getAvailableProviderRefusesAnAmbiguousRegistryInsteadOfFallingBack(): void
    {
        // The fallback chain swallows ConfigurationException to survive an
        // unconfigured install. A duplicate identifier must not be swallowed
        // with it: silently auto-detecting would answer "which key source
        // protects the vault?" by load order.
        $this->configuration
            ->method('getMasterKeyProvider')
            ->willReturn('file');

        $factory = new MasterKeyProviderFactory(
            $this->configuration,
            new MasterKeyProviderRegistry([
                new FileMasterKeyProvider($this->configuration),
                $this->customProvider('file'),
            ]),
        );

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionCode(1789430001);

        $factory->getAvailableProvider();
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
        $configuration = $this->hardenedConfiguration($provider);

        return new MasterKeyProviderFactory($configuration, $this->createBuiltInRegistry($configuration));
    }

    private function hardenedConfiguration(string $provider): ExtensionConfigurationInterface&MockObject
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

        return $configuration;
    }

    /**
     * The four built-in providers, registered exactly as `Services.yaml` tags
     * them, so the unit tests exercise the production registration set.
     */
    private function createBuiltInRegistry(ExtensionConfigurationInterface $configuration): MasterKeyProviderRegistry
    {
        $httpFactory = new HttpFactory();

        return new MasterKeyProviderRegistry([
            new Typo3MasterKeyProvider(),
            new FileMasterKeyProvider($configuration),
            new EnvironmentMasterKeyProvider($configuration),
            new TransitMasterKeyProvider(
                $configuration,
                self::createStub(ClientInterface::class),
                $httpFactory,
                $httpFactory,
            ),
        ]);
    }

    /**
     * A provider as a consuming extension writes one: against the published
     * interface, with an identifier of its own choosing.
     */
    private function customProvider(string $identifier): MasterKeyProviderInterface
    {
        return new class ($identifier) implements MasterKeyProviderInterface {
            public function __construct(private readonly string $identifier) {}

            public function getIdentifier(): string
            {
                return $this->identifier;
            }

            public function isAvailable(): bool
            {
                return true;
            }

            public function getMasterKey(): string
            {
                return str_repeat('k', 32);
            }

            public function storeMasterKey(#[SensitiveParameter] string $key): void {}

            public function generateMasterKey(): string
            {
                return str_repeat('n', 32);
            }

            public static function clearCachedKey(): void {}
        };
    }
}
