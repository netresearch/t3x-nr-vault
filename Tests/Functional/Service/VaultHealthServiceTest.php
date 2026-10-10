<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Crypto\MasterKeyProviderFactoryInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Crypto\Typo3MasterKeyProvider;
use Netresearch\NrVault\Exception\MasterKeyException;
use Netresearch\NrVault\Service\VaultHealthService;
use Netresearch\NrVault\Service\VaultHealthServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * The read-only health status must describe the provider used by the real
 * encryption dependency, including when an unrelated fallback is healthy.
 */
#[CoversClass(VaultHealthService::class)]
final class VaultHealthServiceTest extends AbstractVaultFunctionalTestCase
{
    protected ?int $backendUserUid = null;

    protected array $extensionConfiguration = ['masterKeyProvider' => 'file', 'securityProfile' => 'standard'];

    protected function setUp(): void
    {
        parent::setUp();
        Typo3MasterKeyProvider::clearCachedKey();
        $configuration = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($configuration);
        $system = $configuration['SYS'] ?? [];
        self::assertIsArray($system);
        $system['encryptionKey'] = bin2hex(random_bytes(48));
        $configuration['SYS'] = $system;
        $GLOBALS['TYPO3_CONF_VARS'] = $configuration;
    }

    protected function tearDown(): void
    {
        Typo3MasterKeyProvider::clearCachedKey();
        parent::tearDown();
    }

    #[Test]
    public function unavailableConfiguredFileIsUnhealthyEvenWithAHealthyTypo3Fallback(): void
    {
        $this->configureVault(
            ['masterKeySource' => $this->instancePath . '/missing-configured.key'],
        );
        $this->configureVault(['autoKeyPath' => $this->instancePath . '/missing-auto.key']);

        $factory = $this->get(MasterKeyProviderFactoryInterface::class);
        $configured = $this->get(MasterKeyProviderInterface::class);
        self::assertSame('file', $configured->getIdentifier());
        self::assertFalse($configured->isAvailable());
        self::assertSame('typo3', $factory->getAvailableProvider()->getIdentifier());

        $status = $this->get(VaultHealthServiceInterface::class)->checkHealth();
        self::assertSame('file', $status->masterKeyProvider);
        self::assertFalse($status->masterKeyAvailable);
        self::assertFalse($status->encryptionWorking);
        self::assertTrue($status->hasIssues);

        $this->expectException(MasterKeyException::class);
        $configured->getMasterKey();
    }

    #[Test]
    public function readableConfiguredFileReportsTheSameProviderUsedByEncryption(): void
    {
        $configured = $this->get(MasterKeyProviderInterface::class);
        self::assertSame('file', $configured->getIdentifier());
        self::assertTrue($configured->isAvailable());
        self::assertSame(32, \strlen($configured->getMasterKey()));

        $status = $this->get(VaultHealthServiceInterface::class)->checkHealth();
        self::assertSame('file', $status->masterKeyProvider);
        self::assertTrue($status->masterKeyAvailable);
        self::assertTrue($status->encryptionWorking);
        self::assertFalse($status->hasIssues);
    }

    #[Test]
    public function invalidConfiguredProviderIsUnhealthyEvenWithAHealthyTypo3Fallback(): void
    {
        $this->configureVault(['masterKeyProvider' => 'missing_provider']);

        $factory = $this->get(MasterKeyProviderFactoryInterface::class);
        self::assertSame('typo3', $factory->getAvailableProvider()->getIdentifier());

        $status = $this->get(VaultHealthServiceInterface::class)->checkHealth();
        self::assertSame('', $status->masterKeyProvider);
        self::assertFalse($status->masterKeyAvailable);
        self::assertFalse($status->encryptionWorking);
        self::assertTrue($status->hasIssues);
    }

    /**
     * Change only the requested settings after validating the real TYPO3 fixture.
     *
     * @param array<string, mixed> $settings
     */
    private function configureVault(array $settings): void
    {
        $configuration = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($configuration);
        $extensions = $configuration['EXTENSIONS'] ?? [];
        self::assertIsArray($extensions);
        $vault = $extensions['nr_vault'] ?? [];
        self::assertIsArray($vault);
        $extensions['nr_vault'] = array_replace($vault, $settings);
        $configuration['EXTENSIONS'] = $extensions;
        $GLOBALS['TYPO3_CONF_VARS'] = $configuration;
    }
}
