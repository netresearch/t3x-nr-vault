<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Configuration;

use Netresearch\NrVault\Configuration\ExtensionConfiguration;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration as Typo3ExtensionConfiguration;
use TYPO3\CMS\Core\Core\Environment;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

#[CoversClass(ExtensionConfiguration::class)]
#[AllowMockObjectsWithoutExpectations]
final class ExtensionConfigurationTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    #[Test]
    public function getAutoKeyPathReturnsPathBasedOnVarPath(): void
    {
        $config = new ExtensionConfiguration($this->createConfigurationReturning([]));

        $path = $config->getAutoKeyPath();

        self::assertStringContainsString('secrets/vault-master.key', $path);
        self::assertStringStartsWith(Environment::getVarPath(), $path);
    }

    #[Test]
    public function getTransitConfigDefaultsTheWrappedKeyPathToTheVarPath(): void
    {
        // The default resolves through Environment, which is only initialized in
        // the functional suite; the unit test asserts it stays lazy.
        $config = new ExtensionConfiguration(
            $this->createConfigurationReturning(['hashicorp' => ['address' => 'https://vault.example.com:8200']]),
        );

        $transitConfig = $config->getTransitConfig();

        self::assertSame($config->getAutoKeyPath() . '.transit', $transitConfig->wrappedKeyPath);
        self::assertStringContainsString(Environment::getVarPath(), $transitConfig->wrappedKeyPath);
        self::assertTrue($transitConfig->isComplete());
    }

    #[Test]
    public function getTransitConfigToleratesANonArrayHashicorpSetting(): void
    {
        $config = new ExtensionConfiguration($this->createConfigurationReturning(['hashicorp' => 'not-an-array']));

        $transitConfig = $config->getTransitConfig();

        self::assertSame('', $transitConfig->address);
        self::assertSame('transit', $transitConfig->mount);
        self::assertFalse($transitConfig->isComplete());
    }

    /**
     * @param array<string, mixed> $configuration
     */
    private function createConfigurationReturning(array $configuration): Typo3ExtensionConfiguration
    {
        $typo3Config = $this->createMock(Typo3ExtensionConfiguration::class);
        $typo3Config->method('get')
            ->with('nr_vault')
            ->willReturn($configuration);

        return $typo3Config;
    }
}
