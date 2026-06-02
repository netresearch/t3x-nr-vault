<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Configuration;

use Netresearch\NrVault\Configuration\SiteConfigurationVaultProcessor;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Site\Entity\Site;

#[CoversClass(SiteConfigurationVaultProcessor::class)]
#[AllowMockObjectsWithoutExpectations]
final class SiteConfigurationVaultProcessorTest extends TestCase
{
    private const VAULT_PLACEHOLDER = '%vault(my_key)%';

    private VaultServiceInterface&MockObject $vaultService;

    private LoggerInterface&MockObject $logger;

    private SiteConfigurationVaultProcessor $processor;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);

        $this->processor = new SiteConfigurationVaultProcessor(
            $this->vaultService,
            $this->logger,
        );
    }

    #[Test]
    public function processConfigurationReturnsUnchangedConfigWithoutVaultReferences(): void
    {
        $config = [
            'base' => 'https://example.com',
            'languages' => [],
            'settings' => [
                'key' => 'value',
            ],
        ];

        $result = $this->processor->processConfiguration($config);

        self::assertSame($config, $result);
    }

    #[Test]
    public function processConfigurationResolvesVaultReferences(): void
    {
        $config = [
            'apiKey' => '%vault(my_api_key)%',
        ];

        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('secret_value');

        $result = $this->processor->processConfiguration($config);

        self::assertSame('secret_value', $result['apiKey']);
    }

    #[Test]
    public function processConfigurationHandlesNestedVaultReferences(): void
    {
        $config = [
            'settings' => [
                'payment' => [
                    'apiKey' => '%vault(payment_key)%',
                    'secret' => '%vault(payment_secret)%',
                ],
            ],
        ];

        $this->vaultService
            ->method('retrieve')
            ->willReturnMap([
                ['payment_key', 'key123'],
                ['payment_secret', 'secret456'],
            ]);

        $result = $this->processor->processConfiguration($config);

        self::assertSame('key123', $result['settings']['payment']['apiKey']);
        self::assertSame('secret456', $result['settings']['payment']['secret']);
    }

    #[Test]
    public function processConfigurationPreservesNonVaultValues(): void
    {
        $config = [
            'apiKey' => self::VAULT_PLACEHOLDER,
            'regularValue' => 'not_a_vault_reference',
            'numericValue' => 42,
            'booleanValue' => true,
        ];

        $this->vaultService
            ->method('retrieve')
            ->with('my_key')
            ->willReturn('resolved');

        $result = $this->processor->processConfiguration($config);

        self::assertSame('resolved', $result['apiKey']);
        self::assertSame('not_a_vault_reference', $result['regularValue']);
        self::assertSame(42, $result['numericValue']);
        self::assertTrue($result['booleanValue']);
    }

    #[Test]
    public function processValueResolvesVaultReference(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_secret')
            ->willReturn('secret_value');

        $result = $this->processor->processValue('%vault(my_secret)%');

        self::assertSame('secret_value', $result);
    }

    #[Test]
    public function processValueReturnsOriginalForNonVaultValues(): void
    {
        $result = $this->processor->processValue('regular_string');

        self::assertSame('regular_string', $result);
    }

    #[Test]
    public function processValueReturnsNonStringsUnchanged(): void
    {
        self::assertSame(42, $this->processor->processValue(42));
        self::assertTrue($this->processor->processValue(true));
        self::assertSame(['array'], $this->processor->processValue(['array']));
    }

    #[Test]
    public function isVaultReferenceReturnsTrueForValidReferences(): void
    {
        self::assertTrue($this->processor->isVaultReference(self::VAULT_PLACEHOLDER));
        self::assertTrue($this->processor->isVaultReference('%vault(some_long_identifier_123)%'));
    }

    #[Test]
    public function isVaultReferenceReturnsFalseForInvalidReferences(): void
    {
        self::assertFalse($this->processor->isVaultReference('regular_string'));
        self::assertFalse($this->processor->isVaultReference(''));
        self::assertFalse($this->processor->isVaultReference('%vault%'));
        self::assertFalse($this->processor->isVaultReference('vault(key)'));
        self::assertFalse($this->processor->isVaultReference(42));
    }

    #[Test]
    public function buildVaultReferenceCreatesCorrectFormat(): void
    {
        $result = SiteConfigurationVaultProcessor::buildVaultReference('my_identifier');

        self::assertSame('%vault(my_identifier)%', $result);
    }

    #[Test]
    public function extractIdentifierReturnsIdentifier(): void
    {
        $result = $this->processor->extractIdentifier(self::VAULT_PLACEHOLDER);

        self::assertSame('my_key', $result);
    }

    #[Test]
    public function extractIdentifierReturnsNullForInvalidReference(): void
    {
        $result = $this->processor->extractIdentifier('not_a_reference');

        self::assertNull($result);
    }

    #[Test]
    public function processConfigurationLogsWarningOnRetrievalFailure(): void
    {
        $config = [
            'apiKey' => '%vault(failing_key)%',
        ];

        $this->vaultService
            ->method('retrieve')
            ->willThrowException(new VaultException('Not found'));

        $this->logger
            ->expects($this->once())
            ->method('warning')
            ->with('Failed to resolve vault reference', $this->anything());

        $result = $this->processor->processConfiguration($config);

        // Should return original value on failure
        self::assertSame('%vault(failing_key)%', $result['apiKey']);
    }

    #[Test]
    public function processConfigurationTriesSiteSpecificIdentifierFirst(): void
    {
        $site = $this->createMock(Site::class);
        $site->method('getIdentifier')->willReturn('main');

        $config = [
            'apiKey' => '%vault(api_key)%',
        ];

        // Site-specific does not exist, so falls through to global
        $this->vaultService
            ->method('exists')
            ->with('site:main:api_key')
            ->willReturn(false);

        $this->vaultService
            ->expects($this->once())
            ->method('retrieve')
            ->with('api_key')
            ->willReturn('global_value');

        $result = $this->processor->processConfiguration($config, $site);

        self::assertSame('global_value', $result['apiKey']);
    }

    #[Test]
    public function processConfigurationUsesSiteSpecificIdentifierIfFound(): void
    {
        $site = $this->createMock(Site::class);
        $site->method('getIdentifier')->willReturn('main');

        $config = [
            'apiKey' => '%vault(api_key)%',
        ];

        $this->vaultService
            ->method('exists')
            ->with('site:main:api_key')
            ->willReturn(true);

        $this->vaultService
            ->method('retrieve')
            ->with('site:main:api_key')
            ->willReturn('site_specific_value');

        $result = $this->processor->processConfiguration($config, $site);

        self::assertSame('site_specific_value', $result['apiKey']);
    }

    #[Test]
    #[DataProvider('vaultReferencePatternProvider')]
    public function handlesVariousVaultReferencePatterns(string $input, string $expectedIdentifier): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with($expectedIdentifier)
            ->willReturn('resolved');

        $result = $this->processor->processValue($input);

        self::assertSame('resolved', $result);
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function vaultReferencePatternProvider(): array
    {
        return [
            'simple identifier' => ['%vault(key)%', 'key'],
            'underscore identifier' => ['%vault(my_api_key)%', 'my_api_key'],
            'alphanumeric identifier' => ['%vault(key123)%', 'key123'],
            'colon identifier' => ['%vault(site:main:key)%', 'site:main:key'],
        ];
    }
}
