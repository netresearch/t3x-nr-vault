<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\EventListener;

use Netresearch\NrVault\Configuration\SiteConfigurationVaultProcessor;
use Netresearch\NrVault\Configuration\SiteConfigurationVaultProcessorInterface;
use Netresearch\NrVault\EventListener\SiteConfigurationVaultListener;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Configuration\Event\SiteConfigurationLoadedEvent;

/**
 * Functional tests for SiteConfigurationVaultListener.
 *
 * Tests that vault:// references in site configuration are resolved
 * to their actual secret values via the event listener.
 */
#[CoversClass(SiteConfigurationVaultListener::class)]
#[CoversClass(SiteConfigurationVaultProcessor::class)]
final class SiteConfigurationVaultListenerTest extends AbstractVaultFunctionalTestCase
{
    private const EXAMPLE_BASE_URL = 'https://example.com/';

    private const VAULT_REFERENCE_TEMPLATE = '%%vault(%s)%%';

    private const REASON_TEST_CLEANUP = 'test cleanup';

    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function listenerResolvesVaultReferenceInSiteConfiguration(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = 'site_config_apikey_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'resolved-api-key-value');

        $listener = $this->get(SiteConfigurationVaultListener::class);
        $configuration = [
            'base' => self::EXAMPLE_BASE_URL,
            'apiKey' => \sprintf(self::VAULT_REFERENCE_TEMPLATE, $identifier),
        ];

        $event = new SiteConfigurationLoadedEvent('test-site', $configuration);
        $listener($event);

        $result = $event->getConfiguration();
        self::assertSame('resolved-api-key-value', $result['apiKey']);
        self::assertSame(self::EXAMPLE_BASE_URL, $result['base'], 'Non-vault values must pass through unchanged');

        // Cleanup
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function listenerResolvesNestedVaultReferences(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $identifier = 'site_config_nested_' . bin2hex(random_bytes(4));
        $vaultService->store($identifier, 'nested-secret-value');

        $listener = $this->get(SiteConfigurationVaultListener::class);
        $configuration = [
            'settings' => [
                'payment' => [
                    'apiKey' => \sprintf(self::VAULT_REFERENCE_TEMPLATE, $identifier),
                ],
            ],
        ];

        $event = new SiteConfigurationLoadedEvent('test-site', $configuration);
        $listener($event);

        $result = $event->getConfiguration();
        self::assertSame('nested-secret-value', $result['settings']['payment']['apiKey']);

        // Cleanup
        $vaultService->delete($identifier, self::REASON_TEST_CLEANUP);
    }

    #[Test]
    public function listenerSkipsConfigurationWithNoVaultReferences(): void
    {
        $listener = $this->get(SiteConfigurationVaultListener::class);
        $configuration = [
            'base' => self::EXAMPLE_BASE_URL,
            'settings' => ['debug' => false],
        ];

        $event = new SiteConfigurationLoadedEvent('test-site', $configuration);
        $listener($event);

        self::assertSame($configuration, $event->getConfiguration(), 'Config without vault refs must be unchanged');
    }

    #[Test]
    public function listenerPreservesOriginalWhenVaultRefCannotBeResolved(): void
    {
        $listener = $this->get(SiteConfigurationVaultListener::class);
        $vaultRef = '%vault(nonexistent/secret/identifier)%';
        $configuration = [
            'base' => self::EXAMPLE_BASE_URL,
            'unknownRef' => $vaultRef,
        ];

        $event = new SiteConfigurationLoadedEvent('test-site', $configuration);
        $listener($event);

        $result = $event->getConfiguration();
        // When resolution fails, the original placeholder should be preserved
        self::assertSame($vaultRef, $result['unknownRef'], 'Unresolvable refs must keep original value');
    }

    #[Test]
    public function processorBuildVaultReferenceCreatesCorrectFormat(): void
    {
        $ref = SiteConfigurationVaultProcessor::buildVaultReference('my/secret/id');

        self::assertSame('%vault(my/secret/id)%', $ref);
    }

    #[Test]
    public function processorResolvesMultipleReferencesInSameConfiguration(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $prefix = 'site_config_multi_' . bin2hex(random_bytes(4));
        $id1 = $prefix . '_k1';
        $id2 = $prefix . '_k2';
        $vaultService->store($id1, 'value-one');
        $vaultService->store($id2, 'value-two');

        $processor = $this->get(SiteConfigurationVaultProcessorInterface::class);
        $configuration = [
            'firstKey' => \sprintf(self::VAULT_REFERENCE_TEMPLATE, $id1),
            'secondKey' => \sprintf(self::VAULT_REFERENCE_TEMPLATE, $id2),
            'unchanged' => 'plain-value',
        ];

        $result = $processor->processConfiguration($configuration);

        self::assertSame('value-one', $result['firstKey']);
        self::assertSame('value-two', $result['secondKey']);
        self::assertSame('plain-value', $result['unchanged']);

        // Cleanup
        $vaultService->delete($id1, self::REASON_TEST_CLEANUP);
        $vaultService->delete($id2, self::REASON_TEST_CLEANUP);
    }
}
