<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Crypto;

use Netresearch\NrVault\Crypto\EncryptionService;
use Netresearch\NrVault\Crypto\EnvelopeCodecInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderRegistry;
use Netresearch\NrVault\Crypto\MasterKeyProviderRegistryInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Fixtures\CustomKms\CustomKmsMasterKeyProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;

/**
 * The `#[ExtensionPoint]` on `MasterKeyProviderInterface`, exercised from
 * outside the package.
 *
 * `EXT:vault_custom_provider` is a fixture extension that does nothing but tag
 * a provider of its own in its `Configuration/Services.yaml`. Nothing in
 * nr-vault names that class or its identifier; the only connection is the
 * `masterKeyProvider` setting. Before the registry this could not work — the
 * factory matched a closed list of four identifiers and threw on anything else
 * — so these tests are the ones that would have caught the defect.
 */
#[CoversClass(MasterKeyProviderRegistry::class)]
final class CustomMasterKeyProviderTest extends AbstractVaultFunctionalTestCase
{
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/vault_custom_provider',
    ];

    /**
     * The whole configuration a third-party provider needs: its identifier.
     *
     * @var array<string, mixed>
     */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => CustomKmsMasterKeyProvider::IDENTIFIER,
    ];

    /** No backend user is involved in resolving a key source. */
    protected ?int $backendUserUid = null;

    protected function tearDown(): void
    {
        // The fixture inherits AbstractMasterKeyProvider's request-lifetime
        // cache, so it owns a slot the base class does not know about.
        CustomKmsMasterKeyProvider::clearCachedKey();

        parent::tearDown();
    }

    #[Test]
    public function theConfiguredThirdPartyIdentifierSelectsTheThirdPartyProvider(): void
    {
        $provider = $this->get(MasterKeyProviderInterface::class);

        self::assertInstanceOf(CustomKmsMasterKeyProvider::class, $provider);
        self::assertSame('acme_kms', $provider->getIdentifier());
    }

    #[Test]
    public function theRegistryListsTheThirdPartyProviderAlongsideTheBuiltIns(): void
    {
        $identifiers = $this->get(MasterKeyProviderRegistryInterface::class)->getIdentifiers();

        self::assertContains('acme_kms', $identifiers);
        self::assertContains('typo3', $identifiers);
        self::assertContains('file', $identifiers);
        self::assertContains('env', $identifiers);
        self::assertContains('transit', $identifiers);
    }

    #[Test]
    public function theThirdPartyProviderSuppliesTheMasterKeyTheCryptoBoundaryUses(): void
    {
        // Decisive rather than circumstantial: the provider instance the
        // encryption service holds IS the third-party one, so the key below is
        // the key every envelope in this request is wrapped with.
        $encryptionService = $this->get(EncryptionService::class);
        $provider = (new ReflectionProperty($encryptionService, 'masterKeyProvider'))->getValue($encryptionService);

        self::assertInstanceOf(CustomKmsMasterKeyProvider::class, $provider);
        self::assertSame(CustomKmsMasterKeyProvider::expectedKey(), $provider->getMasterKey());
    }

    #[Test]
    public function anEnvelopeSealedUnderTheThirdPartyKeyOpensAgain(): void
    {
        $codec = $this->get(EnvelopeCodecInterface::class);
        $plaintext = 'value protected by a third-party key source';

        $sealed = $codec->seal($plaintext, 'custom-provider-round-trip');

        self::assertTrue($codec->isSealed($sealed));
        self::assertSame($plaintext, $codec->open($sealed, 'custom-provider-round-trip'));
    }
}
