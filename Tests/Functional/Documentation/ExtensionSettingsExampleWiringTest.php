<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Documentation;

use MyVendor\MyDeeplExtension\Service\DeepLService;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use Throwable;

#[CoversNothing]
final class ExtensionSettingsExampleWiringTest extends AbstractVaultFunctionalTestCase
{
    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/nr_vault_documentation_fixture',
    ];

    protected ?int $backendUserUid = null;

    #[Test]
    public function literalServiceRegistrationAutowiresFromTheRealTypo3Container(): void
    {
        $configuration = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($configuration);
        $extensions = $configuration['EXTENSIONS'] ?? [];
        self::assertIsArray($extensions);
        $extensions['my_deepl_extension'] = ['deeplApiKey' => ''];
        $configuration['EXTENSIONS'] = $extensions;
        $GLOBALS['TYPO3_CONF_VARS'] = $configuration;
        $service = $this->get(DeepLService::class);
        self::assertInstanceOf(DeepLService::class, $service);

        $failure = null;

        try {
            $service->translate('Hello', 'DE');
        } catch (Throwable $caught) {
            $failure = $caught;
        }

        self::assertInstanceOf(RuntimeException::class, $failure);
        self::assertSame(
            'DeepL API key not configured. Enter your secret identifier in extension settings.',
            $failure->getMessage(),
        );
        self::assertSame(1735900000, $failure->getCode());

        $factory = $this->get(RequestFactoryInterface::class);
        self::assertInstanceOf(RequestFactoryInterface::class, $factory);
        $request = $factory->createRequest(
            'POST',
            'https://api-free.deepl.com/v2/translate',
        );
        self::assertSame('POST', $request->getMethod());
        self::assertSame(
            'https://api-free.deepl.com/v2/translate',
            (string) $request->getUri(),
        );
    }
}
