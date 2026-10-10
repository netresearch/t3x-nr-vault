<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Documentation;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use MyVendor\MyDeeplExtension\Service\DeepLService;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\VaultHttpClientInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\RequestInterface;
use RuntimeException;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;

#[CoversNothing]
final class ExtensionSettingsExampleTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__ . '/../../../Documentation/Usage/_DeepLServiceVault.php';
    }

    #[Test]
    public function documentedServiceBuildsADeepLRequestUsingTheConfiguredVaultIdentifier(): void
    {
        $configuration = $this->createMock(ExtensionConfiguration::class);
        $configuration
            ->expects(self::once())
            ->method('get')
            ->with('my_deepl_extension')
            ->willReturn(['deeplApiKey' => 'deepl_api_key']);
        $http = $this->createMock(VaultHttpClientInterface::class);
        $http
            ->expects(self::once())
            ->method('withAuthentication')
            ->with('deepl_api_key', SecretPlacement::Header, ['headerName' => 'Authorization', 'prefix' => 'DeepL-Auth-Key '])
            ->willReturnSelf();
        $http->expects(self::once())->method('withReason')->with('DeepL translation request')->willReturnSelf();
        $http
            ->expects(self::once())
            ->method('sendRequest')
            ->with(
                self::callback(
                    static function (RequestInterface $request): bool {
                        self::assertSame('POST', $request->getMethod());
                        self::assertSame('https://api-free.deepl.com/v2/translate', (string) $request->getUri());
                        self::assertSame('application/json', $request->getHeaderLine('Content-Type'));
                        self::assertSame(
                            ['text' => ['Hello'], 'target_lang' => 'DE'],
                            json_decode((string) $request->getBody(), true, 512, JSON_THROW_ON_ERROR),
                        );
                        self::assertFalse($request->hasHeader('Authorization'));

                        return true;
                    },
                ),
            )
            ->willReturn(new Response(200, [], '{"translations":[{"text":"Hallo"}]}'));
        $vault = $this->createMock(VaultServiceInterface::class);
        $vault->expects(self::once())->method('http')->willReturn($http);
        $service = new DeepLService($vault, new HttpFactory(), $configuration);

        self::assertSame('Hallo', $service->translate('Hello', 'DE'));
    }

    #[Test]
    public function missingIdentifierFailsBeforeRequestingTheHttpClient(): void
    {
        $configuration = $this->createMock(ExtensionConfiguration::class);
        $configuration->expects(self::once())->method('get')->willReturn([]);
        $vault = $this->createMock(VaultServiceInterface::class);
        $vault->expects(self::never())->method('http');
        $service = new DeepLService($vault, new HttpFactory(), $configuration);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageToContain('DeepL API key not configured.');
        $service->translate('Hello', 'DE');
    }
}
