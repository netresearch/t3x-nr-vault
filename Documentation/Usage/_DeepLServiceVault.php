<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace MyVendor\MyDeeplExtension\Service;

use Netresearch\NrVault\Configuration\VaultReference;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Service\VaultServiceInterface;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Http\RequestFactory;

final class DeepLService
{
    private const API_URL = 'https://api-free.deepl.com/v2';

    private ?VaultReference $apiKeyRef = null;

    public function __construct(
        private readonly VaultServiceInterface $vault,
        private readonly RequestFactory $requestFactory,
        ExtensionConfiguration $extensionConfiguration,
    ) {
        $config = $extensionConfiguration->get('my_deepl_extension');
        $setting = (string) ($config['deeplApiKey'] ?? '');

        // Parse vault reference (validates format, extracts identifier)
        $this->apiKeyRef = VaultReference::tryParse($setting);
    }

    public function translate(string $text, string $targetLang): string
    {
        if ($this->apiKeyRef === null) {
            throw new \RuntimeException(
                'DeepL API key not configured. Enter vault:your-secret-id in extension settings.',
                1735900000
            );
        }

        $request = $this->requestFactory->createRequest('POST', self::API_URL . '/translate')
            ->withHeader('Content-Type', 'application/json')
            ->withBody(\GuzzleHttp\Psr7\Utils::streamFor(json_encode([
                'text' => [$text],
                'target_lang' => $targetLang,
            ])));

        // Secret resolved at use time, not config load time.
        // DeepL uses the "Authorization: DeepL-Auth-Key <key>" scheme (not Bearer),
        // expressed via the Header placement + prefix option.
        $response = $this->vault->http()
            ->withAuthentication(
                $this->apiKeyRef->identifier,
                SecretPlacement::Header,
                ['headerName' => 'Authorization', 'prefix' => 'DeepL-Auth-Key '],
            )
            ->withReason('DeepL translation request')
            ->sendRequest($request);

        $data = json_decode($response->getBody()->getContents(), true);
        return $data['translations'][0]['text'] ?? '';
    }
}
