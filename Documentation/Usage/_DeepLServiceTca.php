<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace MyVendor\MyDeeplExtension\Service;

use RuntimeException;
use GuzzleHttp\Psr7\Utils;
use MyVendor\MyDeeplExtension\Domain\Repository\ConfigRepository;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Service\VaultServiceInterface;
use TYPO3\CMS\Core\Http\RequestFactory;

final readonly class DeepLService
{
    public function __construct(
        private VaultServiceInterface $vault,
        private RequestFactory $requestFactory,
        private ConfigRepository $configRepository,
    ) {}

    public function translate(string $text, string $targetLang): string
    {
        $config = $this->configRepository->findDefault();
        if ($config === null) {
            throw new RuntimeException('DeepL not configured', 1735900001);
        }

        $request = $this->requestFactory
            ->createRequest('POST', $config->apiUrl . '/translate')
            ->withHeader('Content-Type', 'application/json')
            ->withBody(Utils::streamFor(json_encode([
                'text' => [$text],
                'target_lang' => $targetLang,
            ])));

        $response = $this->vault
            ->http()
            ->withAuthentication(
                $config->apiKey,
                SecretPlacement::Header,
                ['headerName' => 'Authorization', 'prefix' => 'DeepL-Auth-Key ']
            )
            ->withReason('DeepL translation: ' . $targetLang)
            ->sendRequest($request);

        $data = json_decode($response->getBody()->getContents(), true);
        return $data['translations'][0]['text'] ?? '';
    }
}
