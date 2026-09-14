<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Service;

use Netresearch\NrVault\Http\CancellableHttpClientInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Http\PresetCancellationSignal;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use SensitiveParameter;

/**
 * Consumer-side use of the documented calling API: keep an API token in the
 * vault, read it back, and send an authenticated request through the vault
 * HTTP client with a caller-owned cancellation signal.
 */
final readonly class ApiTokenClient
{
    public function __construct(
        private VaultServiceInterface $vaultService,
        private RequestFactoryInterface $requestFactory,
    ) {}

    public function storeToken(string $identifier, #[SensitiveParameter] string $token): void
    {
        $this->vaultService->store($identifier, $token, [
            'context' => 'consumer_fixture',
            'description' => 'API token kept by the consumer fixture',
        ]);
    }

    public function readToken(string $identifier): ?string
    {
        return $this->vaultService->retrieve($identifier);
    }

    public function call(string $identifier, string $url, bool $cancelled): ResponseInterface
    {
        $client = $this->vaultService->http()
            ->withAuthentication($identifier)
            ->withReason('consumer fixture API call');
        $request = $this->requestFactory->createRequest('GET', $url);

        return $client instanceof CancellableHttpClientInterface && $client->supportsCancellation()
            ? $client->sendCancellable($request, new PresetCancellationSignal($cancelled))
            : $client->sendRequest($request);
    }
}
