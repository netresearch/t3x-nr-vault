<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\HashiCorp;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\HashiCorpException;

use function is_array;

/**
 * KV v2 client for the HashiCorp Vault storage adapter.
 *
 * A request rejected with 403 under a login-based auth method is retried once
 * with a fresh login, because the token may have been revoked or may have
 * expired between two calls in a long-running process. Under the plain token
 * method a 403 is final: there is no other token to try.
 */
final readonly class HashiCorpKvClient implements AtomicKvStoreInterface
{
    public function __construct(
        private ExtensionConfigurationInterface $configuration,
        private HashiCorpHttp $http,
        private HashiCorpAuthenticator $authenticator,
    ) {}

    public function read(string $identifier): ?array
    {
        $url    = $this->endpoint()->dataUrl($identifier);
        $result = $this->send('GET', $url, null, 'read');

        if ($result['status'] === 404) {
            return null;
        }

        $this->assertSuccess($result['status'], 'read');

        $outer = $result['json']['data'] ?? null;
        $data  = is_array($outer) ? ($outer['data'] ?? null) : null;
        if (!is_array($data)) {
            throw HashiCorpException::malformedResponse('read', 'response has no "data.data" object');
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    public function write(string $identifier, array $data): void
    {
        $url    = $this->endpoint()->dataUrl($identifier);
        $result = $this->send('POST', $url, ['data' => $data], 'write');

        $this->assertSuccess($result['status'], 'write');
    }

    public function create(string $identifier, array $data): void
    {
        $url    = $this->endpoint()->dataUrl($identifier);
        $result = $this->send('POST', $url, ['options' => ['cas' => 0], 'data' => $data], 'create');

        // Vault answers a check-and-set mismatch with 400. Only a key that is
        // there explains it; any other 400 is an ordinary rejection.
        if ($result['status'] === 400 && $this->read($identifier) !== null) {
            throw HashiCorpException::keyExists($identifier);
        }

        $this->assertSuccess($result['status'], 'create');
    }

    public function destroy(string $identifier): void
    {
        $url    = $this->endpoint()->metadataUrl($identifier);
        $result = $this->send('DELETE', $url, null, 'delete');

        // Vault answers 204 whether or not the key existed; 404 is accepted
        // too so a repeated delete after a half-finished one succeeds.
        if ($result['status'] === 404) {
            return;
        }

        $this->assertSuccess($result['status'], 'delete');
    }

    public function reference(string $identifier): string
    {
        return $this->endpoint()->reference($identifier);
    }

    private function endpoint(): HashiCorpEndpoint
    {
        return HashiCorpEndpoint::fromConfig($this->configuration->getHashiCorpConfig());
    }

    /**
     * @param array<string, mixed>|null $body
     *
     * @return array{status: int, json: array<array-key, mixed>}
     */
    private function send(string $method, string $url, ?array $body, string $operation): array
    {
        $result = $this->http->request($method, $url, $this->authenticator->token(), $body, $operation);

        if ($result['status'] === 403 && $this->authenticator->canRefresh()) {
            $this->authenticator->invalidate();
            $result = $this->http->request($method, $url, $this->authenticator->token(), $body, $operation);
        }

        return $result;
    }

    private function assertSuccess(int $status, string $operation): void
    {
        if ($status < 200 || $status >= 300) {
            throw HashiCorpException::requestRejected($operation, $status);
        }
    }
}
