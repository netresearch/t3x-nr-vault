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
use function is_int;

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
    private const VERSION_READ_ATTEMPTS = 3;

    private const VERSION_READ_DELAY_MICROSECONDS = 150_000;

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

    public function create(string $identifier, array $data): int
    {
        $url    = $this->endpoint()->dataUrl($identifier);
        $result = $this->send('POST', $url, ['options' => ['cas' => 0], 'data' => $data], 'create');

        // Vault answers a check-and-set mismatch with 400. Only a key that is
        // there explains it; any other 400 is an ordinary rejection.
        if ($result['status'] === 400 && $this->read($identifier) !== null) {
            throw HashiCorpException::keyExists($identifier);
        }

        $this->assertSuccess($result['status'], 'create');

        return $this->versionOf($result['json'], 'create');
    }

    public function writeVersioned(string $identifier, array $data): int
    {
        $url    = $this->endpoint()->dataUrl($identifier);
        $result = $this->send('POST', $url, ['data' => $data], 'write');

        $this->assertSuccess($result['status'], 'write');

        return $this->versionOf($result['json'], 'write');
    }

    public function restoreIfCurrent(string $identifier, array $data, int $version): bool
    {
        $url    = $this->endpoint()->dataUrl($identifier);
        $result = $this->send('POST', $url, ['options' => ['cas' => $version], 'data' => $data], 'restore');

        if ($result['status'] === 400) {
            return false;
        }

        $this->assertSuccess($result['status'], 'restore');

        return true;
    }

    public function destroyIfCurrent(string $identifier, int $version): bool
    {
        // A read that has not caught up with our own write shows an older
        // version for a moment; a few short retries tell that apart from a
        // real concurrent write, which keeps showing another version.
        for ($attempt = 1; $attempt <= self::VERSION_READ_ATTEMPTS; ++$attempt) {
            $result = $this->send('GET', $this->endpoint()->metadataUrl($identifier), null, 'read');
            if ($result['status'] === 404) {
                return false;
            }

            $this->assertSuccess($result['status'], 'read');

            $metadata = $result['json']['data'] ?? null;
            if (is_array($metadata) && ($metadata['current_version'] ?? null) === $version) {
                $this->destroy($identifier);

                return true;
            }

            if ($attempt < self::VERSION_READ_ATTEMPTS) {
                usleep(self::VERSION_READ_DELAY_MICROSECONDS);
            }
        }

        return false;
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

    /**
     * @param array<array-key, mixed> $json
     */
    private function versionOf(array $json, string $operation): int
    {
        $data    = $json['data'] ?? null;
        $version = is_array($data) ? ($data['version'] ?? null) : null;
        if (!is_int($version)) {
            throw HashiCorpException::malformedResponse($operation, 'response has no "data.version"');
        }

        return $version;
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
