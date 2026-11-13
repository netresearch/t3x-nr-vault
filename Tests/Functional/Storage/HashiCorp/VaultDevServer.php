<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Storage\HashiCorp;

use GuzzleHttp\Client;
use RuntimeException;
use Testcontainers\Container\GenericContainer;
use Testcontainers\Container\StartedGenericContainer;
use Testcontainers\Wait\WaitForHttp;
use Throwable;

use function is_array;
use function is_int;
use function is_string;
use function sprintf;

/**
 * A real HashiCorp Vault in development mode, started with Testcontainers.
 *
 * One server serves the whole test run: it starts on first use and stops with
 * the PHP process. Development mode mounts `secret/` as KV v2 and unseals
 * itself, which is the engine the adapter targets. Kubernetes auth asks the
 * cluster API to review the service account token, so a second container plays
 * that API with a fixed positive answer; everything on the Vault side, the
 * login, the role binding and the policy, is the real thing.
 *
 * Docker is a precondition. {@see AbstractHashiCorpContainerTestCase} skips the
 * class on a developer machine without it and lets the failure through in CI, so
 * a runner without Docker cannot turn the whole suite green by skipping it.
 */
final class VaultDevServer
{
    public const ROOT_TOKEN = 'root-token-for-tests-only';

    public const SERVICE_ACCOUNT_NAME = 'web';

    public const SERVICE_ACCOUNT_NAMESPACE = 'typo3';

    private const VAULT_IMAGE = 'hashicorp/vault:2.2';

    private const STUB_IMAGE = 'python:3.13-alpine';

    private const POLICY = 'typo3';

    private static ?self $shared = null;

    private function __construct(
        private readonly StartedGenericContainer $vault,
        private readonly StartedGenericContainer $reviewStub,
        public readonly string $host,
        public readonly string $address,
    ) {}

    public static function shared(): self
    {
        if (self::$shared instanceof self) {
            return self::$shared;
        }

        self::$shared = self::boot();

        register_shutdown_function(static function (): void {
            self::$shared?->stop();
        });

        return self::$shared;
    }

    /**
     * A token that may do what the TYPO3 extension needs under `secret/typo3/`
     * and nothing else.
     */
    public function limitedToken(): string
    {
        $result = $this->admin('POST', '/v1/auth/token/create', ['policies' => [self::POLICY], 'ttl' => '1h']);

        return $this->string($result, ['auth', 'client_token']);
    }

    public function appRoleId(): string
    {
        $result = $this->admin('GET', '/v1/auth/approle/role/typo3/role-id');

        return $this->string($result, ['data', 'role_id']);
    }

    public function newAppRoleSecretId(): string
    {
        $result = $this->admin('POST', '/v1/auth/approle/role/typo3/secret-id');

        return $this->string($result, ['data', 'secret_id']);
    }

    /**
     * A service account token as the kubelet projects it. Vault does not verify
     * its signature itself, it hands the token to the cluster API.
     */
    public function serviceAccountJwt(): string
    {
        $encode = static fn (array $part): string => rtrim(strtr(base64_encode(json_encode($part, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');

        return implode('.', [
            $encode(['alg' => 'RS256', 'typ' => 'JWT']),
            $encode([
                'iss'                                               => 'kubernetes/serviceaccount',
                'sub'                                               => sprintf('system:serviceaccount:%s:%s', self::SERVICE_ACCOUNT_NAMESPACE, self::SERVICE_ACCOUNT_NAME),
                'kubernetes.io/serviceaccount/namespace'            => self::SERVICE_ACCOUNT_NAMESPACE,
                'kubernetes.io/serviceaccount/service-account.name' => self::SERVICE_ACCOUNT_NAME,
                'kubernetes.io/serviceaccount/service-account.uid'  => '11111111-2222-3333-4444-555555555555',
            ]),
            'c2lnbmF0dXJl',
        ]);
    }

    /**
     * Revoke every login token issued under the extension's policy, which
     * simulates an expired or administratively revoked token.
     */
    public function revokeAllExtensionTokens(): int
    {
        $accessors = $this->admin('LIST', '/v1/auth/token/accessors');
        $list      = $this->dig($accessors['json'], 'data', 'keys');
        $revoked   = 0;
        if (!is_array($list)) {
            return 0;
        }

        foreach ($list as $accessor) {
            $lookup   = $this->admin('POST', '/v1/auth/token/lookup-accessor', ['accessor' => $accessor]);
            $policies = $this->dig($lookup['json'], 'data', 'policies');
            if (is_array($policies) && in_array(self::POLICY, $policies, true)) {
                $this->admin('POST', '/v1/auth/token/revoke-accessor', ['accessor' => $accessor]);
                ++$revoked;
            }
        }

        return $revoked;
    }

    /**
     * Read a KV v2 key as an administrator, bypassing the adapter.
     *
     * @return array{status: int, json: array<array-key, mixed>}
     */
    public function readKey(string $identifier): array
    {
        return $this->admin('GET', '/v1/secret/data/typo3/' . $identifier);
    }

    /**
     * The fields of the key as Vault stores them, or null when it does not exist.
     *
     * @return array<array-key, mixed>|null
     */
    public function storedData(string $identifier): ?array
    {
        $result = $this->readKey($identifier);
        if ($result['status'] !== 200) {
            return null;
        }

        $outer = $result['json']['data'] ?? null;
        $data  = is_array($outer) ? ($outer['data'] ?? null) : null;

        return is_array($data) ? $data : null;
    }

    /**
     * The current KV version of the key, or 0 when it does not exist.
     */
    public function currentVersion(string $identifier): int
    {
        $result = $this->admin('GET', '/v1/secret/metadata/typo3/' . $identifier);
        $data   = $result['json']['data'] ?? null;
        $value  = is_array($data) ? ($data['current_version'] ?? 0) : 0;

        return is_int($value) ? $value : 0;
    }

    /**
     * @param array<string, mixed>|null $body
     *
     * @return array{status: int, json: array<array-key, mixed>}
     */
    public function admin(string $method, string $path, ?array $body = null): array
    {
        return $this->request($method, $path, self::ROOT_TOKEN, $body);
    }

    /**
     * @param array<string, mixed>|null $body
     *
     * @return array{status: int, json: array<array-key, mixed>}
     */
    public function request(string $method, string $path, ?string $token, ?array $body = null): array
    {
        $headers = ['Accept' => 'application/json'];
        if ($token !== null) {
            $headers['X-Vault-Token'] = $token;
        }

        $options = ['headers' => $headers, 'http_errors' => false, 'timeout' => 10];
        if ($body !== null) {
            $options['json'] = $body;
        }

        $response = (new Client())->request($method, $this->address . $path, $options);
        $json     = json_decode((string) $response->getBody(), true);

        return ['status' => $response->getStatusCode(), 'json' => is_array($json) ? $json : []];
    }

    public function stop(): void
    {
        foreach ([$this->vault, $this->reviewStub] as $container) {
            try {
                $container->stop();
            } catch (Throwable) {
                // The container may already be gone; the run is over either way.
            }
        }
    }

    private static function boot(): self
    {
        $stubScript = (string) file_get_contents(__DIR__ . '/Fixtures/token-review-stub.py');

        $stub = (new GenericContainer(self::STUB_IMAGE))
            ->withCopyContentToContainer([['content' => $stubScript, 'target' => '/stub.py']])
            ->withCommand(['python', '/stub.py'])
            ->withExposedPorts(8080)
            ->withWait((new WaitForHttp(8080))->withMethod('POST')->withPath('/ready'))
            ->start();

        $vault = (new GenericContainer(self::VAULT_IMAGE))
            ->withEnvironment([
                'VAULT_DEV_ROOT_TOKEN_ID'  => self::ROOT_TOKEN,
                'VAULT_DEV_LISTEN_ADDRESS' => '0.0.0.0:8200',
                'SKIP_SETCAP'              => '1',
            ])
            ->withExposedPorts(8200)
            ->withWait((new WaitForHttp(8200))->withPath('/v1/sys/health'))
            ->start();

        $host   = $vault->getHost();
        $server = new self($vault, $stub, $host, sprintf('http://%s:%d', $host, $vault->getMappedPort(8200)));
        $server->provision($stub->getIpAddress('bridge'));

        return $server;
    }

    private function provision(string $reviewStubIp): void
    {
        $policy = <<<'HCL'
            path "secret/data/typo3/*" { capabilities = ["create", "read", "update"] }
            path "secret/metadata/typo3/*" { capabilities = ["read", "delete"] }
            HCL;
        $this->expectOk($this->admin('PUT', '/v1/sys/policies/acl/' . self::POLICY, ['policy' => $policy]));

        $this->expectOk($this->admin('POST', '/v1/sys/auth/approle', ['type' => 'approle']));
        $this->expectOk($this->admin('POST', '/v1/auth/approle/role/typo3', ['token_policies' => [self::POLICY], 'token_ttl' => '1h']));

        $this->expectOk($this->admin('POST', '/v1/sys/auth/kubernetes', ['type' => 'kubernetes']));
        $this->expectOk($this->admin('POST', '/v1/auth/kubernetes/config', [
            'kubernetes_host'        => sprintf('http://%s:8080', $reviewStubIp),
            'token_reviewer_jwt'     => 'reviewer',
            'disable_iss_validation' => true,
            'disable_local_ca_jwt'   => true,
        ]));
        $this->expectOk($this->admin('POST', '/v1/auth/kubernetes/role/typo3', [
            'bound_service_account_names'      => [self::SERVICE_ACCOUNT_NAME],
            'bound_service_account_namespaces' => [self::SERVICE_ACCOUNT_NAMESPACE],
            'token_policies'                   => [self::POLICY],
            'token_ttl'                        => '1h',
        ]));
    }

    /**
     * @param array{status: int, json: array<array-key, mixed>} $result
     */
    private function expectOk(array $result): void
    {
        if ($result['status'] < 200 || $result['status'] >= 300) {
            throw new RuntimeException(sprintf('Vault provisioning step failed with HTTP %d', $result['status']), 1794400102);
        }
    }

    /**
     * @param array<array-key, mixed> $json
     */
    private function dig(array $json, string ...$path): mixed
    {
        $value = $json;
        foreach ($path as $key) {
            $value = is_array($value) ? ($value[$key] ?? null) : null;
        }

        return $value;
    }

    /**
     * @param array{status: int, json: array<array-key, mixed>} $result
     * @param list<string>                                      $path
     */
    private function string(array $result, array $path): string
    {
        $value = $result['json'];
        foreach ($path as $key) {
            $value = is_array($value) ? ($value[$key] ?? null) : null;
        }

        if (!is_string($value) || $value === '') {
            throw new RuntimeException('Vault answered without ' . implode('.', $path), 1794400103);
        }

        return $value;
    }
}
