<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\HashiCorp;

use Netresearch\NrVault\Configuration\Dto\VaultServerConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\HashiCorpException;

use function is_array;
use function is_string;

/**
 * Obtains the Vault token for one auth method: token, approle or kubernetes.
 *
 * A login token is memoised for this object's lifetime only (a request or one
 * CLI run) and refreshed when its lease is about to end; nothing is written to
 * disk, to the cache or to the database. Credentials come from where a
 * secret may live: the Vault token and the AppRole secret id from the
 * environment, the Kubernetes JWT from the projected service account file. The
 * AppRole secret id has no stored fallback.
 */
final class HashiCorpAuthenticator
{
    /** Re-login when this share of the lease has passed. */
    private const LEASE_SHARE = 0.8;

    private ?string $token = null;

    private int $expiresAt = 0;

    private bool $ownsToken = false;

    public function __construct(
        private readonly ExtensionConfigurationInterface $configuration,
        private readonly HashiCorpHttp $http,
    ) {}

    public function __destruct()
    {
        $this->forget();
    }

    /**
     * @throws HashiCorpException
     */
    public function token(): string
    {
        if ($this->token !== null && $this->expiresAt > time()) {
            return $this->token;
        }

        $config = $this->configuration->getHashiCorpConfig();

        $this->forget();

        return match ($config->authMethod) {
            VaultServerConfig::AUTH_TOKEN      => $this->staticToken($config),
            VaultServerConfig::AUTH_APPROLE    => $this->appRoleLogin($config),
            VaultServerConfig::AUTH_KUBERNETES => $this->kubernetesLogin($config),
            default                            => throw HashiCorpException::notConfigured(
                'hashicorp.authMethod must be token, approle or kubernetes',
            ),
        };
    }

    /**
     * Drop the memoised login so the next call authenticates again. A token
     * the operator configured cannot be renewed this way; for it the next call
     * reads the same source again.
     */
    public function invalidate(): void
    {
        $this->forget();
    }

    /**
     * Whether a rejected request is worth one fresh login.
     */
    public function canRefresh(): bool
    {
        return $this->configuration->getHashiCorpConfig()->authMethod !== VaultServerConfig::AUTH_TOKEN;
    }

    private function staticToken(VaultServerConfig $config): string
    {
        $fromEnv = getenv($config->tokenEnvVar);
        if (is_string($fromEnv) && $fromEnv !== '') {
            return $this->remember($fromEnv, PHP_INT_MAX, true);
        }

        if ($config->token === '') {
            throw HashiCorpException::credentialMissing('environment variable ' . $config->tokenEnvVar);
        }

        // Shares its buffer with the configuration object: never wiped here.
        return $this->remember($config->token, PHP_INT_MAX, false);
    }

    private function appRoleLogin(VaultServerConfig $config): string
    {
        if ($config->roleId === '') {
            throw HashiCorpException::credentialMissing('hashicorp.roleId');
        }

        $secretId = getenv($config->secretIdEnvVar);
        if (!is_string($secretId) || $secretId === '') {
            throw HashiCorpException::credentialMissing('environment variable ' . $config->secretIdEnvVar);
        }

        try {
            return $this->login(
                HashiCorpEndpoint::loginUrl($config, $config->approleMount),
                ['role_id' => $config->roleId, 'secret_id' => $secretId],
                VaultServerConfig::AUTH_APPROLE,
            );
        } finally {
            sodium_memzero($secretId);
        }
    }

    private function kubernetesLogin(VaultServerConfig $config): string
    {
        if ($config->kubernetesRole === '') {
            throw HashiCorpException::credentialMissing('hashicorp.kubernetesRole');
        }

        $jwt = is_readable($config->kubernetesJwtPath) ? file_get_contents($config->kubernetesJwtPath) : false;
        if ($jwt === false || trim($jwt) === '') {
            throw HashiCorpException::credentialMissing('service account token file');
        }

        $jwt = trim($jwt);

        try {
            return $this->login(
                HashiCorpEndpoint::loginUrl($config, $config->kubernetesMount),
                ['role' => $config->kubernetesRole, 'jwt' => $jwt],
                VaultServerConfig::AUTH_KUBERNETES,
            );
        } finally {
            sodium_memzero($jwt);
        }
    }

    /**
     * @param array<string, string> $credentials
     */
    private function login(string $url, array $credentials, string $method): string
    {
        $result = $this->http->request('POST', $url, null, $credentials, $method . ' login');
        if ($result['status'] < 200 || $result['status'] >= 300) {
            throw HashiCorpException::loginRejected($method, $result['status']);
        }

        $auth = $result['json']['auth'] ?? null;
        if (!is_array($auth)) {
            throw HashiCorpException::malformedResponse($method . ' login', 'response has no "auth" object');
        }

        $clientToken = $auth['client_token'] ?? null;
        if (!is_string($clientToken) || $clientToken === '') {
            throw HashiCorpException::malformedResponse($method . ' login', 'response has no client token');
        }

        $lease = $auth['lease_duration'] ?? 0;
        $until = is_int($lease) && $lease > 0
            ? time() + max(1, (int) ($lease * self::LEASE_SHARE))
            : PHP_INT_MAX;

        return $this->remember($clientToken, $until, true);
    }

    private function remember(string $token, int $expiresAt, bool $owns): string
    {
        $this->token     = $token;
        $this->expiresAt = $expiresAt;
        $this->ownsToken = $owns;

        return $token;
    }

    private function forget(): void
    {
        if ($this->token !== null && $this->ownsToken) {
            sodium_memzero($this->token);
        }

        $this->token     = null;
        $this->expiresAt = 0;
        $this->ownsToken = false;
    }
}
