<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Configuration\Dto;

use SensitiveParameter;

use function is_bool;
use function is_string;

/**
 * Data Transfer Object for HashiCorp Vault server configuration.
 *
 * Replaces array{address?: string, path?: string, authMethod?: string, token?: string}
 * for type-safe vault server configuration handling. The credentials that are
 * secrets in themselves (token, AppRole secret id) are read from environment
 * variables whose NAMES live here; only the Vault token has a stored fallback,
 * for historical reasons.
 */
readonly class VaultServerConfig
{
    public const AUTH_TOKEN = 'token';

    public const AUTH_APPROLE = 'approle';

    public const AUTH_KUBERNETES = 'kubernetes';

    public function __construct(
        public string $address = '',
        public string $path = '',
        public string $authMethod = '',
        #[SensitiveParameter]
        public string $token = '',
        public string $tokenEnvVar = 'VAULT_TOKEN',
        public string $approleMount = 'approle',
        public string $roleId = '',
        public string $secretIdEnvVar = 'VAULT_SECRET_ID',
        public string $kubernetesMount = 'kubernetes',
        public string $kubernetesRole = '',
        public string $kubernetesJwtPath = '/var/run/secrets/kubernetes.io/serviceaccount/token',
        public bool $allowInsecureHttp = false,
    ) {}

    /**
     * Create from configuration array.
     *
     * @param array{address?: string, path?: string, authMethod?: string, token?: string, tokenEnvVar?: string, approleMount?: string, roleId?: string, secretIdEnvVar?: string, kubernetesMount?: string, kubernetesRole?: string, kubernetesJwtPath?: string, allowInsecureHttp?: string|bool|int} $config
     */
    public static function fromArray(array $config): self
    {
        $defaults = new self();

        return new self(
            address: $config['address'] ?? '',
            path: $config['path'] ?? '',
            authMethod: $config['authMethod'] ?? '',
            token: $config['token'] ?? '',
            tokenEnvVar: self::nonEmpty($config['tokenEnvVar'] ?? null, $defaults->tokenEnvVar),
            approleMount: self::nonEmpty($config['approleMount'] ?? null, $defaults->approleMount),
            roleId: self::nonEmpty($config['roleId'] ?? null, ''),
            secretIdEnvVar: self::nonEmpty($config['secretIdEnvVar'] ?? null, $defaults->secretIdEnvVar),
            kubernetesMount: self::nonEmpty($config['kubernetesMount'] ?? null, $defaults->kubernetesMount),
            kubernetesRole: self::nonEmpty($config['kubernetesRole'] ?? null, ''),
            kubernetesJwtPath: self::nonEmpty($config['kubernetesJwtPath'] ?? null, $defaults->kubernetesJwtPath),
            allowInsecureHttp: self::toBool($config['allowInsecureHttp'] ?? false),
        );
    }

    /**
     * Check if the configuration is valid for connecting.
     */
    public function isValid(): bool
    {
        return $this->address !== '' && $this->path !== '';
    }

    /**
     * Check if token authentication is configured.
     */
    public function hasTokenAuth(): bool
    {
        return $this->token !== '' && $this->authMethod === self::AUTH_TOKEN;
    }

    /**
     * Convert to array for serialization.
     *
     * The token is part of the array because the shape predates the other
     * credentials; the AppRole secret id never is, it only exists in the
     * environment.
     *
     * @return array{address: string, path: string, authMethod: string, token: string}
     */
    public function toArray(): array
    {
        return [
            'address'    => $this->address,
            'path'       => $this->path,
            'authMethod' => $this->authMethod,
            'token'      => $this->token,
        ];
    }

    private static function nonEmpty(mixed $value, string $default): string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : $default;
    }

    private static function toBool(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        return in_array($value, ['1', 1, 'true'], true);
    }
}
