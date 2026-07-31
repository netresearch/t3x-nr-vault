<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Configuration\Dto;

use SensitiveParameter;

/**
 * Data Transfer Object for the HashiCorp Vault Transit master-key provider.
 *
 * Separate from {@see VaultServerConfig} (which describes the *storage adapter*
 * connection) because the Transit provider is a key-custody concern: it wraps
 * and unwraps the vault master key through Vault's transit secrets engine and
 * never stores secret payloads there.
 *
 * Both read their values from the same `hashicorp.*` extension-configuration
 * group, so a deployment that already points at a Vault server does not have to
 * repeat the address.
 */
readonly class TransitConfig
{
    public const DEFAULT_MOUNT = 'transit';

    public const DEFAULT_KEY_NAME = 'nr-vault-master';

    public const DEFAULT_TOKEN_ENV_VAR = 'VAULT_TOKEN';

    /**
     * @param string $address Vault base address, e.g. https://vault.example.com:8200
     * @param string $mount transit engine mount path (without /v1/)
     * @param string $keyName transit key that wraps the master key
     * @param string $wrappedKeyPath absolute path of the locally stored wrapped
     *                               (Vault-encrypted) master key
     * @param string $authMethod configured auth method; only `token` is
     *                           implemented (see TransitMasterKeyProvider)
     * @param string $tokenEnvVar environment variable read for the Vault
     *                            token; preferred over $token
     * @param string $token token from extension configuration —
     *                      fallback for development only
     */
    public function __construct(
        public string $address = '',
        public string $mount = self::DEFAULT_MOUNT,
        public string $keyName = self::DEFAULT_KEY_NAME,
        public string $wrappedKeyPath = '',
        public string $authMethod = 'token',
        public string $tokenEnvVar = self::DEFAULT_TOKEN_ENV_VAR,
        #[SensitiveParameter]
        public string $token = '',
    ) {}

    /**
     * Create from the `hashicorp` extension-configuration sub-array.
     *
     * @param array{address?: string, authMethod?: string, token?: string, transitMount?: string, transitKeyName?: string, transitWrappedKeyPath?: string, tokenEnvVar?: string} $config
     * @param string $fallbackWrappedKeyPath used when `transitWrappedKeyPath` is
     *                                       empty; callers resolve it from the TYPO3 var
     *                                       path so this DTO stays free of environment
     *                                       lookups
     */
    public static function fromArray(array $config, string $fallbackWrappedKeyPath = ''): self
    {
        $wrappedKeyPath = trim($config['transitWrappedKeyPath'] ?? '');
        $mount = trim($config['transitMount'] ?? '', " \t\n\r\0\x0B/");
        $configuredKeyName = trim($config['transitKeyName'] ?? '');
        $authMethod = trim($config['authMethod'] ?? '');
        $configuredTokenEnvVar = trim($config['tokenEnvVar'] ?? '');

        return new self(
            address: rtrim(trim($config['address'] ?? ''), '/'),
            mount: $mount !== '' ? $mount : self::DEFAULT_MOUNT,
            keyName: $configuredKeyName !== '' ? $configuredKeyName : self::DEFAULT_KEY_NAME,
            wrappedKeyPath: $wrappedKeyPath !== '' ? $wrappedKeyPath : $fallbackWrappedKeyPath,
            authMethod: $authMethod !== '' ? $authMethod : 'token',
            tokenEnvVar: $configuredTokenEnvVar !== '' ? $configuredTokenEnvVar : self::DEFAULT_TOKEN_ENV_VAR,
            token: $config['token'] ?? '',
        );
    }

    /**
     * Everything the provider needs to build a Transit request is present.
     *
     * Deliberately does NOT cover the token: token presence is checked
     * separately so a missing credential can be reported differently from an
     * incomplete server configuration.
     */
    public function isComplete(): bool
    {
        return $this->address !== ''
            && $this->mount !== ''
            && $this->keyName !== ''
            && $this->wrappedKeyPath !== '';
    }

    /**
     * Only token auth is implemented; `kubernetes` and `approle` are rejected
     * by the provider rather than silently treated as token auth.
     */
    public function usesTokenAuth(): bool
    {
        return $this->authMethod === 'token';
    }

    /**
     * Absolute Vault API URL for a transit operation (`encrypt` / `decrypt`).
     */
    public function endpointFor(string $operation): string
    {
        return \sprintf('%s/v1/%s/%s/%s', $this->address, $this->mount, $operation, $this->keyName);
    }

    /**
     * Convert to array for serialization. The token is deliberately omitted —
     * this DTO is dumped into diagnostics output (vault:init, health checks).
     *
     * @return array{address: string, mount: string, keyName: string, wrappedKeyPath: string, authMethod: string, tokenEnvVar: string}
     */
    public function toArray(): array
    {
        return [
            'address' => $this->address,
            'mount' => $this->mount,
            'keyName' => $this->keyName,
            'wrappedKeyPath' => $this->wrappedKeyPath,
            'authMethod' => $this->authMethod,
            'tokenEnvVar' => $this->tokenEnvVar,
        ];
    }
}
