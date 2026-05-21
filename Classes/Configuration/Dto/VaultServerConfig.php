<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Configuration\Dto;

use SensitiveParameter;

/**
 * Data Transfer Object for HashiCorp Vault server configuration.
 *
 * Replaces array{address?: string, path?: string, authMethod?: string, token?: string}
 * for type-safe vault server configuration handling.
 */
readonly class VaultServerConfig
{
    public function __construct(
        public string $address = '',
        public string $path = '',
        public string $authMethod = '',
        #[SensitiveParameter] public string $token = '',
    ) {}

    /**
     * Create from configuration array.
     *
     * @param array{address?: string, path?: string, authMethod?: string, token?: string} $config
     */
    public static function fromArray(array $config): self
    {
        return new self(
            address: $config['address'] ?? '',
            path: $config['path'] ?? '',
            authMethod: $config['authMethod'] ?? '',
            token: $config['token'] ?? '',
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
        return $this->token !== '' && $this->authMethod === 'token';
    }

    /**
     * Convert to array for serialization.
     *
     * @return array{address: string, path: string, authMethod: string, token: string}
     */
    public function toArray(): array
    {
        return [
            'address' => $this->address,
            'path' => $this->path,
            'authMethod' => $this->authMethod,
            'token' => $this->token,
        ];
    }
}
