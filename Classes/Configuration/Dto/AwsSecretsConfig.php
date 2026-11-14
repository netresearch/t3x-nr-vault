<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Configuration\Dto;

use function is_bool;
use function is_string;

/**
 * Data Transfer Object for AWS Secrets Manager configuration.
 *
 * Credentials are explicit and never come from the SDK's default provider
 * chain, which asks the instance metadata service at 169.254.169.254 (blocked
 * by the extension's SSRF defence). The secret access key and the session token
 * are read from environment variables whose NAMES live here; the access key id
 * is an identifier rather than a secret and may also be stored.
 */
readonly class AwsSecretsConfig
{
    public function __construct(
        public string $region = '',
        public string $secretPrefix = '',
        public string $endpoint = '',
        public bool $allowInsecureHttp = false,
        public string $accessKeyId = '',
        public string $accessKeyIdEnvVar = 'NR_VAULT_AWS_ACCESS_KEY_ID',
        public string $secretAccessKeyEnvVar = 'NR_VAULT_AWS_SECRET_ACCESS_KEY',
        public string $sessionTokenEnvVar = 'NR_VAULT_AWS_SESSION_TOKEN',
    ) {}

    /**
     * Create from configuration array.
     *
     * @param array{region?: string, secretPrefix?: string, endpoint?: string, allowInsecureHttp?: string|bool|int, accessKeyId?: string, accessKeyIdEnvVar?: string, secretAccessKeyEnvVar?: string, sessionTokenEnvVar?: string} $config
     */
    public static function fromArray(array $config): self
    {
        $defaults = new self();

        return new self(
            region: $config['region'] ?? '',
            secretPrefix: $config['secretPrefix'] ?? '',
            endpoint: trim($config['endpoint'] ?? ''),
            allowInsecureHttp: self::toBool($config['allowInsecureHttp'] ?? false),
            accessKeyId: trim($config['accessKeyId'] ?? ''),
            accessKeyIdEnvVar: self::nonEmpty($config['accessKeyIdEnvVar'] ?? null, $defaults->accessKeyIdEnvVar),
            secretAccessKeyEnvVar: self::nonEmpty($config['secretAccessKeyEnvVar'] ?? null, $defaults->secretAccessKeyEnvVar),
            sessionTokenEnvVar: self::nonEmpty($config['sessionTokenEnvVar'] ?? null, $defaults->sessionTokenEnvVar),
        );
    }

    /**
     * Check if the configuration is valid.
     */
    public function isValid(): bool
    {
        return $this->region !== '';
    }

    /**
     * Get the full secret name with prefix.
     */
    public function getFullSecretName(string $secretName): string
    {
        if ($this->secretPrefix === '') {
            return $secretName;
        }

        return $this->secretPrefix . '/' . $secretName;
    }

    /**
     * Convert to array for serialization. No credential is part of it.
     *
     * @return array{region: string, secretPrefix: string}
     */
    public function toArray(): array
    {
        return [
            'region'       => $this->region,
            'secretPrefix' => $this->secretPrefix,
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
