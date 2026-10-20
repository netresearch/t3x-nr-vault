<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Configuration\Dto;

/**
 * Data Transfer Object for AWS Secrets Manager configuration.
 *
 * Replaces array{region?: string, secretPrefix?: string}
 * for type-safe AWS configuration handling.
 */
readonly class AwsSecretsConfig
{
    public function __construct(
        public string $region = '',
        public string $secretPrefix = '',
    ) {}

    /**
     * Create from configuration array.
     *
     * @param array{region?: string, secretPrefix?: string} $config
     */
    public static function fromArray(array $config): self
    {
        return new self(
            region: $config['region'] ?? '',
            secretPrefix: $config['secretPrefix'] ?? '',
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
     * Convert to array for serialization.
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
}
