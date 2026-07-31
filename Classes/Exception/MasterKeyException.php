<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

/**
 * Thrown when master key operations fail.
 */
final class MasterKeyException extends VaultException
{
    public static function notFound(string $location): self
    {
        return new self(
            \sprintf('Master key not found at: %s', $location),
            1703800008,
        );
    }

    public static function invalidLength(int $expected, int $actual): self
    {
        return new self(
            \sprintf('Invalid master key length: expected %d bytes, got %d', $expected, $actual),
            1703800009,
        );
    }

    public static function cannotStore(string $reason): self
    {
        return new self(
            \sprintf('Cannot store master key: %s', $reason),
            1703800010,
        );
    }

    public static function environmentVariableNotSet(string $varName): self
    {
        return new self(
            \sprintf('Environment variable "%s" for master key is not set', $varName),
            1703800011,
        );
    }

    /**
     * Transit provider: server configuration is incomplete.
     */
    public static function transitNotConfigured(string $detail): self
    {
        return new self(
            \sprintf('HashiCorp Vault Transit provider is not configured: %s', $detail),
            1754100001,
        );
    }

    /**
     * Transit provider: no Vault token available.
     *
     * Reports only WHERE the token was looked for, never any value.
     */
    public static function transitTokenMissing(string $envVarName): self
    {
        return new self(
            \sprintf(
                'No Vault token available for the Transit provider. Set the "%s" environment '
                . 'variable (preferred) or the hashicorp.token extension setting. Token value: [REDACTED]',
                $envVarName,
            ),
            1754100002,
        );
    }

    /**
     * Transit provider: an auth method other than `token` was configured.
     */
    public static function transitUnsupportedAuthMethod(string $authMethod): self
    {
        return new self(
            \sprintf(
                'Vault auth method "%s" is not supported by the Transit master-key provider. '
                . 'Only "token" is implemented; use hashicorp.authMethod = token and provide the '
                . 'token via environment variable.',
                $authMethod,
            ),
            1754100003,
        );
    }

    /**
     * Transit provider: Vault answered with a non-2xx status.
     *
     * The response body is deliberately NOT included — it echoes the submitted
     * ciphertext on some error paths and may carry Vault internals.
     */
    public static function transitRequestRejected(string $operation, int $statusCode): self
    {
        return new self(
            \sprintf(
                'Vault Transit %s failed with HTTP %d (response body suppressed). '
                . 'Check the token policy grants %s on the configured transit key.',
                $operation,
                $statusCode,
                $operation,
            ),
            1754100004,
        );
    }

    /**
     * Transit provider: transport-level failure (DNS, TLS, timeout).
     *
     * Callers must pass an already-redacted reason.
     */
    public static function transitTransportFailure(string $operation, string $redactedReason): self
    {
        return new self(
            \sprintf('Vault Transit %s request could not be sent: %s', $operation, $redactedReason),
            1754100005,
        );
    }

    /**
     * Transit provider: response was 2xx but not the expected shape.
     */
    public static function transitMalformedResponse(string $operation, string $detail): self
    {
        return new self(
            \sprintf('Vault Transit %s returned an unusable response: %s', $operation, $detail),
            1754100006,
        );
    }

    /**
     * Transit provider: mount path or key name contains characters that must
     * never reach a Vault API URL.
     */
    public static function transitInvalidKeyReference(string $field): self
    {
        return new self(
            \sprintf(
                'HashiCorp Vault Transit %s contains characters that are not allowed in a Vault '
                . 'API path. Allowed: letters, digits, dot, dash, underscore (and "/" for the mount).',
                $field,
            ),
            1754100007,
        );
    }
}
