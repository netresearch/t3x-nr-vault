<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

use function sprintf;

/**
 * Thrown by the HashiCorp Vault storage adapter.
 *
 * No message carries a token, a login credential, a response body or a secret
 * value: Vault echoes submitted data on some error paths and its error text can
 * name cluster internals, so only the operation and the HTTP status appear.
 */
final class HashiCorpException extends VaultException
{
    public static function notConfigured(string $detail): self
    {
        return new self(
            sprintf('HashiCorp Vault storage adapter is not configured: %s', $detail),
            1794400001,
        );
    }

    public static function insecureTransport(): self
    {
        return new self(
            'HashiCorp Vault address must use https. Set hashicorp.allowInsecureHttp only for local development.',
            1794400002,
        );
    }

    public static function unsafePath(string $what): self
    {
        return new self(
            sprintf('HashiCorp Vault %s contains characters that are not allowed in a Vault API path.', $what),
            1794400003,
        );
    }

    public static function credentialMissing(string $what): self
    {
        return new self(
            sprintf('HashiCorp Vault login credential is missing: %s. Value: [REDACTED]', $what),
            1794400004,
        );
    }

    public static function loginRejected(string $method, int $status): self
    {
        return new self(
            sprintf('HashiCorp Vault %s login was rejected with HTTP %d.', $method, $status),
            1794400005,
        );
    }

    public static function requestRejected(string $operation, int $status): self
    {
        return new self(
            sprintf('HashiCorp Vault %s was rejected with HTTP %d.', $operation, $status),
            1794400006,
        );
    }

    public static function transportFailure(string $operation, string $detail): self
    {
        return new self(
            sprintf('HashiCorp Vault %s could not be sent: %s', $operation, $detail),
            1794400007,
        );
    }

    public static function malformedResponse(string $operation, string $detail): self
    {
        return new self(
            sprintf('HashiCorp Vault %s returned an unusable response: %s', $operation, $detail),
            1794400008,
        );
    }

    public static function backingObjectMissing(string $identifier): self
    {
        return new self(
            sprintf('The registry row for secret "%s" points at HashiCorp Vault, but Vault holds no value for it.', $identifier),
            1794400009,
        );
    }

    public static function backingObjectMismatch(string $identifier): self
    {
        return new self(
            sprintf('The HashiCorp Vault object for secret "%s" does not belong to that identifier.', $identifier),
            1794400010,
        );
    }

    public static function externalSecretsBlockMasterKeyRotation(string $identifier, string $adapter): self
    {
        return new self(
            sprintf(
                'Secret "%s" is stored in the "%s" adapter. Master key rotation cannot re-wrap an envelope outside the local '
                . 'database in one transaction, so it refuses to run while such secrets exist.',
                $identifier,
                $adapter,
            ),
            1794400011,
        );
    }
}
