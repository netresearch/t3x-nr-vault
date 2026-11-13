<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

use function sprintf;

/**
 * Thrown by the AWS Secrets Manager storage adapter.
 *
 * No message carries an access key, a session token, a response body or a secret
 * value, and none is chained to the SDK exception: that one holds the signed
 * request, the command parameters (which include the encrypted envelope) and
 * the service's error text. Only the operation, the HTTP status and the AWS
 * error code appear; the error code is a fixed identifier such as
 * `ResourceNotFoundException`, never free text.
 */
final class AwsSecretsManagerException extends VaultException
{
    public static function notConfigured(string $detail): self
    {
        return new self(
            sprintf('AWS Secrets Manager storage adapter is not configured: %s', $detail),
            1794500001,
        );
    }

    public static function insecureTransport(): self
    {
        return new self(
            'AWS Secrets Manager endpoint must use https. Set aws.allowInsecureHttp only for local development.',
            1794500003,
        );
    }

    public static function unsafeName(string $what): self
    {
        return new self(
            sprintf('AWS Secrets Manager %s contains characters or a length that AWS does not allow in a secret name.', $what),
            1794500004,
        );
    }

    public static function credentialMissing(string $what): self
    {
        return new self(
            sprintf('AWS credential is missing: %s. Value: [REDACTED]', $what),
            1794500005,
        );
    }

    public static function requestRejected(string $operation, int $status, string $awsCode): self
    {
        return new self(
            sprintf(
                'AWS Secrets Manager %s was rejected with HTTP %d%s.',
                $operation,
                $status,
                $awsCode !== '' ? sprintf(' (%s)', $awsCode) : '',
            ),
            1794500006,
        );
    }

    public static function transportFailure(string $operation, string $detail): self
    {
        return new self(
            sprintf('AWS Secrets Manager %s could not be sent: %s', $operation, $detail),
            1794500007,
        );
    }

    public static function malformedResponse(string $operation, string $detail): self
    {
        return new self(
            sprintf('AWS Secrets Manager %s returned an unusable response: %s', $operation, $detail),
            1794500008,
        );
    }

    public static function backingObjectMissing(string $identifier): self
    {
        return new self(
            sprintf('The registry row for secret "%s" points at AWS Secrets Manager, but AWS holds no value for it.', $identifier),
            1794500009,
        );
    }

    public static function nameTaken(string $identifier): self
    {
        return new self(
            sprintf(
                'An AWS secret already exists under the name nr-vault would use for "%s", and it is not an nr-vault secret for that identifier. '
                . 'It was not changed. Choose another aws.secretPrefix or remove that secret.',
                $identifier,
            ),
            1794500011,
        );
    }

    public static function backingObjectMismatch(string $identifier): self
    {
        return new self(
            sprintf('The AWS Secrets Manager object for secret "%s" does not belong to that identifier.', $identifier),
            1794500010,
        );
    }
}
