<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

use Throwable;

/**
 * Thrown when OAuth 2.0 token operations fail.
 */
final class OAuthException extends VaultException
{
    /**
     * HTTP status code from the failed token-endpoint response, or null if
     * the failure was not a transport-level HTTP error (JSON decode,
     * missing access_token, network errors, etc.).
     */
    public ?int $httpStatus = null;

    /**
     * OAuth 2.0 `error` field from the token-endpoint JSON error body
     * (e.g. `invalid_grant`, `invalid_client`, `invalid_request`). Null
     * if the server did not produce an RFC 6749 §5.2 error object.
     */
    public ?string $oauthError = null;

    public static function tokenRequestFailed(int $statusCode, ?string $oauthError = null): self
    {
        $self = new self(
            $oauthError !== null
                ? \sprintf('OAuth token request failed with status %d (%s)', $statusCode, $oauthError)
                : \sprintf('OAuth token request failed with status %d', $statusCode),
            2477018617,
        );
        $self->httpStatus = $statusCode;
        $self->oauthError = $oauthError;

        return $self;
    }

    public static function missingAccessToken(): self
    {
        return new self(
            'OAuth response missing access_token',
            9878610721,
        );
    }

    public static function invalidJsonResponse(Throwable $previous): self
    {
        return new self(
            'Invalid JSON response from OAuth server',
            1703800020,
            $previous,
        );
    }

    public static function requestFailed(string $message, ?Throwable $previous = null): self
    {
        return new self(
            \sprintf('OAuth token request failed: %s', $message),
            1703800021,
            $previous,
        );
    }
}
