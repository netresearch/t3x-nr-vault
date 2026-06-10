<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http\OAuth;

use Netresearch\NrVault\Exception\ValidationException;

/**
 * Configuration for OAuth 2.0 authentication.
 *
 * Supports client_credentials and refresh_token grant types.
 */
final readonly class OAuthConfig
{
    /** Supported OAuth 2.0 grant types — anything else fails fast. */
    private const SUPPORTED_GRANT_TYPES = ['client_credentials', 'refresh_token'];

    /**
     * @param string $tokenEndpoint OAuth token endpoint URL
     * @param string $clientIdSecret Vault identifier for client ID
     * @param string $clientSecretSecret Vault identifier for client secret
     * @param string $grantType Grant type (client_credentials, refresh_token)
     * @param string|null $refreshTokenSecret Vault identifier for refresh token (if using refresh_token grant)
     * @param array<string> $scopes OAuth scopes to request
     * @param int $tokenExpiryBuffer Seconds before expiry to trigger refresh (default: 60)
     * @param array<string, string> $additionalParams Additional parameters for token request
     *
     * @throws ValidationException If the grant type is unsupported, or the
     *                             refresh_token grant is requested without a
     *                             refresh-token secret identifier
     */
    public function __construct(
        public string $tokenEndpoint,
        public string $clientIdSecret,
        public string $clientSecretSecret,
        public string $grantType = 'client_credentials',
        public ?string $refreshTokenSecret = null,
        public array $scopes = [],
        public int $tokenExpiryBuffer = 60,
        public array $additionalParams = [],
    ) {
        if (!\in_array($this->grantType, self::SUPPORTED_GRANT_TYPES, true)) {
            throw ValidationException::invalidOption(
                'grantType',
                \sprintf(
                    'must be one of: %s',
                    implode(', ', self::SUPPORTED_GRANT_TYPES),
                ),
            );
        }

        // A refresh_token grant with no refresh-token secret is an illegal
        // state: the manager would silently fall back to client_credentials,
        // hiding a misconfiguration. Reject it at construction time.
        if ($this->grantType === 'refresh_token'
            && ($this->refreshTokenSecret === null || $this->refreshTokenSecret === '')
        ) {
            throw ValidationException::invalidOption(
                'refreshTokenSecret',
                'is required for the refresh_token grant type',
            );
        }
    }

    /**
     * Create config for client credentials flow.
     *
     * @param string $tokenEndpoint OAuth token endpoint URL
     * @param string $clientIdSecret Vault identifier for client ID
     * @param string $clientSecretSecret Vault identifier for client secret
     * @param array<string> $scopes OAuth scopes to request
     */
    public static function clientCredentials(
        string $tokenEndpoint,
        string $clientIdSecret,
        string $clientSecretSecret,
        array $scopes = [],
    ): self {
        return new self(
            tokenEndpoint: $tokenEndpoint,
            clientIdSecret: $clientIdSecret,
            clientSecretSecret: $clientSecretSecret,
            grantType: 'client_credentials',
            scopes: $scopes,
        );
    }

    /**
     * Create config for refresh token flow.
     *
     * @param string $tokenEndpoint OAuth token endpoint URL
     * @param string $clientIdSecret Vault identifier for client ID
     * @param string $clientSecretSecret Vault identifier for client secret
     * @param string $refreshTokenSecret Vault identifier for refresh token
     * @param array<string> $scopes OAuth scopes to request
     */
    public static function refreshToken(
        string $tokenEndpoint,
        string $clientIdSecret,
        string $clientSecretSecret,
        string $refreshTokenSecret,
        array $scopes = [],
    ): self {
        return new self(
            tokenEndpoint: $tokenEndpoint,
            clientIdSecret: $clientIdSecret,
            clientSecretSecret: $clientSecretSecret,
            grantType: 'refresh_token',
            refreshTokenSecret: $refreshTokenSecret,
            scopes: $scopes,
        );
    }

    /**
     * Get scopes as space-separated string.
     */
    public function getScopesString(): string
    {
        return implode(' ', $this->scopes);
    }
}
