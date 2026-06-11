<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http;

use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Psr\Http\Client\ClientInterface;

/**
 * PSR-18 compatible HTTP client with vault-based authentication.
 *
 * This interface extends PSR-18 ClientInterface to provide a standard
 * HTTP client that can automatically inject vault-stored secrets.
 *
 * Usage:
 *     // Configure authentication, then send PSR-7 requests
 *     $client = $vault->http()->withAuthentication('api_key', SecretPlacement::Bearer);
 *     $response = $client->sendRequest($request);
 *
 *     // For OAuth2
 *     $client = $vault->http()->withOAuth($oauthConfig);
 *     $response = $client->sendRequest($request);
 */
interface VaultHttpClientInterface extends ClientInterface
{
    /**
     * Create a new client instance configured with authentication.
     *
     * Returns a new immutable instance - the original is unchanged.
     *
     * @param string $secretIdentifier Vault identifier for the secret
     * @param SecretPlacement $placement How to inject the secret
     * @param array{
     *     headerName?: string,
     *     prefix?: string,
     *     queryParam?: string,
     *     bodyField?: string,
     *     usernameSecret?: string,
     *     reason?: string
     * } $options Additional options:
     *     - headerName: Custom header name (for SecretPlacement::Header)
     *     - prefix: Auth scheme/prefix prepended to the secret (for SecretPlacement::Header),
     *       e.g. 'Key ' → "Authorization: Key <secret>" or 'DeepL-Auth-Key ' for DeepL
     *     - queryParam: Custom query param name (for SecretPlacement::QueryParam)
     *     - bodyField: Custom body field name (for SecretPlacement::BodyField)
     *     - usernameSecret: Username secret identifier (for SecretPlacement::BasicAuth)
     *     - reason: Audit log reason for this client's requests
     *
     * @return static New client instance with authentication configured
     */
    public function withAuthentication(
        string $secretIdentifier,
        SecretPlacement $placement = SecretPlacement::Bearer,
        array $options = [],
    ): static;

    /**
     * Create a new client instance configured with OAuth 2.0 authentication.
     *
     * Returns a new immutable instance - the original is unchanged.
     *
     * @param OAuthConfig $config OAuth configuration
     * @param string $reason Audit log reason for this client's requests
     *
     * @return static New client instance with OAuth configured
     */
    public function withOAuth(OAuthConfig $config, string $reason = 'OAuth2 API call'): static;

    /**
     * Create a new client instance with a custom audit reason.
     *
     * @param string $reason Audit log reason for requests
     *
     * @return static New client instance with reason configured
     */
    public function withReason(string $reason): static;

    /**
     * Create a new client instance with a request timeout override.
     *
     * Returns a new immutable instance - the original is unchanged. The
     * override applies Guzzle's `timeout` option (total request duration in
     * seconds) to every request sent through the returned instance,
     * authenticated or not. Connection establishment (`connect_timeout`)
     * stays platform-managed.
     *
     * @param int $seconds Timeout in seconds; non-positive values mean
     *                     "no override" and fall back to the platform default
     *                     ($GLOBALS['TYPO3_CONF_VARS']['HTTP']['timeout'])
     *
     * @return static New client instance with the timeout configured
     */
    public function withTimeout(int $seconds): static;
}
