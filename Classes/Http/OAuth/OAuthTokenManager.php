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

use DateTimeImmutable;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use JsonException;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\OAuthException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Manages OAuth 2.0 token acquisition and refresh.
 *
 * Features:
 * - Automatic token refresh before expiry
 * - In-memory token caching
 * - Support for client_credentials and refresh_token grants
 * - Secure credential retrieval from vault
 * - PSR-18 compliant HTTP client
 * - Automatic fallback to client_credentials if refresh_token rejected
 */
final class OAuthTokenManager
{
    /**
     * Cached tokens indexed by config hash.
     *
     * @var array<string, OAuthToken>
     */
    private array $tokenCache = [];

    private readonly RequestFactoryInterface $requestFactory;

    private readonly StreamFactoryInterface $streamFactory;

    public function __construct(
        private readonly VaultServiceInterface $vaultService,
        private readonly ?LoggerInterface $logger = null,
        private readonly ClientInterface $httpClient = new Client(['timeout' => 30, 'connect_timeout' => 10]),
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        private readonly ?AuditLogServiceInterface $auditLogService = null,
    ) {
        $httpFactory = new HttpFactory();
        $this->requestFactory = $requestFactory ?? $httpFactory;
        $this->streamFactory = $streamFactory ?? $httpFactory;
    }

    public function __destruct()
    {
        $this->clearToken();
    }

    /**
     * Get a valid access token for the given OAuth config.
     *
     * Automatically refreshes the token if it's expired or about to expire.
     *
     * @throws OAuthException If token cannot be obtained
     */
    public function getAccessToken(OAuthConfig $config): string
    {
        $cacheKey = $this->getCacheKey($config);

        // Check cache
        if (isset($this->tokenCache[$cacheKey])) {
            $cachedToken = $this->tokenCache[$cacheKey];

            if (!$cachedToken->isExpired($config->tokenExpiryBuffer)) {
                return $cachedToken->accessToken;
            }

            // Token expired or about to expire, refresh it
            $this->logger?->debug('OAuth token expired or about to expire, refreshing');
        }

        // Fetch new token, with fallback to client_credentials on refresh failure.
        $token = $this->fetchTokenWithFallback($config);
        $this->tokenCache[$cacheKey] = $token;

        return $token->accessToken;
    }

    /**
     * Clear the token cache for a specific config or all configs.
     */
    public function clearCache(?OAuthConfig $config = null): void
    {
        if ($config instanceof OAuthConfig) {
            $cacheKey = $this->getCacheKey($config);
            unset($this->tokenCache[$cacheKey]);
        } else {
            $this->tokenCache = [];
        }
    }

    /**
     * Clear the cached token references to allow garbage collection.
     *
     * Since OAuthToken is readonly, sodium_memzero cannot be used on its properties.
     * This method nulls the cache references so the token objects can be collected.
     */
    public function clearToken(): void
    {
        $this->tokenCache = [];
    }

    /**
     * Attempt to fetch a token; on refresh_token rejection, fall back to a
     * client_credentials grant when the failure clearly indicates the
     * refresh token itself is bad (not a server outage or config error).
     *
     * The fallback trigger is deliberately narrow:
     *
     *  - original grant type MUST be `refresh_token`, AND
     *  - the token endpoint responded HTTP 400 or 401
     *    (RFC 6749 §5.2 permits either for invalid refresh tokens), AND
     *  - the OAuth error field (when present) is `invalid_grant`
     *    or `invalid_token`.
     *
     * Any other failure — HTTP 5xx, 429, 400 without `invalid_grant`,
     * network errors, JSON decode errors — re-throws the original
     * exception so the caller can see the real cause and back off /
     * alert rather than masking it with an identical retry.
     *
     * Both the failed refresh and the subsequent fallback are audit-
     * logged so an operator can see the fallback happened.
     *
     * @throws OAuthException If both refresh and fallback fail
     */
    private function fetchTokenWithFallback(OAuthConfig $config): OAuthToken
    {
        if ($config->grantType !== 'refresh_token') {
            return $this->fetchToken($config);
        }

        try {
            return $this->fetchToken($config);
        } catch (OAuthException $e) {
            // Only fall back when the OAuth server specifically rejected
            // the refresh token. Everything else (5xx, 429, transport
            // errors, invalid_client, invalid_request) bubbles up so a
            // real outage / misconfig is not masked by retry noise.
            $shouldFallBack =
                $e->getCode() === 2477018617
                && ($e->httpStatus === 400 || $e->httpStatus === 401)
                && ($e->oauthError === null || \in_array($e->oauthError, ['invalid_grant', 'invalid_token'], true));

            if (!$shouldFallBack) {
                throw $e;
            }

            $this->logger?->warning('OAuth refresh_token rejected, falling back to client_credentials', [
                'token_endpoint' => $config->tokenEndpoint,
                'original_error' => $e->getMessage(),
            ]);

            // Audit the failed refresh attempt so the fallback is not silent.
            $this->auditLogService?->log(
                $config->refreshTokenSecret ?? $config->clientIdSecret,
                'oauth_refresh_failed',
                false,
                $e->getMessage(),
                'refresh_token rejected by OAuth server (HTTP non-200)',
            );

            // Build a client_credentials config with the same endpoint & scopes.
            $fallback = new OAuthConfig(
                tokenEndpoint: $config->tokenEndpoint,
                clientIdSecret: $config->clientIdSecret,
                clientSecretSecret: $config->clientSecretSecret,
                grantType: 'client_credentials',
                refreshTokenSecret: null,
                scopes: $config->scopes,
                tokenExpiryBuffer: $config->tokenExpiryBuffer,
                additionalParams: $config->additionalParams,
            );

            $token = $this->fetchToken($fallback);

            // Audit the successful fallback.
            $this->auditLogService?->log(
                $config->clientIdSecret,
                'oauth_fallback_client_credentials',
                true,
                null,
                'fell back to client_credentials after refresh_token rejection',
            );

            return $token;
        }
    }

    /**
     * Fetch a new token from the OAuth server.
     *
     * @throws OAuthException If token request fails
     */
    private function fetchToken(OAuthConfig $config): OAuthToken
    {
        // Build the request params VO (holds credentials/refresh_token from
        // vault). Plaintext is wiped via `wipeCredentials()` in the
        // `finally` block regardless of send success.
        $params = $this->buildTokenRequestParams($config);

        try {
            $response = $this->dispatchTokenRequest($config, $params);
            $this->assertSuccessResponse($response);
            $body = $this->decodeTokenBody($response);

            $token = $this->buildToken($body);
            $this->storeRotatedRefreshToken($config, $body);

            $this->logger?->info('OAuth token obtained successfully', [
                'expires_in' => $token->expiresAt->getTimestamp() - time(),
                'token_type' => $token->tokenType,
            ]);

            return $token;
        } catch (ClientExceptionInterface $e) {
            $this->logger?->error('OAuth token request failed', ['error' => $e->getMessage()]);

            throw OAuthException::requestFailed($e->getMessage(), $e);
        } catch (JsonException $e) {
            throw OAuthException::invalidJsonResponse($e);
        } finally {
            $params->wipeCredentials();
        }
    }

    /**
     * Resolve credentials from the vault and assemble the OAuth token-request
     * parameter VO. The returned object holds credential plaintext until
     * `wipeCredentials()` is called — the caller is responsible for that.
     *
     * @throws SecretNotFoundException If any required credential isn't in the vault
     */
    private function buildTokenRequestParams(OAuthConfig $config): OAuthTokenRequestParams
    {
        $clientId = $this->vaultService->retrieve($config->clientIdSecret);
        if ($clientId === null) {
            throw new SecretNotFoundException($config->clientIdSecret, 6051576903);
        }

        $clientSecret = $this->vaultService->retrieve($config->clientSecretSecret);
        if ($clientSecret === null) {
            sodium_memzero($clientId);

            throw new SecretNotFoundException($config->clientSecretSecret, 4158358265);
        }

        $refreshToken = null;
        if ($config->grantType === 'refresh_token' && $config->refreshTokenSecret !== null) {
            $refreshToken = $this->vaultService->retrieve($config->refreshTokenSecret);
            if ($refreshToken === null) {
                sodium_memzero($clientId);
                sodium_memzero($clientSecret);

                throw new SecretNotFoundException($config->refreshTokenSecret, 6618787426);
            }
        }

        return new OAuthTokenRequestParams(
            grantType: $config->grantType,
            clientId: $clientId,
            clientSecret: $clientSecret,
            scope: $config->scopes !== [] ? $config->getScopesString() : null,
            refreshToken: $refreshToken,
            additionalParams: $config->additionalParams,
        );
    }

    /**
     * Send the PSR-7 token request. Caller owns the `$params` VO and is
     * responsible for calling `$params->wipeCredentials()` after this
     * returns (whether by exception or normal return).
     */
    private function dispatchTokenRequest(OAuthConfig $config, OAuthTokenRequestParams $params): ResponseInterface
    {
        $body = $this->streamFactory->createStream($params->toHttpQuery());
        $request = $this->requestFactory->createRequest('POST', $config->tokenEndpoint)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($body);

        return $this->httpClient->sendRequest($request);
    }

    /**
     * Assert HTTP 200 — extract the RFC 6749 §5.2 `error` field on non-200 so
     * `fetchTokenWithFallback()` can distinguish `invalid_grant` (refresh
     * token rejected → fallback makes sense) from `invalid_client` (wrong
     * secret → fallback would also fail).
     *
     * @throws OAuthException
     */
    private function assertSuccessResponse(ResponseInterface $response): void
    {
        if ($response->getStatusCode() === 200) {
            return;
        }
        $oauthError = $this->extractOauthErrorField($response);

        throw OAuthException::tokenRequestFailed($response->getStatusCode(), $oauthError);
    }

    private function extractOauthErrorField(ResponseInterface $response): ?string
    {
        $rawBody = (string) $response->getBody();
        if ($rawBody === '') {
            return null;
        }

        try {
            /** @var array<string, mixed>|null $errorBody */
            $errorBody = json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
        if (\is_array($errorBody) && isset($errorBody['error']) && \is_string($errorBody['error'])) {
            return $errorBody['error'];
        }

        return null;
    }

    /**
     * @throws JsonException
     * @throws OAuthException
     *
     * @return array<string, mixed>
     */
    private function decodeTokenBody(ResponseInterface $response): array
    {
        /** @var array<string, mixed>|null $body */
        $body = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        if (!\is_array($body) || !isset($body['access_token'])) {
            throw OAuthException::missingAccessToken();
        }

        return $body;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function buildToken(array $body): OAuthToken
    {
        $accessToken = \is_string($body['access_token']) ? $body['access_token'] : '';
        $tokenType = \is_string($body['token_type'] ?? null) ? $body['token_type'] : 'Bearer';
        $scope = isset($body['scope']) && \is_string($body['scope']) ? $body['scope'] : null;
        $expiresIn = \is_int($body['expires_in'] ?? null) ? $body['expires_in'] : 3600;

        return new OAuthToken(
            accessToken: $accessToken,
            tokenType: $tokenType,
            expiresAt: new DateTimeImmutable('+' . $expiresIn . ' seconds'),
            scope: $scope,
        );
    }

    /**
     * Persist a rotated refresh token if the server returned one.
     *
     * Crash safety: the OAuth server has already issued the new tokens and
     * (per RFC 6749 §6) will typically have invalidated the old refresh
     * token. If `vaultService->store()` throws here we must NOT propagate —
     * the caller would lose the access_token we just obtained, and the
     * vault would still hold the now-invalidated old refresh_token.
     * Instead: log loudly, return the access_token so the caller's current
     * request succeeds. The next refresh attempt will fetch the stale
     * refresh_token from the vault, the OAuth server will reject it, and
     * `fetchTokenWithFallback()` will auto-recover via the
     * `client_credentials` flow.
     *
     * @param array<string, mixed> $body
     */
    private function storeRotatedRefreshToken(OAuthConfig $config, array $body): void
    {
        if (!isset($body['refresh_token']) || !\is_string($body['refresh_token']) || $config->refreshTokenSecret === null) {
            return;
        }

        try {
            $this->vaultService->store($config->refreshTokenSecret, $body['refresh_token'], [
                'source' => 'oauth_refresh',
            ]);
        } catch (Throwable $storeException) {
            $this->handleRefreshTokenStorageFailure($config, $storeException);
        }
    }

    /**
     * Best-effort reporting of a refresh-token storage failure.
     *
     * Crash-safe by design: both the PSR-3 logger and the audit-log writer
     * are wrapped in their own `try/catch` because they likely share the
     * same DB as the failing vault — propagating either would still cost
     * the caller the access_token they just obtained. Final fallback is
     * `error_log()`, which writes via PHP's own error handler and does
     * not depend on the DB.
     *
     * The vault identifier (`refreshTokenSecret`) is hashed before
     * logging — the path itself reveals which secrets exist in the vault
     * and is useful enough to attackers that we treat it as semi-secret.
     */
    private function handleRefreshTokenStorageFailure(OAuthConfig $config, Throwable $storeException): void
    {
        $secretIdHash = $config->refreshTokenSecret !== null
            ? substr(hash('sha256', $config->refreshTokenSecret), 0, 16)
            : null;

        $message = 'OAuth refresh_token rotation: vault store failed — returning access_token but '
            . 'subsequent refresh will fail until vault is writeable (auto-recovers via '
            . 'fetchTokenWithFallback()).';
        $context = [
            'token_endpoint' => $config->tokenEndpoint,
            'refresh_token_secret_hash' => $secretIdHash,
            'error' => $storeException->getMessage(),
        ];

        try {
            $this->logger?->error($message, $context);
        } catch (Throwable) {
            // Last-resort: PHP's own error log is independent of DB / logger backend.
            error_log('nr-vault: ' . $message . ' [' . $storeException->getMessage() . ']');
        }

        try {
            $this->auditLogService?->log(
                $config->refreshTokenSecret ?? '',
                'oauth_refresh_store_failed',
                false,
                'vault store of new refresh_token failed; access_token returned to caller, '
                . 'next refresh will fall back to client_credentials',
            );
        } catch (Throwable) {
            // Audit log likely uses the same DB as the vault — propagating
            // here would still cost the caller the access_token. The
            // logger->error above already captured the failure.
        }
    }

    /**
     * Generate a cache key for an OAuth config.
     *
     * Cache key is identity-only — used to look up an in-memory `OAuthToken`.
     * Uses xxh128 (PHP 8.1+ non-cryptographic hash) because it's fast and
     * collision-resistant enough for cache-keying; we avoid md5/sha1 because
     * Sonar flags them across the board, and avoid sha256 because the extra
     * cost is wasted for a non-security use.
     */
    private function getCacheKey(OAuthConfig $config): string
    {
        return hash('xxh128', implode(':', [
            $config->tokenEndpoint,
            $config->clientIdSecret,
            $config->grantType,
            $config->getScopesString(),
        ]));
    }
}
