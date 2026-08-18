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
use GuzzleHttp\Promise\Utils as PromiseUtils;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\RequestOptions;
use JsonException;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HttpCallContext;
use Netresearch\NrVault\Exception\OAuthException;
use Netresearch\NrVault\Exception\RequestCancelledException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Http\CancellableTransport;
use Netresearch\NrVault\Http\CancellationSignalInterface;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
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
    private const REDACT_REPLACEMENT = '$1[REDACTED]';

    /**
     * The `reason` on every `oauth_token_request` audit row. A fixed literal:
     * the manager does not know the caller's reason, and the row records the
     * manager's own outbound call, not the caller's.
     */
    private const TOKEN_REQUEST_REASON = 'OAuth2 token round trip';

    /**
     * Fixed literal for a token request cancelled before anything egressed —
     * before the body carrying the credentials was even built. Fixed so the
     * audit row and the exception a caller sees can never carry a credential.
     */
    private const TOKEN_CANCELLED_BEFORE_SEND_MESSAGE
        = 'OAuth token request cancelled before send: nothing egressed';

    /**
     * Fixed literal for a token transfer aborted after it was handed to the
     * transport: the `client_secret` must be treated as exposed.
     */
    private const TOKEN_CANCELLED_IN_FLIGHT_MESSAGE
        = 'OAuth token request cancelled after send began: the client credential was handed to the transport';

    /**
     * Fixed literal for the tick loop's defensive wall-clock bound — a bug in
     * the transport, not something a caller did. Mirrors
     * `VaultHttpClient::TICK_BUDGET_EXHAUSTED_MESSAGE`.
     */
    private const TOKEN_TICK_BUDGET_EXHAUSTED_MESSAGE
        = 'Cancellable OAuth token transfer exceeded its wall-clock budget and was aborted';

    /**
     * Fixed literal for a transport that settled with something that is not a
     * PSR-7 response. Not reachable through any handler this package builds.
     */
    private const TOKEN_NON_RESPONSE_SETTLEMENT_MESSAGE
        = 'Cancellable OAuth token transport settled with a value that is not an HTTP response';

    /** Fixed literal for an async rejection reason that is not a throwable. */
    private const TOKEN_TRANSFER_REJECTED_MESSAGE
        = 'Cancellable OAuth token transfer was rejected';

    /**
     * Fixed literal for a throw the audit classification did not enumerate.
     * Pre-set so an unexpected error can never be the one round trip missing
     * from the log.
     */
    private const TOKEN_REQUEST_UNEXPECTED_MESSAGE
        = 'OAuth token request aborted by an unexpected error';

    /**
     * The RFC 6749 §5.2 / RFC 6750 §3.1 error codes this class recognises.
     *
     * A whitelist rather than a passthrough on purpose: the `error` field is
     * server-controlled free text, and since the `oauth_token_request` row
     * exists it would travel — bounded only by pattern redaction — into the
     * tamper-evident audit chain, where a row can never be deleted. A
     * compromised endpoint echoing a bare credential in that field must not
     * reach the chain. The only semantic consumer
     * (`fetchTokenWithFallback()`) cares about `invalid_grant` /
     * `invalid_token`; the rest exist so the exception message can still name
     * a well-formed error. Anything outside the list collapses to null, which
     * every consumer already handles.
     */
    private const KNOWN_OAUTH_ERROR_CODES = [
        'invalid_request',
        'invalid_client',
        'invalid_grant',
        'unauthorized_client',
        'unsupported_grant_type',
        'invalid_scope',
        'invalid_token',
        'insufficient_scope',
        'server_error',
        'temporarily_unavailable',
    ];

    /**
     * Cached tokens indexed by config hash.
     *
     * @var array<string, OAuthToken>
     */
    private array $tokenCache = [];

    private readonly RequestFactoryInterface $requestFactory;

    private readonly StreamFactoryInterface $streamFactory;

    /**
     * @param ClientInterface $httpClient HTTP client to dispatch the token
     *                                    request through. Callers MUST inject a hardened client (e.g. built
     *                                    by `SecureHttpClientFactory::create()`) — the default plain
     *                                    `GuzzleHttp\Client` was removed to prevent OAuth token endpoints
     *                                    bypassing the SSRF + DNS-rebinding + no-redirect-by-default guards.
     *                                    A misconfigured (or attacker-controlled) `OAuthConfig.tokenEndpoint`
     *                                    would otherwise leak the bearer `client_secret` to internal IPs,
     *                                    cloud-metadata services, or arbitrary redirect targets.
     * @param SecureHttpClientFactory $secureHttpClientFactory used ONLY to
     *                                                         gate the token endpoint host through `isHostAllowed()` before the
     *                                                         request is sent. The `$httpClient` middleware already rejects
     *                                                         dangerous resolved IPs at request time, but it does NOT apply the
     *                                                         `$GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']` allowlist
     *                                                         admins use to restrict outbound calls to a known set of partner
     *                                                         hostnames. Without this extra gate, an attacker-controlled
     *                                                         `tokenEndpoint` could reach any public host the IP guards consider
     *                                                         "safe" — defeating the allowlist on the OAuth leg only.
     * @param CancellableTransport|null $cancellableTransport Explicit transport
     *                                                        for a token request carrying a cancellation signal. Normally null:
     *                                                        the transport is built on demand from `$secureHttpClientFactory`,
     *                                                        so a manager whose callers never pass a signal pays nothing.
     *                                                        `@internal` test seam, mirroring the parameter of the same name on
     *                                                        `VaultHttpClient` — it is how the suite drives the token-leg tick
     *                                                        loop deterministically. Trailing position preserves positional BC.
     */
    public function __construct(
        private readonly VaultServiceInterface $vaultService,
        private readonly ClientInterface $httpClient,
        private readonly SecureHttpClientFactory $secureHttpClientFactory,
        private readonly ?LoggerInterface $logger = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        private readonly ?AuditLogServiceInterface $auditLogService = null,
        private readonly ?CancellableTransport $cancellableTransport = null,
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
     * @param CancellationSignalInterface|null $cancellationSignal When given,
     *                                                             the token round trip honours it: an already-set signal aborts
     *                                                             before any credential is read from the vault, and an in-flight
     *                                                             token POST is torn down through a cancellable transport built by
     *                                                             `SecureHttpClientFactory::createCancellable()` (issue #303).
     *                                                             That transport carries the same hardening as the manager's own
     *                                                             client but NOT a caller-supplied client's custom middleware —
     *                                                             callers who handed this manager their own `$httpClient` and need
     *                                                             its semantics must not pass a signal.
     *                                                             `VaultHttpClient::sendCancellable()` passes its signal exactly
     *                                                             when its own transfer runs cancellable, so the token leg and the
     *                                                             API leg degrade together. A cached, still-valid token is returned
     *                                                             without consulting the signal — it costs nothing and egresses
     *                                                             nothing.
     *
     * @throws OAuthException If token cannot be obtained
     * @throws RequestCancelledException When the signal aborted the token round trip
     */
    public function getAccessToken(OAuthConfig $config, ?CancellationSignalInterface $cancellationSignal = null): string
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

        // Checked BEFORE the vault is read: an already-cancelled call must not
        // retrieve the client credentials it will not use. No audit row here —
        // the `oauth_token_request` row records round trips attempted with
        // credentials in hand, and this abort never got that far. (On the
        // `sendCancellable()` path the CALL's own row is still written by
        // `VaultHttpClient::injectAuthenticationAudited()`.)
        if ($cancellationSignal instanceof CancellationSignalInterface && $cancellationSignal->isCancelled()) {
            throw new RequestCancelledException(self::TOKEN_CANCELLED_BEFORE_SEND_MESSAGE, 1786579301);
        }

        // Fetch new token, with fallback to client_credentials on refresh failure.
        $token = $this->fetchTokenWithFallback($config, $cancellationSignal);
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
    private function fetchTokenWithFallback(
        OAuthConfig $config,
        ?CancellationSignalInterface $cancellationSignal = null,
    ): OAuthToken {
        if ($config->grantType !== 'refresh_token') {
            return $this->fetchToken($config, $cancellationSignal);
        }

        try {
            return $this->fetchToken($config, $cancellationSignal);
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
                'original_error' => $this->redactCredentials($e->getMessage()),
            ]);

            // Audit the failed refresh attempt so the fallback is not silent.
            $this->auditLogService?->log(
                $config->refreshTokenSecret ?? $config->clientIdSecret,
                'oauth_refresh_failed',
                false,
                $this->redactCredentials($e->getMessage()),
                'refresh_token rejected by OAuth server (HTTP non-200)',
            );

            // Build a client_credentials config with the same endpoint & scopes.
            $fallback = new OAuthConfig(
                tokenEndpoint: $config->tokenEndpoint,
                clientIdSecret: $config->clientIdSecret,
                clientSecretSecret: $config->clientSecretSecret,
                grantType: 'client_credentials',
                scopes: $config->scopes,
                tokenExpiryBuffer: $config->tokenExpiryBuffer,
                additionalParams: $config->additionalParams,
            );

            $token = $this->fetchToken($fallback, $cancellationSignal);

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
     * Every attempted round trip leaves exactly one `oauth_token_request`
     * audit row (issue #303), written from the `finally` so no outcome can be
     * the one missing from the log — the outbound POST here carries the
     * `client_secret`, and until this row existed it left no trace at all.
     * The row opens once the credentials have been read from the vault; the
     * status is the endpoint's real answer where one arrived and `0` where
     * nothing was received, and the message is a fixed literal (or the
     * redacted upstream message) naming the failure. The vault's own rows
     * about reading the credentials, and the `oauth_refresh_*` rows about the
     * refresh flow, are unchanged — they answer different questions.
     *
     * @throws OAuthException If token request fails
     * @throws RequestCancelledException When the signal aborted the round trip
     */
    private function fetchToken(
        OAuthConfig $config,
        ?CancellationSignalInterface $cancellationSignal = null,
    ): OAuthToken {
        // Build the request params VO (holds credentials/refresh_token from
        // vault). Plaintext is wiped via `wipeCredentials()` in the
        // `finally` block regardless of send success.
        $params = $this->buildTokenRequestParams($config);

        $auditStatus = 0;
        $auditSuccess = false;
        $auditMessage = self::TOKEN_REQUEST_UNEXPECTED_MESSAGE;

        try {
            $response = $this->dispatchTokenRequest($config, $params, $cancellationSignal);
            $auditStatus = $response->getStatusCode();
            $this->assertSuccessResponse($response);
            $body = $this->decodeTokenBody($response);

            $token = $this->buildToken($body);
            $this->storeRotatedRefreshToken($config, $body);

            $this->logger?->info('OAuth token obtained successfully', [
                'expires_in' => $token->expiresAt->getTimestamp() - time(),
                'token_type' => $token->tokenType,
            ]);

            $auditSuccess = true;
            $auditMessage = null;

            return $token;
        } catch (RequestCancelledException $e) {
            // Both cancellation literals are fixed constants of this class —
            // safe on the row as-is, and they are what distinguishes "nothing
            // egressed" from "the credential was handed to the transport".
            $auditMessage = $e->getMessage();

            throw $e;
        } catch (OAuthException $e) {
            // The host-gate rejection (nothing egressed), a non-200 answer
            // (status recorded above), a missing access_token, the tick
            // loop's wall-clock bound. Messages are built by this package;
            // redaction is defence in depth.
            $auditMessage = $this->redactCredentials($e->getMessage());

            throw $e;
        } catch (ClientExceptionInterface $e) {
            $redacted = $this->redactCredentials($e->getMessage());
            $this->logger?->error('OAuth token request failed', [
                'error' => $redacted,
                'previous_class' => $e::class,
            ]);

            $auditMessage = $redacted;

            throw OAuthException::requestFailed(
                $redacted . \sprintf(' (caused by %s)', $e::class),
            );
        } catch (JsonException $e) {
            // Fixed literal, not the JsonException message: the parser error
            // quotes the response body, which nobody vetted for credentials.
            $auditMessage = 'OAuth token response is not valid JSON';

            throw OAuthException::invalidJsonResponse($e);
        } catch (Throwable $throwable) {
            $auditMessage = self::TOKEN_REQUEST_UNEXPECTED_MESSAGE
                . ': ' . $this->redactCredentials($throwable->getMessage());

            throw $throwable;
        } finally {
            // Wipe first (shortest plaintext residency during the DB write
            // below), audit second. The row's unconditionality rests on
            // wipeCredentials() never throwing — which its idempotence guard
            // guarantees (OAuthTokenRequestParams wipes each buffer at most
            // once); a throw here would both skip the row and mask the
            // original exception.
            $params->wipeCredentials();
            $this->auditTokenRoundTrip($config, $auditSuccess, $auditStatus, $auditMessage);
        }
    }

    /**
     * The one `oauth_token_request` row per attempted round trip.
     *
     * Written through the optional audit service: a manager constructed
     * without one (a standalone consumer) keeps working, and the row's
     * absence is that consumer's explicit choice. `VaultHttpClient` always
     * passes its own audit service since issue #303.
     */
    private function auditTokenRoundTrip(
        OAuthConfig $config,
        bool $success,
        int $statusCode,
        ?string $errorMessage,
    ): void {
        if (!$this->auditLogService instanceof AuditLogServiceInterface) {
            return;
        }

        try {
            $this->auditLogService->log(
                $config->clientIdSecret,
                AuditAction::OAuthTokenRequest->value,
                $success,
                $errorMessage,
                self::TOKEN_REQUEST_REASON,
                null,
                null,
                HttpCallContext::fromRequest('POST', $config->tokenEndpoint, $statusCode),
            );
        } catch (Throwable $auditException) {
            // Crash-safe like every other audit write in this class (see
            // handleRefreshTokenStorageFailure(), and the test that pins the
            // doctrine: getAccessTokenSurvivesAuditLogFailureDuringStorageFailure).
            // The round trip already happened — a throw from the `finally`
            // this is called from would cost the caller the token the OAuth
            // server just issued, or mask the real failure, and un-send
            // nothing. Fall back loudly instead.
            try {
                $this->logger?->error('OAuth token round trip could not be audited', [
                    'token_endpoint' => $config->tokenEndpoint,
                    'error' => $this->redactCredentials($auditException->getMessage()),
                ]);
            } catch (Throwable) {
                error_log(
                    'nr-vault: OAuth token round trip could not be audited: '
                    . $this->redactCredentials($auditException->getMessage()),
                );
            }
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
     * returns. The caller's `finally` in `fetchToken()` covers the case
     * where this method throws (Stream/Request factory or HTTP client) —
     * exception propagates up and the outer finally wipes credentials
     * regardless.
     */
    private function dispatchTokenRequest(
        OAuthConfig $config,
        OAuthTokenRequestParams $params,
        ?CancellationSignalInterface $cancellationSignal = null,
    ): ResponseInterface {
        // Gate the host BEFORE building the request body so the bearer
        // `client_secret` never gets serialised when the host is rejected
        // by the allowlist. The `$httpClient` middleware also rejects
        // dangerous IPs at request time, but it does NOT enforce the
        // `allowed_hosts` allowlist — this is the OAuth-leg equivalent of
        // the gate `VaultHttpClient::sendRequest()` applies on outer API
        // requests (see VaultHttpClient.php — same call shape).
        $host = parse_url($config->tokenEndpoint, PHP_URL_HOST);
        if (!\is_string($host) || !$this->secureHttpClientFactory->isHostAllowed($host)) {
            throw new OAuthException(
                \sprintf(
                    'OAuth token endpoint host "%s" is not in the allowed hosts list.',
                    \is_string($host) ? $host : '(unparseable)',
                ),
                3149205122,
            );
        }

        // Checked BEFORE the body carrying the credentials is built: the
        // credentials were already read from the vault (unavoidably — the
        // pre-read check lives in getAccessToken()), but a cancelled call
        // must not serialise or egress them. This also covers the degraded
        // blocking send below.
        if ($cancellationSignal instanceof CancellationSignalInterface && $cancellationSignal->isCancelled()) {
            throw new RequestCancelledException(self::TOKEN_CANCELLED_BEFORE_SEND_MESSAGE, 1786579302);
        }

        // `toHttpQuery()` builds a one-shot encoded body. Any throw from
        // the stream/request factories (or sendRequest) bubbles to the
        // outer `finally` in `fetchToken()` which calls
        // `$params->wipeCredentials()` — no `try/finally` needed here.
        $body = $this->streamFactory->createStream($params->toHttpQuery());
        $request = $this->requestFactory->createRequest('POST', $config->tokenEndpoint)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($body);

        if ($cancellationSignal instanceof CancellationSignalInterface) {
            return $this->dispatchCancellable($request, $cancellationSignal);
        }

        return $this->httpClient->sendRequest($request);
    }

    /**
     * Send the token request through a cancellable transport, aborting when
     * the signal says so (issue #303).
     *
     * The loop is the token-leg sibling of
     * `VaultHttpClient::sendCancellably()` and follows the same mechanics for
     * the same measured reasons documented there — `SYNCHRONOUS` deliberately
     * absent (it would route back to the blocking handler whose cancel is a
     * no-op), `ALLOW_REDIRECTS`/`HTTP_ERRORS` pinned per request, settlement
     * observed through a `then()` handler rather than `getState()`, the
     * global promise queue drained before the first tick and after every
     * tick, and one teardown site: every abnormal exit cancels the promise,
     * which is what closes the socket. It stays a private copy rather than a
     * shared helper because the two callers classify outcomes differently —
     * this one throws OAuth-flavoured exceptions and leaves the audit
     * bookkeeping to `fetchToken()`'s wrapper, while `sendCancellably()`
     * interleaves its own audit state with the loop.
     *
     * When no transport can be built (no `curl_multi_*` on this platform),
     * the call degrades to the manager's blocking client — the same degraded
     * mode `sendCancellable()` documents, and the pre-send signal check in
     * `dispatchTokenRequest()` has already run.
     *
     * @throws RequestCancelledException When the signal aborted the transfer
     * @throws OAuthException For the loop's own failure modes
     * @throws ClientExceptionInterface When the transfer itself failed
     */
    private function dispatchCancellable(
        RequestInterface $request,
        CancellationSignalInterface $cancellationSignal,
    ): ResponseInterface {
        $transport = $this->cancellableTransport
            ?? $this->secureHttpClientFactory->createCancellable();

        if (!$transport instanceof CancellableTransport) {
            return $this->httpClient->sendRequest($request);
        }

        $promise = null;

        try {
            $promise = $transport->client()->sendAsync($request, [
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::HTTP_ERRORS => false,
            ]);

            $settled = false;
            $rejected = false;
            $settledValue = null;
            $promise->then(
                static function (mixed $value) use (&$settled, &$settledValue): void {
                    $settled = true;
                    $settledValue = $value;
                },
                static function (mixed $reason) use (&$settled, &$rejected, &$settledValue): void {
                    $settled = true;
                    $rejected = true;
                    $settledValue = $reason;
                },
            );

            $ticker = $transport->ticker();
            $deadline = microtime(true) + $transport->wallClockBudgetSeconds();

            // Drained before the first tick: an already-rejected promise (the
            // SSRF middleware rejects synchronously) has its handler queued,
            // not run inline.
            PromiseUtils::queue()->run();

            while (!$settled) {
                if ($cancellationSignal->isCancelled()) {
                    throw new RequestCancelledException(self::TOKEN_CANCELLED_IN_FLIGHT_MESSAGE, 1786579303);
                }

                if (microtime(true) >= $deadline) {
                    throw new OAuthException(self::TOKEN_TICK_BUDGET_EXHAUSTED_MESSAGE, 1786579304);
                }

                $ticker->tick();
                PromiseUtils::queue()->run();
            }

            if ($rejected) {
                // A throwable reason (the SSRF middleware's RequestException,
                // a connect failure) is rethrown as itself so fetchToken()'s
                // ClientExceptionInterface handling treats it exactly like a
                // blocking-path failure.
                if ($settledValue instanceof Throwable) {
                    throw $settledValue;
                }

                throw new OAuthException(self::TOKEN_TRANSFER_REJECTED_MESSAGE, 1786579305);
            }

            if (!$settledValue instanceof ResponseInterface) {
                throw new OAuthException(self::TOKEN_NON_RESPONSE_SETTLEMENT_MESSAGE, 1786579306);
            }

            return $settledValue;
        } catch (Throwable $throwable) {
            // THE teardown: Promise::cancel() runs CurlMultiHandler's cancel
            // function, which removes the easy handle and closes the socket.
            // On a settled promise it returns immediately; null only when
            // sendAsync() itself threw.
            $promise?->cancel();

            throw $throwable;
        }
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

        if (
            \is_array($errorBody)
            && isset($errorBody['error'])
            && \is_string($errorBody['error'])
            && \in_array($errorBody['error'], self::KNOWN_OAUTH_ERROR_CODES, true)
        ) {
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
        $redactedError = $this->redactCredentials($storeException->getMessage());
        $context = [
            'token_endpoint' => $config->tokenEndpoint,
            'refresh_token_secret_hash' => $secretIdHash,
            'error' => $redactedError,
        ];

        try {
            $this->logger?->error($message, $context);
        } catch (Throwable) {
            // Last-resort: PHP's own error log is independent of DB / logger backend.
            error_log('nr-vault: ' . $message . ' [' . $redactedError . ']');
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
     *
     * The key folds in every input that changes WHICH token the endpoint
     * returns:
     *  - `clientSecretSecret` so a credential rotation that swaps the
     *    client_secret vault handle (without changing the client_id) gets a
     *    fresh slot rather than serving the pre-rotation token;
     *  - `refreshTokenSecret` so a config pointing at a different refresh-token
     *    source is a distinct identity;
     *  - `additionalParams` (audience / resource / tenant / …) so two configs
     *    that differ only in audience don't collide — otherwise a token minted
     *    for audience A leaks to a request asking for audience B.
     *
     * The cache holds the access token, NOT the secret VALUES — only the vault
     * identifiers and request params, which are non-sensitive enough to key on.
     */
    private function getCacheKey(OAuthConfig $config): string
    {
        // `additionalParams` (audience, resource, tenant, …) materially change
        // which token the endpoint returns. Two configs identical except for
        // these params MUST get distinct cache slots, otherwise a token minted
        // for audience A would be served to a request that asked for audience B
        // (cross-audience token confusion). Serialize deterministically (ksort)
        // so key order never affects the hash.
        $params = $config->additionalParams;
        ksort($params);

        return hash('xxh128', implode(':', [
            $config->tokenEndpoint,
            $config->clientIdSecret,
            $config->clientSecretSecret,
            $config->grantType,
            // For the refresh_token grant the refresh-token vault handle is part
            // of the identity — a config pointing at a different refresh-token
            // secret is a different token source.
            $config->refreshTokenSecret ?? '',
            $config->getScopesString(),
            hash('xxh128', json_encode($params, JSON_THROW_ON_ERROR)),
        ]));
    }

    /**
     * Defensive redaction of common credential patterns from upstream error
     * messages before they reach the logger / audit log / OAuthException.
     *
     * Guzzle's `RequestException::getMessage()` typically includes the RESPONSE
     * body, not the request — so a well-behaved server doesn't leak the
     * `client_secret` we sent. But:
     *
     *  - OAuth servers sometimes echo the offending input back, either in a
     *    JSON error body (`{"error":"...","client_secret":"xyz"}`) or quoted
     *    in prose (`Invalid client_secret 'xyz'`). RFC 6749 doesn't forbid it.
     *  - A future refactor could land HTTP Basic auth (`Authorization: Basic
     *    base64(client_id:client_secret)`) which DOES appear in
     *    `RequestException::getMessage()` when verbose error formatting kicks
     *    in.
     *  - Generic Bearer tokens shouldn't appear here today but the same
     *    pattern would mask them too.
     *
     * Defence in depth: never trust upstream error messages to be free of
     * credentials. Cheap to apply, eliminates an entire class of accidental
     * leaks through logs/audit/exception chains. All patterns are BOUNDED
     * (delimiter-anchored character classes, no `.*?`/nested quantifiers) so
     * they cannot trigger catastrophic regex backtracking.
     */
    private function redactCredentials(string $message): string
    {
        // Pass 1: prefix-anchored forms whose value runs to a delimiter. The
        // shared replacement keeps capture group 1 (the key/prefix) and drops
        // the value.
        $message = (string) preg_replace(
            [
                // form-encoded `client_secret=...` (request bodies, query strings)
                '/(client_secret=)[^&\s"\'<>]+/i',
                // form-encoded `refresh_token=...`
                '/(refresh_token=)[^&\s"\'<>]+/i',
                // Bearer / Basic Authorization headers (any case)
                '/(Authorization:\s*Bearer\s+)\S+/i',
                '/(Authorization:\s*Basic\s+)\S+/i',
            ],
            self::REDACT_REPLACEMENT,
            $message,
        );

        // Pass 2: quoted-value forms where the credential is wrapped in matching
        // quotes — a JSON error body (`"client_secret":"xyz"`) or a prose echo
        // (`client_secret 'xyz'`). Group 1 keeps the key + opening quote,
        // group 2 keeps the closing quote; the value between is dropped.
        return (string) preg_replace(
            [
                // JSON: "client_secret":"...", "refresh_token":"...", "access_token":"..."
                // The value part handles JSON escape sequences (`\"`, `\\`, …)
                // via the unrolled-loop idiom `[^"\x5c]*(?:\x5c.[^"\x5c]*)*`
                // (\x5c = backslash): a credential containing an escaped quote
                // would otherwise end the match early and leak its remainder.
                // The idiom is linear — each position is matched by exactly one
                // branch, so no catastrophic backtracking.
                '/("(?:client_secret|refresh_token|access_token)"\s*:\s*")[^"\x5c]*(?:\x5c.[^"\x5c]*)*(")/i',
                // Quoted echo: client_secret '...' or client_secret "..."
                '/((?:client_secret|refresh_token|access_token)\s+["\'])[^"\']*(["\'])/i',
            ],
            '$1[REDACTED]$2',
            $message,
        );
    }
}
