<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http;

use GuzzleHttp\Psr7\Utils;
use JsonException;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HttpCallContext;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Http\OAuth\OAuthTokenManager;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * PSR-18 HTTP client that injects vault secrets as authentication.
 *
 * This is an immutable, fluent PSR-18 client. Configure authentication
 * with withAuthentication() or withOAuth(), then send requests with sendRequest().
 *
 * TYPO3 HTTP Settings:
 * This client respects TYPO3's HTTP configuration ($GLOBALS['TYPO3_CONF_VARS']['HTTP']):
 * - proxy: Corporate proxy settings from TYPO3 or environment (HTTP_PROXY, HTTPS_PROXY)
 * - verify, cert, ssl_key: SSL/TLS certificate configuration
 * - timeout, connect_timeout: Connection timeouts
 *   (the total-duration `timeout` can be overridden per instance via withTimeout())
 * - allow_redirects: Redirect behavior
 *
 * Security Hardening:
 * - debug is always disabled to prevent request/response logging that could expose secrets
 * - http_errors is disabled so this client can handle errors and audit them properly
 *
 * Supports various authentication types via SecretPlacement enum:
 * - Bearer: Bearer token in Authorization header
 * - BasicAuth: HTTP Basic Authentication
 * - Header: Custom header with secret value
 * - QueryParam: Query parameter with secret value
 * - BodyField: Secret in request body (JSON or form)
 * - OAuth2: OAuth 2.0 with automatic token refresh
 * - ApiKey: X-API-Key header (shorthand)
 *
 * @example
 *     // Create request using TYPO3's RequestFactory
 *     $requestFactory = GeneralUtility::makeInstance(RequestFactory::class);
 *     $request = $requestFactory->createRequest('GET', 'https://api.example.com/data');
 *
 *     // Bearer token authentication
 *     $client = $vault->http()->withAuthentication('stripe_key', SecretPlacement::Bearer);
 *     $response = $client->sendRequest($request);
 *
 *     // OAuth 2.0
 *     $client = $vault->http()->withOAuth($oauthConfig);
 *     $response = $client->sendRequest($request);
 *
 * @see SecureHttpClientFactory for TYPO3 HTTP configuration handling
 */
final readonly class VaultHttpClient implements VaultHttpClientInterface
{
    private ClientInterface $innerClient;

    private OAuthTokenManager $oauthManager;

    private SecureHttpClientFactory $secureHttpClientFactory;

    /**
     * @param VaultServiceInterface $vaultService Vault for secret retrieval
     * @param AuditLogServiceInterface $auditLogService Audit logging
     * @param ClientInterface|null $innerClient Underlying PSR-18 client
     * @param string|null $secretIdentifier Configured secret identifier
     * @param SecretPlacement|null $placement Configured placement type
     * @param OAuthConfig|null $oauthConfig Configured OAuth config
     * @param string|null $headerName Custom header name for Header placement
     * @param string|null $queryParam Custom query param for QueryParam placement
     * @param string|null $bodyField Custom body field for BodyField placement
     * @param string|null $usernameSecretIdentifier Username secret for BasicAuth
     * @param string $reason Audit log reason
     * @param OAuthTokenManager|null $oauthManager Reusable token manager
     *                                             carrying the token cache across `with*()` clones. When null, the
     *                                             constructor builds a fresh one bound to the inner client. The
     *                                             `with*()` methods MUST forward the existing instance so a single
     *                                             fluent chain (e.g. `$vault->http()->withOAuth($cfg)->sendRequest()`)
     *                                             hits the IdP at most once per token lifetime instead of once per
     *                                             clone. Trailing position (after `$reason`) preserves positional BC
     *                                             for callers built against the pre-PR signature.
     * @param SecureHttpClientFactory|null $secureHttpClientFactory Factory
     *                                                              used for (a) building the inner client when none is injected and
     *                                                              (b) the `isHostAllowed()` gate the OAuth manager applies to its
     *                                                              token endpoint. When null, `GeneralUtility::makeInstance()` resolves
     *                                                              it from the DI container. Trailing position preserves positional BC.
     * @param string|null $authPrefix Optional scheme/prefix prepended to the secret for Header
     *                                placement (e.g. "Key " → "Authorization: Key <secret>").
     *                                Logically a Header-placement option, but placed last in the
     *                                signature to preserve positional BC for pre-PR callers.
     */
    public function __construct(
        private VaultServiceInterface $vaultService,
        private AuditLogServiceInterface $auditLogService,
        ?ClientInterface $innerClient = null,
        private ?string $secretIdentifier = null,
        private ?SecretPlacement $placement = null,
        private ?OAuthConfig $oauthConfig = null,
        private ?string $headerName = null,
        private ?string $queryParam = null,
        private ?string $bodyField = null,
        private ?string $usernameSecretIdentifier = null,
        private string $reason = 'HTTP API call',
        ?OAuthTokenManager $oauthManager = null,
        ?SecureHttpClientFactory $secureHttpClientFactory = null,
        private ?string $authPrefix = null,
    ) {
        // Resolve the factory once: it builds the inner client (when missing)
        // AND backs the OAuth manager's `isHostAllowed()` gate. VaultHttpClient
        // is a fluent immutable value-object instantiated per call chain, not
        // a long-lived DI service — `makeInstance()` is the standard TYPO3
        // bootstrap path here (same pattern as before this PR).
        $this->secureHttpClientFactory = $secureHttpClientFactory
            ?? GeneralUtility::makeInstance(SecureHttpClientFactory::class);

        $this->innerClient = $innerClient ?? $this->secureHttpClientFactory->create();

        // Share the hardened innerClient with the OAuth manager so token
        // requests inherit the SSRF / DNS-rebinding / no-redirect defences.
        // The shared factory also lets the manager call `isHostAllowed()` on
        // the token endpoint — closes the allowed_hosts allowlist gap that
        // the request-time middleware doesn't cover.
        $this->oauthManager = $oauthManager ?? new OAuthTokenManager(
            $this->vaultService,
            $this->innerClient,
            $this->secureHttpClientFactory,
        );
    }

    public function withAuthentication(
        string $secretIdentifier,
        SecretPlacement $placement = SecretPlacement::Bearer,
        array $options = [],
    ): static {
        return new self(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $this->innerClient,
            secretIdentifier: $secretIdentifier,
            placement: $placement,
            headerName: $options['headerName'] ?? null,
            queryParam: $options['queryParam'] ?? null,
            bodyField: $options['bodyField'] ?? null,
            usernameSecretIdentifier: $options['usernameSecret'] ?? null,
            reason: $options['reason'] ?? $this->reason,
            oauthManager: $this->oauthManager,
            secureHttpClientFactory: $this->secureHttpClientFactory,
            authPrefix: $options['prefix'] ?? null,
        );
    }

    public function withOAuth(OAuthConfig $config, string $reason = 'OAuth2 API call'): static
    {
        return new self(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $this->innerClient,
            placement: SecretPlacement::OAuth2,
            oauthConfig: $config,
            reason: $reason,
            oauthManager: $this->oauthManager,
            secureHttpClientFactory: $this->secureHttpClientFactory,
        );
    }

    public function withReason(string $reason): static
    {
        return new self(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $this->innerClient,
            secretIdentifier: $this->secretIdentifier,
            placement: $this->placement,
            oauthConfig: $this->oauthConfig,
            headerName: $this->headerName,
            queryParam: $this->queryParam,
            bodyField: $this->bodyField,
            usernameSecretIdentifier: $this->usernameSecretIdentifier,
            reason: $reason,
            oauthManager: $this->oauthManager,
            secureHttpClientFactory: $this->secureHttpClientFactory,
            authPrefix: $this->authPrefix,
        );
    }

    public function withTimeout(int $seconds): static
    {
        // PSR-18 sendRequest() carries no per-request options, so the override
        // must be baked into the inner Guzzle client's configuration. The
        // shared SecureHttpClientFactory rebuilds the inner client with the
        // full security hardening (SSRF DNS pinning, debug off, redirects off)
        // plus the `timeout` override, so EVERY send path through the returned
        // instance — plain and authenticated alike — honours it. Non-positive
        // values rebuild with the platform default (no override). A custom
        // inner client injected at construction time is replaced by the
        // factory-built one. The forwarded OAuth token manager keeps its own
        // platform-default client: the override governs the API call, not the
        // token-endpoint round trip, and forwarding preserves the token cache.
        return new self(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $this->secureHttpClientFactory->create($seconds > 0 ? $seconds : null),
            secretIdentifier: $this->secretIdentifier,
            placement: $this->placement,
            oauthConfig: $this->oauthConfig,
            headerName: $this->headerName,
            queryParam: $this->queryParam,
            bodyField: $this->bodyField,
            usernameSecretIdentifier: $this->usernameSecretIdentifier,
            reason: $this->reason,
            oauthManager: $this->oauthManager,
            secureHttpClientFactory: $this->secureHttpClientFactory,
            authPrefix: $this->authPrefix,
        );
    }

    /**
     * Send an HTTP request with configured authentication.
     *
     * @throws ClientExceptionInterface If request fails
     * @throws VaultException If secret retrieval fails
     */
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        // Validate scheme (only HTTP/HTTPS allowed to prevent file://, gopher://, etc.)
        $scheme = strtolower($request->getUri()->getScheme());
        if ($scheme !== 'https' && $scheme !== 'http') {
            throw new VaultException(
                \sprintf('Unsupported URI scheme "%s"; only https and http are allowed', $scheme),
                1735858523,
            );
        }

        // Validate host against allowlist before injecting authentication secrets
        $host = strtolower($request->getUri()->getHost());
        if (!$this->secureHttpClientFactory->isHostAllowed($host)) {
            throw new VaultException(
                \sprintf('Host "%s" is not in the allowed hosts list', $host),
                1735858522,
            );
        }

        $authenticatedRequest = $this->injectAuthentication($request);
        $secretForAudit = $this->getSecretIdentifierForAudit();

        try {
            $response = $this->innerClient->sendRequest($authenticatedRequest);

            $this->logHttpCall(
                $secretForAudit,
                $request->getMethod(),
                (string) $request->getUri(),
                $response->getStatusCode(),
                true,
                null,
            );

            return $response;
        } catch (ClientExceptionInterface $e) {
            $this->logHttpCall(
                $secretForAudit,
                $request->getMethod(),
                (string) $request->getUri(),
                0,
                false,
                $e->getMessage(),
            );

            throw $e;
        }
    }

    /**
     * Inject authentication into the request based on configuration.
     */
    private function injectAuthentication(RequestInterface $request): RequestInterface
    {
        if ($this->oauthConfig instanceof OAuthConfig) {
            return $this->injectOAuth($request);
        }

        if ($this->secretIdentifier === null || !$this->placement instanceof SecretPlacement) {
            return $request;
        }

        return match ($this->placement) {
            SecretPlacement::Bearer => $this->injectBearer($request),
            SecretPlacement::BasicAuth => $this->injectBasicAuth($request),
            SecretPlacement::Header => $this->injectHeader($request),
            SecretPlacement::ApiKey => $this->injectApiKey($request),
            SecretPlacement::QueryParam => $this->injectQueryParam($request),
            SecretPlacement::BodyField => $this->injectBodyField($request),
            SecretPlacement::OAuth2 => $request, // Handled above
        };
    }

    private function injectBearer(RequestInterface $request): RequestInterface
    {
        \assert($this->secretIdentifier !== null);
        $secret = $this->retrieveSecret($this->secretIdentifier);

        try {
            return $request->withHeader('Authorization', 'Bearer ' . $secret);
        } finally {
            sodium_memzero($secret);
        }
    }

    private function injectBasicAuth(RequestInterface $request): RequestInterface
    {
        \assert($this->secretIdentifier !== null);
        $password = $this->retrieveSecret($this->secretIdentifier);

        if ($this->usernameSecretIdentifier !== null) {
            $username = $this->retrieveSecret($this->usernameSecretIdentifier);
            $credentials = $username . ':' . $password;
            sodium_memzero($username);
        } else {
            $credentials = $password;
        }

        try {
            return $request->withHeader('Authorization', 'Basic ' . base64_encode($credentials));
        } finally {
            sodium_memzero($password);
            sodium_memzero($credentials);
        }
    }

    private function injectHeader(RequestInterface $request): RequestInterface
    {
        \assert($this->secretIdentifier !== null);
        $secret = $this->retrieveSecret($this->secretIdentifier);
        $headerName = $this->headerName ?? 'X-API-Key';
        // Optional auth scheme/prefix ("Key " for FAL, "DeepL-Auth-Key " for DeepL) so
        // non-Bearer "Authorization: <scheme> <secret>" schemes use audited injection.
        // Only concatenate when a prefix is set: for the common no-prefix case this avoids
        // copying the secret into a second buffer (extra allocation + wider exposure window).
        $value = $this->authPrefix !== null ? $this->authPrefix . $secret : $secret;

        try {
            return $request->withHeader($headerName, $value);
        } finally {
            sodium_memzero($secret);
            // $value is a distinct buffer only when a prefix was prepended; otherwise it
            // aliases $secret (already zeroed above), so a second memzero would be redundant.
            if ($this->authPrefix !== null) {
                sodium_memzero($value);
            }
        }
    }

    private function injectApiKey(RequestInterface $request): RequestInterface
    {
        \assert($this->secretIdentifier !== null);
        $secret = $this->retrieveSecret($this->secretIdentifier);

        try {
            return $request->withHeader('X-API-Key', $secret);
        } finally {
            sodium_memzero($secret);
        }
    }

    private function injectQueryParam(RequestInterface $request): RequestInterface
    {
        \assert($this->secretIdentifier !== null);
        $secret = $this->retrieveSecret($this->secretIdentifier);
        $paramName = $this->queryParam ?? 'api_key';

        try {
            $uri = $request->getUri();
            $existingQuery = $uri->getQuery();
            $separator = $existingQuery !== '' ? '&' : '';
            $newQuery = $existingQuery . $separator . urlencode($paramName) . '=' . urlencode($secret);

            return $request->withUri($uri->withQuery($newQuery));
        } finally {
            sodium_memzero($secret);
        }
    }

    private function injectBodyField(RequestInterface $request): RequestInterface
    {
        \assert($this->secretIdentifier !== null);
        $secret = $this->retrieveSecret($this->secretIdentifier);
        $fieldName = $this->bodyField ?? 'api_key';

        try {
            $contentType = $request->getHeaderLine('Content-Type');
            $body = (string) $request->getBody();

            if (str_contains($contentType, 'application/json')) {
                $data = $this->decodeJsonObjectBody($body);
                $data[$fieldName] = $secret;
                $newBody = json_encode($data, JSON_THROW_ON_ERROR);
            } else {
                parse_str($body, $data);
                $data[$fieldName] = $secret;
                $newBody = http_build_query($data);
            }

            $result = $request->withBody(Utils::streamFor($newBody));
            sodium_memzero($newBody);

            return $result;
        } finally {
            sodium_memzero($secret);
        }
    }

    /**
     * Decode a JSON request body into a string-keyed array suitable for adding
     * the secret field.
     *
     * An empty (or whitespace-only) body is treated as "no fields yet" and
     * yields `[]`. Anything else MUST be a JSON object — a scalar (`"x"`,
     * `42`, `true`) would make the subsequent `$data[$field] = ...` fatal,
     * and a JSON array/list (including the empty list `[]`) would silently
     * reshape into a mixed-key structure. Both indicate the caller paired a
     * non-object body with body-field secret injection, so we fail loudly
     * instead of corrupting it. Malformed JSON is rejected explicitly for the
     * same reason — the old `?: []` coercion silently dropped the payload.
     *
     * Because `json_decode(..., true)` maps both `{}` and `[]` to the same
     * PHP value (`[]`), the decoded value alone cannot distinguish an empty
     * object from an empty list; the first non-whitespace character is the
     * deterministic discriminator (a JSON object always starts with `{`).
     *
     * @throws VaultException If the body is non-empty but not a JSON object
     *
     * @return array<string, mixed>
     */
    private function decodeJsonObjectBody(string $body): array
    {
        $trimmed = trim($body);
        if ($trimmed === '') {
            return [];
        }

        if (!str_starts_with($trimmed, '{')) {
            throw new VaultException(
                'Cannot inject body-field secret: request body must be a JSON object',
                1735858524,
            );
        }

        try {
            $decoded = json_decode($trimmed, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new VaultException(
                'Cannot inject body-field secret: request body is not valid JSON',
                1781076764,
                $exception,
            );
        }

        // Type guard for static analysis plus rejection of JSON objects whose
        // numeric string keys decode to a PHP list ({"0":"a"} → [0 => 'a']) —
        // injecting a named field there would re-encode a reshaped structure.
        if (!\is_array($decoded) || ($decoded !== [] && array_is_list($decoded))) {
            throw new VaultException(
                'Cannot inject body-field secret: request body must be a JSON object',
                1735858524,
            );
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    private function injectOAuth(RequestInterface $request): RequestInterface
    {
        \assert($this->oauthConfig instanceof OAuthConfig);
        $accessToken = $this->oauthManager->getAccessToken($this->oauthConfig);

        try {
            return $request->withHeader('Authorization', 'Bearer ' . $accessToken);
        } finally {
            sodium_memzero($accessToken);
        }
    }

    /**
     * Retrieve secret from vault, throwing if not found.
     */
    private function retrieveSecret(string $identifier): string
    {
        $secret = $this->vaultService->retrieve($identifier);

        if ($secret === null) {
            throw new SecretNotFoundException($identifier, 1735858521);
        }

        return $secret;
    }

    /**
     * Get the secret identifier for audit logging.
     */
    private function getSecretIdentifierForAudit(): string
    {
        if ($this->oauthConfig instanceof OAuthConfig) {
            return 'oauth2:' . $this->oauthConfig->clientIdSecret;
        }

        return $this->secretIdentifier ?? 'none';
    }

    /**
     * Log HTTP call to audit log.
     */
    private function logHttpCall(
        string $secretIdentifier,
        string $method,
        string $url,
        int $statusCode,
        bool $success,
        ?string $errorMessage,
    ): void {
        $this->auditLogService->log(
            $secretIdentifier,
            'http_call',
            $success,
            $errorMessage,
            $this->reason,
            null,
            null,
            HttpCallContext::fromRequest($method, $url, $statusCode),
        );
    }
}
