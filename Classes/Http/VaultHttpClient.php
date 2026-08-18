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

use GuzzleHttp\ClientInterface as GuzzleClientInterface;
use GuzzleHttp\Promise\Utils as PromiseUtils;
use GuzzleHttp\Psr7\Utils;
use GuzzleHttp\RequestOptions;
use JsonException;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HttpCallContext;
use Netresearch\NrVault\Exception\RequestCancelledException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Http\OAuth\OAuthTokenManager;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;
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
final readonly class VaultHttpClient implements VaultHttpClientInterface, CancellableHttpClientInterface
{
    /**
     * Fixed literal for a call refused before anything was sent.
     *
     * Never derived from the promise's rejection reason: transport error
     * strings on this client can contain the injected secret and are redacted
     * only on the way INTO the audit row.
     */
    private const CANCELLED_BEFORE_SEND_MESSAGE
        = 'Request cancelled before send: nothing egressed and no secret was retrieved';

    /**
     * Fixed literal for a call aborted after the credential was injected.
     *
     * Deliberately NOT phrased as "the bytes left the process": the signal can
     * turn true on the first pass through the loop, before the first tick, and
     * the handler only queued the easy handle at that point. What IS certain at
     * this point — and what separates this outcome from the pre-flight one — is
     * that the secret was retrieved, injected into the request and handed to the
     * transport, i.e. it must be treated as exposed.
     */
    private const CANCELLED_IN_FLIGHT_MESSAGE
        = 'Request cancelled after send began: credential injected and transfer handed to the transport';

    /**
     * Fixed literal for a throw that came from neither the transport nor this
     * class — the caller's signal or a ticker implementation — after the
     * credential had already been injected. The row is written from a `finally`
     * so that this case cannot be the one call missing from the log.
     */
    private const UNEXPECTED_OUTCOME_MESSAGE
        = 'Cancellable transfer aborted by an unexpected error after the credential was injected';

    /**
     * Fixed literal for the defensive wall-clock bound. Reaching it means the
     * transport stopped settling its promise, which is a bug in the handler and
     * not something a caller did.
     */
    private const TICK_BUDGET_EXHAUSTED_MESSAGE
        = 'Cancellable transfer exceeded its wall-clock budget and was aborted';

    /**
     * Fixed literal for a transport that settled with something that is not a
     * PSR-7 response. Not reachable through any handler this package builds;
     * it exists so the case cannot be silently returned as a response.
     */
    private const NON_RESPONSE_SETTLEMENT_MESSAGE
        = 'Cancellable transport settled with a value that is not an HTTP response';

    /**
     * Fixed literal for a throw out of the blocking send that is not a PSR-18
     * `ClientExceptionInterface` — `Client::applyOptions()` raises
     * `InvalidArgumentException` outside `Client::transfer()`'s try/catch, so a
     * bad option set leaves `sendRequest()` as a plain throw. The credential is
     * already injected by then, so the row is written from a `finally`.
     */
    private const UNEXPECTED_BLOCKING_OUTCOME_MESSAGE
        = 'Blocking send aborted by an unexpected error after the credential was injected';

    /**
     * Fixed literal for a URI whose scheme is not http/https. The scheme is
     * appended because `HttpCallContext` records method, host, path and status
     * and has nowhere to put it — and "somebody tried `file://`" is the whole
     * reason this row exists.
     *
     * Guarded by `VaultHttpClientTest::aRefusedSchemeIsAuditedAsAFailedHttpCall()`.
     */
    private const SCHEME_REFUSED_MESSAGE
        = 'Request refused before any secret was read: unsupported URI scheme';

    /**
     * Fixed literal for a host outside `allowed_hosts`. The host itself is on
     * the row already, in the audit context.
     *
     * Guarded by `VaultHttpClientTest::aRefusedHostIsAuditedAsAFailedHttpCall()`.
     */
    private const HOST_REFUSED_MESSAGE
        = 'Request refused before any secret was read: host is not in the allowed hosts list';

    /**
     * Fixed literal for a credential that could not be obtained — a missing
     * secret, a denied read, a failed OAuth token leg. Nothing was sent, and
     * the original message follows the colon.
     *
     * Guarded by `VaultHttpClientTest::aFailedCredentialInjectionIsAuditedAsAFailedHttpCall()`.
     */
    private const INJECTION_FAILED_MESSAGE
        = 'Credential injection failed; nothing was sent';

    /**
     * Fixed literal for a transport that could not be built at all. The
     * resolution runs before the credential is read, so nothing egressed and no
     * secret was retrieved — but the call was asked for, and "every
     * `sendCancellable()` leaves exactly one row" has to hold for it too.
     *
     * Guarded by
     * `VaultHttpClientCancellableTest::aThrowFromTheTransportResolutionLeavesAnAuditRow()`.
     */
    private const TRANSPORT_RESOLUTION_FAILED_MESSAGE
        = 'Cancellable transport could not be built; nothing was sent';

    private ClientInterface $innerClient;

    /**
     * Whether `$this->innerClient` is one this class built from the factory
     * with `$this->timeoutSeconds`, rather than one a caller handed in.
     *
     * Derived, never asserted by a caller — see the `$clonedFrom` parameter.
     * The cancellable path may only act when this is true; see
     * `supportsCancellation()`.
     */
    private bool $innerClientIsFactoryBuilt;

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
     * @param int|null $timeoutSeconds The `withTimeout()` override, remembered so a
     *                                 cancellable transport built later honours it.
     *                                 `withTimeout()` bakes the override into the inner
     *                                 client; without remembering the value, a transport
     *                                 built on demand would silently fall back to the
     *                                 platform timeout.
     * @param CancellableTransport|null $cancellableTransport Explicit transport for
     *                                                        `sendCancellable()`. Normally null:
     *                                                        the transport is built on demand,
     *                                                        so the common case (a client that
     *                                                        only ever calls `sendRequest()`)
     *                                                        pays nothing.
     *                                                        `@internal` test seam — it is how
     *                                                        the suite drives the tick loop
     *                                                        deterministically, and it is only
     *                                                        honoured when the inner client is
     *                                                        factory-built, so it can never
     *                                                        displace a client a caller supplied.
     *                                                        Trailing position preserves
     *                                                        positional BC.
     * @param self|null $clonedFrom The instance whose inner client is being forwarded,
     *                              passed by the `with*()` clones and by nothing else.
     *                              It exists so `$innerClientIsFactoryBuilt` cannot be
     *                              ASSERTED by a caller: the fact is inherited only when
     *                              the forwarded client is the very object a factory-built
     *                              instance holds, which requires already holding such an
     *                              instance. A caller who passes their own client cannot
     *                              reach that branch — see
     *                              `VaultHttpClientCancellableTest::aCallerCannotAssertTheFactoryBuiltFactByCloningFromAnotherInstance()`
     *                              — so "a supplied client is never replaced by a
     *                              transport" holds by construction rather than by
     *                              discipline, with the one documented exception of
     *                              `withTimeout()`, which rebuilds the client outright.
     *                              So does the equal-timeout property,
     *                              because the only instance that can be cloned from is one
     *                              whose client was built with its own `$timeoutSeconds`.
     *                              Typing it as the class is what makes it unforgeable and
     *                              also why `Services.yaml` pins it to null: autowiring
     *                              would read it as a dependency of this service on itself.
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
        private ?int $timeoutSeconds = null,
        private ?CancellableTransport $cancellableTransport = null,
        ?self $clonedFrom = null,
    ) {
        // Resolve the factory once: it builds the inner client (when missing)
        // AND backs the OAuth manager's `isHostAllowed()` gate. VaultHttpClient
        // is a fluent immutable value-object instantiated per call chain, not
        // a long-lived DI service — `makeInstance()` is the standard TYPO3
        // bootstrap path here (same pattern as before this PR).
        $this->secureHttpClientFactory = $secureHttpClientFactory
            ?? GeneralUtility::makeInstance(SecureHttpClientFactory::class);

        // No client passed → this constructor builds it below, so it is
        // factory-built by definition. A client that WAS passed only counts as
        // factory-built when it is the identical object a factory-built
        // instance already holds, i.e. when a `with*()` clone forwarded it.
        $this->innerClientIsFactoryBuilt = !$innerClient instanceof ClientInterface
            || ($clonedFrom instanceof self
                && $clonedFrom->innerClientIsFactoryBuilt
                && $clonedFrom->innerClient === $innerClient);

        // The remembered override is applied HERE too, not only in
        // withTimeout(): a client constructed with a timeout but without an
        // inner client would otherwise send blocking at the platform default
        // while the cancellable transport used the override, i.e. the two send
        // paths would disagree on the deadline.
        $this->innerClient = $innerClient ?? $this->secureHttpClientFactory->create($timeoutSeconds);

        // Share the hardened innerClient with the OAuth manager so token
        // requests inherit the SSRF / DNS-rebinding / no-redirect defences.
        // The shared factory also lets the manager call `isHostAllowed()` on
        // the token endpoint — closes the allowed_hosts allowlist gap that
        // the request-time middleware doesn't cover. The audit service is
        // passed too (issue #303): the token round trip carries the
        // `client_secret`, and a manager built without the service writes no
        // `oauth_token_request` row for it.
        $this->oauthManager = $oauthManager ?? new OAuthTokenManager(
            $this->vaultService,
            $this->innerClient,
            $this->secureHttpClientFactory,
            auditLogService: $this->auditLogService,
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
            timeoutSeconds: $this->timeoutSeconds,
            cancellableTransport: $this->cancellableTransport,
            clonedFrom: $this,
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
            timeoutSeconds: $this->timeoutSeconds,
            cancellableTransport: $this->cancellableTransport,
            clonedFrom: $this,
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
            timeoutSeconds: $this->timeoutSeconds,
            cancellableTransport: $this->cancellableTransport,
            clonedFrom: $this,
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
        // factory-built one — the one place where "a supplied client is never
        // replaced" stops, and the returned clone therefore reports
        // supportsCancellation() true
        // (VaultHttpClientCancellableTest::withTimeoutRebuildsACallerSuppliedClientAndTurnsCancellationOn()).
        // The forwarded OAuth token manager keeps its own
        // platform-default client: the override governs the API call, not the
        // token-endpoint round trip, and forwarding preserves the token cache.
        //
        // The cancellable transport is deliberately NOT forwarded: it carries
        // its own client, built with the PREVIOUS timeout. Carrying it over
        // would leave a caller ticking the event loop of a client that is not
        // serving the request — the loop would spin until its wall-clock bound
        // while the transfer it meant to watch ran somewhere else. Dropping it
        // to null makes the next sendCancellable() build a transport with the
        // override applied, so the two cannot disagree by construction.
        //
        // No `innerClient` argument below, deliberately: leaving it at the
        // default has the constructor build the client from the same factory
        // with the very `timeoutSeconds` passed here, which is also what makes
        // the clone factory-built without anyone having to assert it.
        return new self(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
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
            timeoutSeconds: $seconds > 0 ? $seconds : null,
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
        $this->assertSchemeIsAllowed($request);
        $this->assertHostIsAllowed($request);

        $secretForAudit = $this->getSecretIdentifierForAudit();
        $authenticatedRequest = $this->injectAuthenticationAudited($request, $secretForAudit);

        // The send-and-audit body lives in sendBlocking() and is called from
        // exactly two places — here and the degraded cancellable path. Inlining
        // it here as well would let the two copies drift, and "the blocking
        // send audits differently depending on which method you entered
        // through" is precisely the class of bug the audit row exists to rule
        // out.
        return $this->sendBlocking($request, $authenticatedRequest, $secretForAudit);
    }

    public function supportsCancellation(): bool
    {
        // FIRST, before anything else can say yes: a client passed to the
        // constructor stays the one that sends. It may carry a caller's own
        // middleware, proxy or handler, and quietly sending through a different
        // client would be a substitution nobody asked for. Such an instance
        // degrades to a blocking send on the caller's client — including when a
        // transport was injected, which is why this check is not below that one.
        if (!$this->innerClientIsFactoryBuilt) {
            return false;
        }

        // An injected transport brings its own ticker, so the platform's
        // curl-multi support is not what decides here.
        if ($this->cancellableTransport instanceof CancellableTransport) {
            return true;
        }

        // Otherwise the transport has to be BUILT, and cancellation is then a
        // property of Guzzle's curl-multi handler, which only
        // `SecureHttpClientFactory::createCancellable()` can hand out together
        // with the ticker that drives it. This reports exactly what
        // `resolveCancellableTransport()` will do.
        return $this->innerClient instanceof GuzzleClientInterface
            && \function_exists('curl_multi_exec');
    }

    /**
     * Send an HTTP request, aborting the transfer when `$signal` says so.
     *
     * Runs the identical guard sequence to `sendRequest()`: scheme allowlist,
     * host allowlist, credential injection, audit write. Those four are plain
     * statements in the sending method rather than middleware, so they do NOT
     * come along for free with a different send — they are re-executed here on
     * purpose, in the same order, and the pre-flight signal check sits between
     * the allowlist and the secret retrieval so a cancelled call never reads a
     * secret it will not use.
     *
     * A transport this method resolves for itself comes from
     * `SecureHttpClientFactory`: an abort needs the event loop that only the
     * factory hands out. It carries the option set and the middleware `create()`
     * installs (`VaultHttpClientCancellableTest::ssrfDnsPinIsInstalledOnTheCancellableTransport()`)
     * and the timeout the blocking client carries
     * (`…::theTransportTheClientResolvesForItselfCarriesTheRememberedTimeout()`).
     *
     * No client a caller supplied is ever replaced by a transport
     * (`…::anInjectedGuzzleClientIsNeverSwappedForACancellableTransport()`).
     * When the inner client came from the caller — or the platform has no
     * `curl_multi_*` — `supportsCancellation()` is false and this method
     * completes the call blocking, on that client, with an ordinary `http_call`
     * row. A pre-flight signal is still honoured there, because nothing has
     * egressed yet
     * (`…::aPreFlightSignalIsHonouredEvenWhenCancellationIsUnsupported()`).
     *
     * @throws RequestCancelledException When the signal aborted the call
     * @throws ClientExceptionInterface When the transfer itself failed
     * @throws VaultException If the scheme/host is rejected or secret retrieval fails
     */
    public function sendCancellable(
        RequestInterface $request,
        CancellationSignalInterface $signal,
    ): ResponseInterface {
        $this->assertSchemeIsAllowed($request);
        $this->assertHostIsAllowed($request);

        $secretForAudit = $this->getSecretIdentifierForAudit();

        // Checked BEFORE injectAuthentication(): an already-cancelled call must
        // not retrieve a secret. The row is still written — an operator asking
        // "what did this run do?" gets an answer for every sendCancellable().
        // This is the ONE abort where no credential was involved, and it gets
        // its own action rather than a distinguishing error string: an auditor
        // must be able to EXCLUDE these rows by query when asking which calls
        // were abandoned after their credential went out. An error message is
        // free text nobody can filter on.
        if ($signal->isCancelled()) {
            $this->logHttpCall(
                $secretForAudit,
                $request->getMethod(),
                (string) $request->getUri(),
                0,
                false,
                self::CANCELLED_BEFORE_SEND_MESSAGE,
                AuditAction::HttpCallCancelledBeforeSend,
            );

            throw new RequestCancelledException(self::CANCELLED_BEFORE_SEND_MESSAGE, 1786579201);
        }

        $transport = $this->resolveCancellableTransportAudited($request, $secretForAudit);

        // The signal reaches the OAuth token leg exactly when this call's own
        // transfer runs cancellable (issue #303): with a transport in hand the
        // token POST is torn down by the same signal, and on the degraded
        // blocking path the token leg blocks like everything else — the two
        // legs never disagree on whether the call is abortable.
        $authenticatedRequest = $this->injectAuthenticationAudited(
            $request,
            $secretForAudit,
            $transport instanceof CancellableTransport ? $signal : null,
        );

        if (!$transport instanceof CancellableTransport) {
            // Degraded: this platform or this instance cannot tick a transport.
            // The call still happens, blocking, with an ordinary audit row.
            return $this->sendBlocking($request, $authenticatedRequest, $secretForAudit);
        }

        return $this->sendCancellably($transport, $request, $authenticatedRequest, $secretForAudit, $signal);
    }

    /**
     * Reject anything but http/https (file://, gopher://, …) before a secret is
     * ever read.
     *
     * The refusal is audited, on both send paths: these are the calls an
     * operator goes looking for — somebody tried `file://` — and until this row
     * existed the attempt left no trace at all.
     * The exception is unchanged, byte for byte; only the row is new.
     * `VaultHttpClientTest::sendRequestRefusesAnUnsupportedSchemeWithAnUnchangedException()`
     * pins the class, the code and the message against exactly that.
     *
     * Filed as `http_call` / `success = false`, not as a new action: the row is
     * a refused outbound call, which is what that tuple already means here —
     * the SSRF middleware rejection lands in it too, and is the same kind of
     * egress-policy refusal caught one layer later.
     *
     * @throws VaultException
     */
    private function assertSchemeIsAllowed(RequestInterface $request): void
    {
        $scheme = strtolower($request->getUri()->getScheme());
        if ($scheme === 'https' || $scheme === 'http') {
            return;
        }

        $this->logRefusal($request, \sprintf('%s "%s"', self::SCHEME_REFUSED_MESSAGE, $scheme));

        throw new VaultException(
            \sprintf('Unsupported URI scheme "%s"; only https and http are allowed', $scheme),
            1735858523,
        );
    }

    /**
     * Validate the host against the allowlist BEFORE injecting authentication
     * secrets.
     *
     * Audited for the same reason as the scheme guard, and under the same
     * action: a host nobody approved is precisely the attempt an operator wants
     * to find. The exception is unchanged —
     * `VaultHttpClientTest::sendRequestRefusesAHostOutsideTheAllowlistWithAnUnchangedException()`.
     *
     * @throws VaultException
     */
    private function assertHostIsAllowed(RequestInterface $request): void
    {
        $host = strtolower($request->getUri()->getHost());
        if ($this->secureHttpClientFactory->isHostAllowed($host)) {
            return;
        }

        $this->logRefusal($request, self::HOST_REFUSED_MESSAGE);

        throw new VaultException(
            \sprintf('Host "%s" is not in the allowed hosts list', $host),
            1735858522,
        );
    }

    /**
     * Inject the credential, and audit the call when that fails.
     *
     * `injectAuthentication()` reads the vault and, for OAuth, runs a token
     * round trip; either can throw. That window sits between the allowlist and
     * the send, so without this wrapper a call that was asked for would leave
     * no `http_call` row — which is the one thing the row is for. Nothing
     * egressed, so it is a failure like any other: `http_call` /
     * `success = false`.
     *
     * This row is the CALL's, and it does not replace anything the vault or the
     * OAuth manager wrote about the credential itself (a denied read is still
     * an `access_denied` row from `VaultService`, a failed refresh still an
     * `oauth_refresh_failed` one). They answer different questions: what
     * happened to the secret, and what happened to the call.
     *
     * The exception reaches the caller unchanged —
     * `VaultHttpClientTest::sendRequestRefusesAMissingSecretWithAnUnchangedException()`.
     */
    private function injectAuthenticationAudited(
        RequestInterface $request,
        string $secretForAudit,
        ?CancellationSignalInterface $signal = null,
    ): RequestInterface {
        try {
            return $this->injectAuthentication($request, $signal);
        } catch (Throwable $throwable) {
            $this->logHttpCall(
                $secretForAudit,
                $request->getMethod(),
                (string) $request->getUri(),
                0,
                false,
                self::INJECTION_FAILED_MESSAGE . ': ' . $throwable->getMessage(),
            );

            throw $throwable;
        }
    }

    /**
     * The audit row for a call refused before the credential was read.
     *
     * Written from the guards themselves so both send paths get it from one
     * place; the URI is the pre-injection one, so no secret can reach the row.
     */
    private function logRefusal(RequestInterface $request, string $message): void
    {
        $this->logHttpCall(
            $this->getSecretIdentifierForAudit(),
            $request->getMethod(),
            (string) $request->getUri(),
            0,
            false,
            $message,
        );
    }

    /**
     * Resolve the transport, and audit the call when that fails.
     *
     * `resolveCancellableTransport()` sat outside every audited region on
     * `sendCancellable()`: it runs after the guards and before the credential
     * injection, so a throw from `SecureHttpClientFactory::createCancellable()`
     * — the option build, the handler composition, the Guzzle client
     * construction — left no row, and "every call leaves exactly one row" had
     * an outcome nobody had enumerated.
     *
     * Same shape as `injectAuthenticationAudited()`, for the same reason and
     * with the same restraint: `http_call` / `success = false`, the original
     * message after the colon, and the throwable itself rethrown unchanged.
     * Nothing egressed here and no secret was read — the row records that a
     * call was asked for, not that a credential was exposed.
     */
    private function resolveCancellableTransportAudited(
        RequestInterface $request,
        string $secretForAudit,
    ): ?CancellableTransport {
        try {
            return $this->resolveCancellableTransport();
        } catch (Throwable $throwable) {
            $this->logHttpCall(
                $secretForAudit,
                $request->getMethod(),
                (string) $request->getUri(),
                0,
                false,
                self::TRANSPORT_RESOLUTION_FAILED_MESSAGE . ': ' . $throwable->getMessage(),
            );

            throw $throwable;
        }
    }

    /**
     * The transport for `sendCancellable()`: the injected one, or a freshly
     * built one carrying the current timeout override.
     *
     * Built on demand rather than in the constructor so a client that only ever
     * calls `sendRequest()` — which is nearly all of them — does not pay for a
     * second Guzzle client and a curl multi handle it never uses.
     *
     * An inner client passed into the constructor can never serve a cancellable
     * send: an abort needs the `CurlMultiHandler` reference that
     * `createCancellable()` hands out next to its client. That leaves one
     * question — what to do for an instance whose inner client came from a
     * caller — and the answer is to degrade rather than substitute:
     *
     * - A caller-supplied client is the one that sends. It may carry that
     *   caller's middleware, proxy or handler stack, and replacing it with a
     *   factory-built one behind their back would silently drop all of it on
     *   this path only. `supportsCancellation()` reports false for such an
     *   instance and `sendCancellable()` completes it blocking, on their client
     *   (`VaultHttpClientCancellableTest::anInjectedGuzzleClientIsNeverSwappedForACancellableTransport()`).
     * - Only a factory-built inner client gets a cancellable sibling. When this
     *   method builds it, it is built from the same `buildOptions()`, carries
     *   the same `ssrf-dns-pin` middleware and — because the fact is derived
     *   from the constructor having built that client with this instance's
     *   `$timeoutSeconds` — the same deadline
     *   (`…::theTransportTheClientResolvesForItselfCarriesTheRememberedTimeout()`).
     *
     * "The transport is always one the factory built" would be false, and is
     * not claimed: the `@internal` `$cancellableTransport` parameter is public,
     * and a transport handed in that way is returned here as-is, with whatever
     * hardening it was built with. What the seam cannot do is displace a
     * caller-supplied client, because the guard above runs before it is read
     * (`…::anInjectedTransportNeverDisplacesACallerSuppliedClient()`).
     */
    private function resolveCancellableTransport(): ?CancellableTransport
    {
        // Asked FIRST, so an injected transport cannot displace a client the
        // caller supplied; `supportsCancellation()` reports the same answer.
        if (!$this->supportsCancellation()) {
            return null;
        }

        return $this->cancellableTransport
            ?? $this->secureHttpClientFactory->createCancellable($this->timeoutSeconds);
    }

    /**
     * The blocking send plus its audit row — the body `sendRequest()` runs,
     * reused by the degraded cancellable path so the guards are not evaluated
     * (and the host not re-resolved) a second time.
     *
     * The row is written from a `finally`, for the same reason the cancellable
     * path writes its own from one: `Client::applyOptions()` raises
     * `InvalidArgumentException` OUTSIDE `Client::transfer()`'s try/catch, so a
     * bad option set leaves `sendRequest()` as a throw and not as a PSR-18
     * `ClientExceptionInterface`. Catching only the latter would let such a
     * call — credential already injected — leave no trace, on the plain
     * `sendRequest()` path and on the degraded cancellable one alike.
     *
     * @throws ClientExceptionInterface
     */
    private function sendBlocking(
        RequestInterface $request,
        RequestInterface $authenticatedRequest,
        string $secretForAudit,
    ): ResponseInterface {
        $auditStatus = 0;
        $auditSuccess = false;
        $auditMessage = self::UNEXPECTED_BLOCKING_OUTCOME_MESSAGE;

        try {
            $response = $this->innerClient->sendRequest($authenticatedRequest);

            $auditStatus = $response->getStatusCode();
            $auditSuccess = true;
            $auditMessage = null;

            return $response;
        } catch (ClientExceptionInterface $e) {
            // Unchanged from before the `finally`: a transport failure keeps
            // status 0, success false and the transport's own message, which
            // `logHttpCall()` redacts on the way into the row.
            $auditMessage = $e->getMessage();

            throw $e;
        } catch (Throwable $throwable) {
            $auditMessage = self::UNEXPECTED_BLOCKING_OUTCOME_MESSAGE . ': ' . $throwable->getMessage();

            throw $throwable;
        } finally {
            $this->logHttpCall(
                $secretForAudit,
                $request->getMethod(),
                (string) $request->getUri(),
                $auditStatus,
                $auditSuccess,
                $auditMessage,
            );
        }
    }

    /**
     * Drive one transfer on the cancellable transport.
     *
     * The promise never leaves this method, and `wait()` is never used to make
     * it settle: that would run `CurlMultiHandler::execute()`, which loops until
     * every handle on the handler completes and leaves no window in which the
     * signal could be observed. The loop settles the promise itself, one bounded
     * tick at a time, and only reads the value once the promise has left the
     * pending state.
     *
     * Every exit from this method writes exactly one audit row, from a
     * `finally` that opens on the FIRST statement — the credential was injected
     * before this method was entered, so there is no window here that may throw
     * unaudited. Three of the moving parts belong to somebody else: Guzzle's own
     * option handling inside `sendAsync()`, the caller's signal, and the ticker
     * seam. A throw from any of them would otherwise escape a method whose
     * entire purpose is to leave a trace when a credential went out.
     *
     * @throws RequestCancelledException
     * @throws ClientExceptionInterface
     * @throws VaultException
     */
    private function sendCancellably(
        CancellableTransport $transport,
        RequestInterface $request,
        RequestInterface $authenticatedRequest,
        string $secretForAudit,
        CancellationSignalInterface $signal,
    ): ResponseInterface {
        // The single outcome the `finally` writes. Pre-set to the one case no
        // branch below records: a throw from code this method does not own —
        // Guzzle's option handling, the caller's signal, a ticker
        // implementation. `$outcomeRecorded` says whether the ladder was
        // reached, so that message is not overwritten by a later one.
        $auditAction = AuditAction::HttpCall;
        $auditStatus = 0;
        $auditSuccess = false;
        $auditMessage = self::UNEXPECTED_OUTCOME_MESSAGE;
        $outcomeRecorded = false;

        // Declared before the try so the catch can tear down a transfer that had
        // already been handed to the transport when the throw happened, and can
        // tell that case apart from one where no promise exists yet.
        $promise = null;

        try {
            // Inside the try, deliberately. `Client::applyOptions()` raises
            // InvalidArgumentException OUTSIDE `Client::transfer()`'s own
            // try/catch, so a bad option set leaves sendAsync() as a THROW
            // rather than as a rejected promise. The credential is already
            // injected by the time this method is entered, so a throw here
            // without an audit row would be exactly the hole the pre-flight
            // decision exists to close. Same reasoning for the `then()`
            // registration and the two transport accessors below.
            $promise = $transport->client()->sendAsync($authenticatedRequest, [
                // Client::sendRequest() pins these per request; an async send
                // sets neither, so allow_redirects would fall back to the client
                // default — which honours
                // $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allow_redirects'] when an
                // operator set it. On such an install this path alone would
                // start following redirects, past a DNS pin computed for the
                // ORIGINAL host. Measured, not theoretical: the same client
                // answered "302 not followed" synchronously and "200 followed"
                // asynchronously.
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::HTTP_ERRORS => false,
                // RequestOptions::SYNCHRONOUS is deliberately absent: setting it
                // routes the send back to the blocking CurlHandler, whose
                // promise is already settled and whose cancel() is a no-op — an
                // abort that fails by doing nothing.
            ]);

            // Settlement is observed through a handler, NOT through getState(): a
            // promise counts as fulfilled the moment it is resolved WITH ANOTHER
            // PROMISE, which may still be pending. State alone would therefore call
            // an unfinished transfer done and hand the caller a value that is not a
            // response. A handler fires only when the chain has resolved all the way
            // down to a real value.
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

            // Drained BEFORE the first tick. sendAsync() can return an ALREADY
            // rejected promise — the SSRF middleware rejects synchronously and
            // Client::transfer() converts the throw into a rejection — whose
            // handler is queued rather than run inline. Draining first settles
            // that case without touching the transport at all, instead of
            // ticking a handler that has nothing on it.
            PromiseUtils::queue()->run();

            $cancelled = false;
            $budgetExhausted = false;

            while (!$settled) {
                // Neither branch tears the transfer down here. Every way out of
                // this loop other than a settled promise ends in a throw, and
                // the catch below cancels exactly once for all of them —
                // including the throws that come from the signal or the ticker,
                // which no branch here could have caught. One teardown site
                // instead of three, and no path that aborts without one.
                if ($signal->isCancelled()) {
                    $cancelled = true;
                    break;
                }

                if (microtime(true) >= $deadline) {
                    $budgetExhausted = true;
                    break;
                }

                $ticker->tick();

                // The tick advances the transfer; this propagates the result up
                // the middleware chain. Done here rather than relying on the
                // ticker so the loop's progress does not depend on which ticker
                // implementation it was handed.
                PromiseUtils::queue()->run();
            }

            if ($cancelled) {
                $auditAction = AuditAction::HttpCallCancelled;
                $auditMessage = self::CANCELLED_IN_FLIGHT_MESSAGE;
                $outcomeRecorded = true;

                throw new RequestCancelledException(self::CANCELLED_IN_FLIGHT_MESSAGE, 1786579202);
            }

            if ($budgetExhausted) {
                // A FAILURE, not a cancellation: nobody asked for this. The
                // defensive bound only trips when the handler stopped settling
                // its promise, which is a bug in the transport and belongs with
                // the other transport failures under `http_call` /
                // `success = false`. `http_call_cancelled` answers exactly one
                // question — which calls did a caller abandon after their
                // credential went out — and a second meaning on it would make
                // that query wrong again. The fixed literal below is what tells
                // this failure apart from a connection refusal.
                $auditMessage = self::TICK_BUDGET_EXHAUSTED_MESSAGE;
                $outcomeRecorded = true;

                throw new VaultException(self::TICK_BUDGET_EXHAUSTED_MESSAGE, 1786579203);
            }

            if ($rejected) {
                // Audited more widely than sendRequest()'s catch on purpose: an
                // async rejection reason need not implement any PSR-18
                // interface, and a call whose credential already egressed must
                // never be the one row missing from the log. `wait()` is never
                // used to surface it — that would run
                // CurlMultiHandler::execute() and block until every other handle
                // on the loop finished. The error string still travels through
                // logHttpCall(), which is where secret redaction happens.
                $message = $settledValue instanceof Throwable
                    ? $settledValue->getMessage()
                    : 'Cancellable transfer was rejected';

                $auditMessage = $message;
                $outcomeRecorded = true;

                if ($settledValue instanceof Throwable) {
                    throw $settledValue;
                }

                throw new VaultException($message, 1786579204);
            }

            if (!$settledValue instanceof ResponseInterface) {
                // `http_call` with success = false, deliberately: the transfer
                // ran to a settlement and produced something unusable. That is
                // a transport failure, and it sits with the other transport
                // failures rather than with the one thing
                // `http_call_cancelled` means. The fixed literal below is what
                // separates it from a connection refusal in the row.
                $auditMessage = self::NON_RESPONSE_SETTLEMENT_MESSAGE;
                $outcomeRecorded = true;

                throw new VaultException(self::NON_RESPONSE_SETTLEMENT_MESSAGE, 1786579205);
            }

            $auditStatus = $settledValue->getStatusCode();
            $auditSuccess = true;
            $auditMessage = null;
            $outcomeRecorded = true;

            return $settledValue;
        } catch (Throwable $throwable) {
            // THE teardown. Every abort — a signalled one, the wall-clock bound,
            // and a throw from the caller's signal or the ticker — leaves the
            // try block through here with the transfer still running, and this
            // is what closes the socket: Promise::cancel() runs the cancel
            // function CurlMultiHandler attached, which removes the easy handle
            // from the multi handle and drops the last reference to it. On a
            // promise that already settled it returns immediately, so the
            // outcomes that need no teardown pay nothing. Null only when
            // sendAsync() itself threw, i.e. when there is no transfer yet.
            $promise?->cancel();

            if (!$outcomeRecorded) {
                // A FAILURE, and audited as one: `http_call` / success = false.
                // Nobody asked for it — the signal was not set, the transfer was
                // not abandoned on purpose, something in code this class does
                // not own threw. `http_call_cancelled` stays reserved for the
                // single case where a caller's signal stopped an in-flight
                // request; the literal below, plus the original message, is what
                // identifies this one.
                $auditMessage = self::UNEXPECTED_OUTCOME_MESSAGE . ': ' . $throwable->getMessage();
            }

            throw $throwable;
        } finally {
            $this->logHttpCall(
                $secretForAudit,
                $request->getMethod(),
                (string) $request->getUri(),
                $auditStatus,
                $auditSuccess,
                $auditMessage,
                $auditAction,
            );
        }
    }

    /**
     * Inject authentication into the request based on configuration.
     *
     * `$signal` reaches only the OAuth leg: it is the one injection that
     * performs its own outbound round trip (issue #303). Every other
     * placement reads the vault locally and has nothing to abort.
     */
    private function injectAuthentication(
        RequestInterface $request,
        ?CancellationSignalInterface $signal = null,
    ): RequestInterface {
        if ($this->oauthConfig instanceof OAuthConfig) {
            return $this->injectOAuth($request, $signal);
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

    private function injectOAuth(
        RequestInterface $request,
        ?CancellationSignalInterface $signal = null,
    ): RequestInterface {
        \assert($this->oauthConfig instanceof OAuthConfig);
        $accessToken = $this->oauthManager->getAccessToken($this->oauthConfig, $signal);

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
     *
     * The context is built from the PRE-injection request, so a QueryParam-placed
     * secret can never reach the audit row. `$errorMessage` may still contain the
     * injected secret — a transport error string quotes the URL it failed on —
     * and is redacted by `AuditLogService::sanitizeErrorMessage()` on the way in.
     * Every audit row this client writes therefore goes through THIS method.
     * An exception handed back to a caller does not — which is why the ones
     * this class raises itself are fixed literals.
     *
     * @param AuditAction $action Which action this row is filed under. Only three
     *                            values ever reach this method, and each means one
     *                            thing: `HttpCallCancelled` — a caller's signal
     *                            stopped an in-flight request; `HttpCallCancelledBeforeSend`
     *                            — refused before the send, no secret read;
     *                            `HttpCall` — everything else, including every
     *                            failure. The two cancellations are actions rather
     *                            than distinguishing error strings because a string
     *                            is free text an auditor cannot filter on, while the
     *                            action drives the backend's filter dropdown.
     */
    private function logHttpCall(
        string $secretIdentifier,
        string $method,
        string $url,
        int $statusCode,
        bool $success,
        ?string $errorMessage,
        AuditAction $action = AuditAction::HttpCall,
    ): void {
        $this->auditLogService->log(
            $secretIdentifier,
            $action->value,
            $success,
            $errorMessage,
            $this->reason,
            null,
            null,
            HttpCallContext::fromRequest($method, $url, $statusCode),
        );
    }
}
