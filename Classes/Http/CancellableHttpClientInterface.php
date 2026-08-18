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

use Netresearch\NrVault\Exception\RequestCancelledException;
use Netresearch\NrVault\Exception\VaultException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * An outbound send that a caller can abort while it is still on the wire.
 *
 * Separate from :php:`VaultHttpClientInterface` on purpose: this is additive,
 * so the existing interface — and every implementor and consumer of it — is
 * untouched, and a consumer feature-detects instead of requiring a version
 * floor::
 *
 *     $client = $vault->http()->withReason('MCP tool call')->withTimeout(15);
 *     $response = $client instanceof CancellableHttpClientInterface && $client->supportsCancellation()
 *         ? $client->sendCancellable($request, $signal)
 *         : $client->sendRequest($request);
 *
 * **No transport type crosses THIS interface**, and the class that attaches the
 * secret exports none either: every public method of `VaultHttpClient` returns
 * a configured clone, a PSR-7 response or a bool — no client, no handler, no
 * promise — and `sendCancellable()` takes no options parameter through which a
 * caller could reach the transport. Both are pinned by
 * `VaultHttpClientCancellableTest::theCredentialBearingClientExportsNoTransportAndNoPromise()`.
 *
 * The boundary this package actually has is two-tier, and always was:
 *
 * - `SecureHttpClientFactory::create()` and `createCancellable()` are public and
 *   hand out a raw transport — a Guzzle client, and next to it the ticker that
 *   drives its event loop. Consumers depend on that (nr-llm injects the factory
 *   directly), and it is a supported case: what they get carries the SSRF reject
 *   middleware and the `CURLOPT_RESOLVE` DNS pin, and carries no vault secret,
 *   no scheme guard, no `allowed_hosts` gate and no audit write.
 * - All four together live on `VaultHttpClient`, and it is the only send a
 *   caller can drive that puts a vault secret on their request. That is what
 *   this interface's shape protects: the request and response are PSR-7, and
 *   the signal and the exception are ours.
 *
 * nr-vault does send two credentials of its own elsewhere, on paths that are
 * not a caller's request and are not covered by the four: the `X-Vault-Token`
 * header in `TransitMasterKeyProvider::callTransit()`, on the plain Guzzle
 * client `MasterKeyProviderFactory` builds, and the `client_secret` form body
 * in `OAuthTokenManager::dispatchTokenRequest()`, which applies the
 * `allowed_hosts` gate and — since issue #303 — writes one
 * `oauth_token_request` audit row per attempted round trip and honours this
 * send's cancellation signal. "No credential-bearing send exists outside
 * `VaultHttpClient`" would still be false (the transit leg remains); see
 * ADR-037.
 *
 * The four are plain statements in the sending method, not middleware, so a
 * shape that handed a caller the promise for an authenticated send — or the
 * client with the credential already on it — would drop all four, including the
 * allowlist that runs before the credential reaches the request. On this send
 * that gate precedes the vault read as well; on the OAuth token leg the secrets
 * are read first and the gate runs before the body carrying them is built.
 *
 * **There is no per-request option surface, and adding one is a security
 * change.** A caller-supplied `stream => true` would route the request to the
 * stream handler, which ignores the `CURLOPT_RESOLVE` DNS pin without warning;
 * a caller-supplied `curl` array is applied last by Guzzle's curl factory and
 * would overwrite that same vetted pin.
 *
 * @see CancellationSignalInterface
 * @see VaultHttpClientInterface for the plain PSR-18 send
 */
interface CancellableHttpClientInterface
{
    /**
     * Send an HTTP request, aborting the transfer as soon as `$signal` says so.
     *
     * Runs the same guard sequence as :php:`sendRequest()` — scheme allowlist,
     * host allowlist, credential injection, audit write — so the log stays
     * complete with respect to *calls*, not merely with respect to egress.
     * **Every call leaves exactly one row from this client**, under one of
     * three actions. Each outcome below names the test in
     * `VaultHttpClientCancellableTest` that asserts its row:
     *
     * - ``http_call_cancelled`` — and only this — when the signal stopped an
     *   in-flight request. The credential was injected and handed to the
     *   transport: treat it as exposed. Because the action means nothing else,
     *   "which calls were abandoned after their credential went out?" is one
     *   query on one action value
     *   (`cancellingMidFlightAbortsTheTransferAndAuditsItAsCancelled()`,
     *   `theTwoCancellationOutcomesAreToldApartByTheirAction()`; that the
     *   failures below stay OUT of it is pinned by
     *   `anExhaustedWallClockBudgetAbortsTheTransferAndAuditsIt()` and
     *   `aSignalThatThrowsMidFlightStillLeavesAnAuditRow()`);
     * - ``http_call_cancelled_before_send`` when the signal was already true on
     *   entry. No secret was read, nothing egressed
     *   (`cancellingBeforeSendReadsNoSecretAndStillLeavesADistinguishableRow()`,
     *   and on a degraded instance
     *   `aPreFlightSignalIsHonouredEvenWhenCancellationIsUnsupported()`);
     * - ``http_call`` for everything else: the completed call
     *   (`anUncancelledCallReturnsTheResponseAndAuditsAnOrdinaryHttpCall()`) and,
     *   with ``success = false``, everything that failed rather than was
     *   cancelled — a refused scheme or host
     *   (`schemeGuardRunsOnTheCancellablePathBeforeAnySecretIsRead()`,
     *   `hostAllowlistRunsOnTheCancellablePathBeforeAnySecretIsRead()`), a
     *   credential that could not be obtained
     *   (`aFailedCredentialInjectionOnTheCancellablePathLeavesARow()`), a
     *   transport rejection
     *   (`anSsrfRejectionSettlesBeforeTheFirstTickAndStillWritesItsRow()`), the
     *   tick loop's defensive wall-clock bound, a settlement that is not a
     *   response (`aNonResponseSettlementIsRefusedInsteadOfReturned()`), or a
     *   throw from the signal, the ticker or Guzzle's option handling
     *   (`aThrowFromTheSendItselfStillLeavesAnAuditRow()`). Which one it was is
     *   a fixed literal in the row's error message, rendered under the badge.
     *
     * The rows for everything after the credential was injected are written
     * from a `finally`, on the cancellable branch and on the degraded blocking
     * one alike, so the guarantee does not depend on which branch a call took:
     * a throw that is not a PSR-18 `ClientExceptionInterface` (Guzzle's option
     * handling raises `InvalidArgumentException` outside its own try/catch on
     * the synchronous path as well) still leaves a row
     * (`aThrowFromTheDegradedBlockingSendStillLeavesAnAuditRow()`).
     *
     * When this instance builds its own transport, that transport comes from
     * `SecureHttpClientFactory` and carries the same `ssrf-dns-pin` middleware
     * (`ssrfDnsPinIsInstalledOnTheCancellableTransport()`) and the same timeout
     * as the blocking client (`theTransportTheClientResolvesForItselfCarriesTheRememberedTimeout()`)
     * — cancellation is an early exit, and a transport that could run longer
     * than the send it replaces would be the opposite of one. A client a caller
     * passed to the constructor is never replaced by a transport; see
     * :php:`supportsCancellation()`.
     *
     * When :php:`supportsCancellation()` is false the call still completes —
     * blocking, through the ordinary path, with an ordinary ``http_call`` audit
     * row (`aNonGuzzleInnerClientDegradesToABlockingSendWithAnOrdinaryAuditRow()`).
     * It degrades; it does not fail.
     *
     * @param RequestInterface $request PSR-7 request
     * @param CancellationSignalInterface $signal Polled before the send and between transport ticks
     *
     * @throws RequestCancelledException When the signal aborted the call
     * @throws ClientExceptionInterface When the transfer itself failed
     * @throws VaultException When the scheme or host is rejected, or secret retrieval fails
     *
     * @return ResponseInterface PSR-7 response
     */
    public function sendCancellable(
        RequestInterface $request,
        CancellationSignalInterface $signal,
    ): ResponseInterface;

    /**
     * Whether this instance can actually abort a transfer in flight.
     *
     * False whenever the inner client was supplied by the caller rather than
     * built by `SecureHttpClientFactory` — that check runs first, so nothing
     * overrides it, not even an `@internal` injected transport
     * (`anInjectedGuzzleClientIsNeverSwappedForACancellableTransport()`,
     * `anInjectedTransportNeverDisplacesACallerSuppliedClient()`). A supplied
     * client may carry that caller's own middleware, proxy or handler, so on
     * this path it stays the one that sends; this method says so instead. The
     * fact is derived from who built the client and cannot be passed in as a
     * flag (`aCallerCannotAssertTheFactoryBuiltFactByCloningFromAnotherInstance()`).
     *
     * Where that stops: :php:`withTimeout()` has to bake the override into a
     * client, so it rebuilds one from the factory and drops the supplied one —
     * and the clone then reports true
     * (`withTimeoutRebuildsACallerSuppliedClientAndTurnsCancellationOn()`).
     *
     * Also false when the transport would have to be built here and the
     * platform has no `curl_multi_*` support. (An `@internal` injected
     * transport brings its own ticker, so that gate does not apply to it — but
     * the factory-built check above still does.)
     *
     * When it is false, :php:`sendCancellable()` still honours a *pre-flight*
     * signal — nothing has egressed yet, so refusing to send is possible on any
     * instance, with the same exception and the same row
     * (`aPreFlightSignalIsHonouredEvenWhenCancellationIsUnsupported()`) — but it
     * cannot interrupt a transfer that has begun.
     */
    public function supportsCancellation(): bool;
}
