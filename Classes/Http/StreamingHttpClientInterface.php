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
 * An outbound send whose response body can be read while it is still arriving.
 *
 * Separate from :php:`VaultHttpClientInterface` and
 * :php:`CancellableHttpClientInterface` on purpose, like the latter before it:
 * it is additive, so a consumer feature-detects instead of raising a version
 * floor::
 *
 *     $response = $client instanceof StreamingHttpClientInterface && $client->supportsStreaming()
 *         ? $client->sendStreaming($request, $signal)
 *         : $client->sendRequest($request);
 *
 * This is a calling interface, not an extension point: a minor release may add
 * methods to it.
 *
 * **The DNS pin is kept.** The transfer runs on the same curl-multi transport
 * `sendCancellable()` uses, built by `SecureHttpClientFactory::createCancellable()`
 * with the `ssrf-dns-pin` middleware and its `CURLOPT_RESOLVE` entry. Guzzle's
 * `stream => true` option is never set: it would route the request to the
 * stream handler, which ignores the pin (see ADR-039).
 *
 * @see CancellableHttpClientInterface for the same guards on a buffered send
 */
interface StreamingHttpClientInterface
{
    /**
     * Send an HTTP request and return once the final response head and the
     * first bytes of its body have arrived, or the transfer has ended.
     *
     * The head is the origin's: a later head replaces an earlier one until
     * body bytes arrive, so neither a `1xx` interim head nor a tunnelling
     * proxy's `200 Connection established` is ever returned as the response.
     *
     * Runs the same guard sequence as :php:`sendRequest()` — scheme allowlist,
     * host allowlist, credential injection — and writes exactly one audit row,
     * when this method returns or throws. The body of the returned response
     * advances the transfer when it is read:
     *
     * - `read()` returns the bytes that have arrived, or drives the transport
     *   until some arrive or the transfer ends;
     * - a transfer that failed after the headers throws from `read()` once the
     *   bytes that did arrive are consumed — it never ends as a short body;
     * - `close()`, `detach()` or dropping the body before the end removes the
     *   transfer from the transport and closes it;
     * - `$signal` is polled before the send and on every step, headers and body
     *   alike; a signal that fires aborts the transfer;
     * - at most 16 MiB of unread body is buffered: a step that delivers more —
     *   typically a small compressed body that decodes to a very large one —
     *   fails the transfer with its own message instead of filling memory;
     * - a stall ends: at the total `timeout` when one is configured, otherwise
     *   after `SecureHttpClientFactory::STREAMING_IDLE_BUDGET_SECONDS` without
     *   receiving anything, so a stream that keeps delivering is not cut off;
     * - `getContents()` and `__toString()` return at most 16 MiB, and
     *   `__toString()` throws rather than return a partial body — a deliberate
     *   deviation from PSR-7 (ADR-039).
     *
     * Redirects are not followed: a 3xx response is returned as it is.
     *
     * When :php:`supportsStreaming()` is false the call still completes —
     * blocking, through the ordinary path — and the body is already complete
     * when it is returned.
     *
     * @param RequestInterface $request PSR-7 request
     * @param CancellationSignalInterface|null $signal Polled before the send and on every transport step
     *
     * @throws RequestCancelledException When the signal aborted the call before it returned
     * @throws ClientExceptionInterface When the transfer failed before it returned
     * @throws VaultException When the scheme or host is rejected, secret retrieval fails, the transfer overran its time bound,
     *                        or one step delivered more body than the buffer holds
     *
     * @return ResponseInterface PSR-7 response whose body is read from the wire
     */
    public function sendStreaming(
        RequestInterface $request,
        ?CancellationSignalInterface $signal = null,
    ): ResponseInterface;

    /**
     * Whether `sendStreaming()` delivers the body while it arrives.
     *
     * The same answer as `CancellableHttpClientInterface::supportsCancellation()`,
     * for the same reasons: false when the inner client was supplied by the
     * caller, and false when the platform has no `curl_multi_*` support.
     */
    public function supportsStreaming(): bool;
}
