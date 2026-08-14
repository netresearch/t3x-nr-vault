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

/**
 * The two halves of a cancellable transport, kept together so they cannot drift.
 *
 * A cancellable send needs an async-capable client AND a reference to the event
 * loop that client's bottom handler is driven by. Held apart, the two silently
 * decouple — the classic failure is a client rebuilt by `withTimeout()` while
 * the caller keeps ticking the handler of the previous one, which serves
 * nothing and spins until the wall-clock bound. Passing them as one value makes
 * that mistake structurally impossible.
 *
 * `SecureHttpClientFactory::createCancellable()` builds it, and returns `null`
 * rather than a half-usable transport when the platform cannot support one, so
 * there is no "transport without a ticker" state to reason about. This
 * constructor is public, and the test suite builds transports directly through
 * it — "only the factory builds one" would be false.
 *
 * Reachable from outside: `createCancellable()` is public, like `create()`
 * before it, and returns this. What it hands out is a hardened but
 * credential-free transport — SSRF reject middleware and the `CURLOPT_RESOLVE`
 * DNS pin, no vault secret, no `allowed_hosts` gate, no audit write.
 *
 * What holds for the credential path is narrower, and tested: a transport never
 * displaces a client a caller supplied
 * (`VaultHttpClientCancellableTest::anInjectedTransportNeverDisplacesACallerSuppliedClient()`),
 * and `VaultHttpClient` exports neither transport nor promise
 * (`VaultHttpClientCancellableTest::theCredentialBearingClientExportsNoTransportAndNoPromise()`).
 */
final readonly class CancellableTransport
{
    /**
     * @param GuzzleClientInterface $client Async-capable client carrying the full hardened option set
     * @param TransportTickerInterface $ticker Drives the loop the above client's handler runs on
     * @param float $wallClockBudgetSeconds Defensive upper bound for the tick loop.
     *                                      Derived from the transport's own
     *                                      `timeout` + `connect_timeout` plus a
     *                                      margin, so it can only ever fire
     *                                      AFTER libcurl's own deadline should
     *                                      have. If it does fire, the handler
     *                                      misbehaved — better to abort and
     *                                      audit than to hang a TYPO3 request.
     */
    public function __construct(
        private GuzzleClientInterface $client,
        private TransportTickerInterface $ticker,
        private float $wallClockBudgetSeconds,
    ) {}

    public function client(): GuzzleClientInterface
    {
        return $this->client;
    }

    public function ticker(): TransportTickerInterface
    {
        return $this->ticker;
    }

    public function wallClockBudgetSeconds(): float
    {
        return $this->wallClockBudgetSeconds;
    }
}
