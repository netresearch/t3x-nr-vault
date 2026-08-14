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

use GuzzleHttp\Handler\CurlMultiHandler;

/**
 * Ticks a Guzzle `CurlMultiHandler`.
 *
 * The handler is held privately and this class exposes only `tick()`:
 * `CurlMultiHandler::cancel()` is private in Guzzle, so the only route to an
 * abort is the cancel function of the promise the handler produced. That
 * promise does not leave `VaultHttpClient::sendCancellable()`, whose export
 * surface is asserted by
 * `VaultHttpClientCancellableTest::theCredentialBearingClientExportsNoTransportAndNoPromise()`.
 *
 * One tick runs the pending promise queue, then advances libcurl's multi
 * interface, blocking at most `select_timeout` inside `curl_multi_select`. That
 * bound is what makes the cancellation latency predictable; see
 * `SecureHttpClientFactory::CANCELLABLE_SELECT_TIMEOUT_SECONDS`.
 */
final readonly class CurlMultiTicker implements TransportTickerInterface
{
    public function __construct(private CurlMultiHandler $handler) {}

    public function tick(): void
    {
        $this->handler->tick();
    }
}
