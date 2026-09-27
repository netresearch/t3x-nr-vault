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

use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\Utils as PromiseUtils;

/**
 * One transfer on the curl-multi transport, driven one step at a time.
 *
 * Shared by the two phases of `VaultHttpClient::sendStreaming()`: the wait for
 * the response headers, and every `read()` of the body afterwards. Both need
 * the same step — poll the signal, check the wall-clock bound, tick the
 * transport, run the promise queue — and the same teardown, so it lives here
 * once.
 *
 * Settlement is observed through `then()` handlers, never through the promise
 * state: a promise resolved with another promise reads as fulfilled while the
 * inner one is still pending, and after a failed transfer the state and the
 * outcome have been seen to disagree. `wait()` is never called — it would run
 * `CurlMultiHandler::execute()`, which does not return until every transfer on
 * the handler has finished.
 *
 * @internal Nothing outside `VaultHttpClient` and `StreamingResponseBody`
 *           constructs or receives one; it never leaves the package's
 *           response object.
 */
final class StreamingTransfer
{
    /** `advance()` ticked the transport; call it again to make more progress. */
    public const STEPPED = 0;

    /** `advance()` found the caller's signal set and tore the transfer down. */
    public const CANCELLED = 1;

    /**
     * `advance()` found the wall-clock bound exceeded and tore the transfer
     * down.
     */
    public const BUDGET_EXHAUSTED = 2;

    private bool $settled = false;

    private bool $rejected = false;

    private mixed $settledValue = null;

    private readonly float $deadline;

    /**
     * @param PromiseInterface $promise The transport's promise for this transfer
     * @param TransportTickerInterface $ticker Drives the loop that promise belongs to
     * @param float $wallClockBudgetSeconds Upper bound for the whole transfer, headers and body.
     *                                      Derived by the factory from `timeout` +
     *                                      `connect_timeout` plus a margin, so it only
     *                                      fires after libcurl's own deadline should have
     * @param CancellationSignalInterface|null $signal The caller's abort question, if any
     */
    public function __construct(
        private readonly PromiseInterface $promise,
        private readonly TransportTickerInterface $ticker,
        float $wallClockBudgetSeconds,
        private readonly ?CancellationSignalInterface $signal,
    ) {
        $this->deadline = microtime(true) + $wallClockBudgetSeconds;

        $promise->then(
            function (mixed $value): void {
                $this->settled = true;
                $this->settledValue = $value;
            },
            function (mixed $reason): void {
                $this->settled = true;
                $this->rejected = true;
                $this->settledValue = $reason;
            },
        );

        // A promise that was rejected synchronously — the SSRF middleware
        // rejects before the transport is touched — queues its handler instead
        // of running it inline. Draining here settles that case without a tick.
        PromiseUtils::queue()->run();
    }

    /**
     * Make one step of progress, or refuse to.
     *
     * Checks the signal first and the wall-clock bound second; either one
     * tears the transfer down before it returns its answer, so a caller that
     * gets `CANCELLED` or `BUDGET_EXHAUSTED` has nothing left to clean up.
     *
     * @return self::STEPPED|self::CANCELLED|self::BUDGET_EXHAUSTED
     */
    public function advance(): int
    {
        if ($this->signal?->isCancelled() === true) {
            $this->abandon();

            return self::CANCELLED;
        }

        if (microtime(true) >= $this->deadline) {
            $this->abandon();

            return self::BUDGET_EXHAUSTED;
        }

        $this->ticker->tick();

        // The tick advances libcurl; this propagates the result up the
        // middleware chain, whichever ticker implementation was handed in.
        PromiseUtils::queue()->run();

        return self::STEPPED;
    }

    /**
     * Remove the transfer from the transport and close it.
     *
     * `Promise::cancel()` runs the cancel function `CurlMultiHandler` attached,
     * which takes the easy handle off the multi handle and closes it. On a
     * promise that already settled — including one this method cancelled
     * before — it does nothing, so calling it twice is safe.
     */
    public function abandon(): void
    {
        $this->promise->cancel();
    }

    public function isSettled(): bool
    {
        return $this->settled;
    }

    public function isRejected(): bool
    {
        return $this->rejected;
    }

    /**
     * The fulfilment value or the rejection reason, once settled.
     */
    public function settledValue(): mixed
    {
        return $this->settledValue;
    }
}
