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

use Closure;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\Utils as PromiseUtils;
use Throwable;

/**
 * One transfer on the curl-multi transport, driven one step at a time.
 *
 * Shared by the two phases of `VaultHttpClient::sendStreaming()`: the wait for
 * the final head and its first body bytes, and every `read()` afterwards. Both need
 * the same step — poll the signal, tick the transport, run the promise queue,
 * enforce the bound — and the same teardown, so it lives here once.
 *
 * The bound is one of two. With a total timeout it is a wall-clock budget
 * from the start of the transfer, checked before each tick. Without one it is
 * an idle bound on silence, checked after each tick: the step first collects
 * whatever arrived while nobody was reading, so a consumer's own pause between
 * two reads is never mistaken for a silent server.
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

    /**
     * `advance()` found that nothing arrived for the idle budget and tore the
     * transfer down. Only possible when the transport has no total timeout.
     */
    public const IDLE_EXHAUSTED = 3;

    private bool $settled = false;

    private bool $rejected = false;

    private mixed $settledValue = null;

    private float $deadline;

    private int $lastProgress = 0;

    /**
     * @param PromiseInterface $promise The transport's promise for this transfer
     * @param TransportTickerInterface $ticker Drives the loop that promise belongs to
     * @param float $wallClockBudgetSeconds Upper bound for the whole transfer, headers and body.
     *                                      Derived by the factory from `timeout` +
     *                                      `connect_timeout` plus a margin, so it only
     *                                      fires after libcurl's own deadline should have
     * @param CancellationSignalInterface|null $signal The caller's abort question, if any
     * @param float|null $idleBudgetSeconds When set, the bound is on silence instead of
     *                                      duration: the deadline moves forward every
     *                                      time `$progress` reports something new. Set
     *                                      when the transport has no total timeout, so
     *                                      that a stream still delivering is not cut
     *                                      off while one that stalls still ends
     * @param (Closure(): int)|null $progress A counter that grows whenever the transfer received
     *                                        something (a response head, body bytes) and
     *                                        never shrinks; required in idle mode
     */
    public function __construct(
        private readonly PromiseInterface $promise,
        private readonly TransportTickerInterface $ticker,
        float $wallClockBudgetSeconds,
        private readonly ?CancellationSignalInterface $signal,
        private readonly ?float $idleBudgetSeconds = null,
        private readonly ?Closure $progress = null,
    ) {
        $this->deadline = microtime(true) + ($idleBudgetSeconds ?? $wallClockBudgetSeconds);

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
     * Checks the signal first. Any of the three refusals tears the transfer
     * down before it returns its answer, so a caller that gets `CANCELLED`,
     * `BUDGET_EXHAUSTED` or `IDLE_EXHAUSTED` has nothing left to clean up. So
     * does a throw — from the caller's signal, which must not throw but might,
     * or from the ticker: the transfer is torn down before the throwable
     * leaves, on the body path as on the head path.
     *
     * The wall-clock bound is checked before the tick. The idle bound is
     * checked after it, once what arrived meanwhile has been counted: time the
     * consumer spent between two reads is not silence if the server sent
     * something in it, and a transfer that has settled is not aborted.
     *
     * @return self::STEPPED|self::CANCELLED|self::BUDGET_EXHAUSTED|self::IDLE_EXHAUSTED
     */
    public function advance(): int
    {
        $idle = $this->idleBudgetSeconds !== null && $this->progress instanceof Closure;

        try {
            if ($this->signal?->isCancelled() === true) {
                $this->abandon();

                return self::CANCELLED;
            }

            if (!$idle && microtime(true) >= $this->deadline) {
                $this->abandon();

                return self::BUDGET_EXHAUSTED;
            }

            $this->ticker->tick();

            // The tick advances libcurl; this propagates the result up the
            // middleware chain, whichever ticker implementation was handed in.
            PromiseUtils::queue()->run();
        } catch (Throwable $throwable) {
            $this->abandon();

            throw $throwable;
        }

        if ($idle) {
            // Only growth counts: a counter that went down (it cannot, by
            // contract, but the closure is not ours to trust) must not buy the
            // transfer more time.
            $progress = ($this->progress)();
            if ($progress > $this->lastProgress) {
                $this->lastProgress = $progress;
                $this->deadline = microtime(true) + (float) $this->idleBudgetSeconds;
            }

            if (!$this->settled && microtime(true) >= $this->deadline) {
                $this->abandon();

                return self::IDLE_EXHAUSTED;
            }
        }

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
