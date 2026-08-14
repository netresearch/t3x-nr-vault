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

/**
 * Drives one step of the transport event loop.
 *
 * This seam exists so the cancellation loop can be tested at all. The suite's
 * only in-process HTTP seam replaces a client's BOTTOM handler
 * (`HandlerStack::setHandler()`), which destroys the very `CurlMultiHandler`
 * the loop would have to tick — a primitive that ticked a privately held
 * handler could therefore never be exercised by a unit test, only asserted at
 * by inspection.
 *
 * With the ticker behind an interface, a test builds a transport from a stub
 * bottom handler plus a ticker closure that settles the stubbed promise on the
 * Nth call, and the abort is provable without a socket, a sleep or a flake.
 *
 * Mirrors the injection precedent already in this namespace
 * (`DnsResolverInterface` / `DefaultDnsResolver`).
 *
 * @see CurlMultiTicker for the production implementation
 */
interface TransportTickerInterface
{
    /**
     * Advance the transport by one step.
     *
     * Blocks for at most the transport's own select timeout. It MUST NOT block
     * for the remaining duration of the transfer — that would leave no window
     * in which a cancellation signal could be observed.
     */
    public function tick(): void;
}
