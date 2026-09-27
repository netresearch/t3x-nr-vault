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
use Psr\Http\Message\ResponseInterface;

/**
 * What the idle bound of `StreamingTransfer` counts as progress.
 *
 * One rule for every send on the cancellable transport, kept in one place so
 * the sends cannot drift apart: a final response head counts, and so do the
 * body bytes the sink took while a final head was the current one. Anything
 * else buys no time.
 *
 * - Every head passes through `on_headers`, the curl handler's hook. A `1xx`
 *   head is not final and resets the current head: Guzzle 7 calls `on_headers`
 *   for every one, so a server repeating `100 Continue` would otherwise keep a
 *   transfer without a total timeout alive for ever.
 * - While no final head is current — before the first one, or after a `1xx`
 *   replaced it — the counter stays where it is. Bytes behind an unsolicited
 *   `101 Switching Protocols` land in the sink as raw connection data and are
 *   not the body of any final head.
 * - A later head replaces an earlier one, as on the blocking path. On Guzzle 7
 *   a tunnelling proxy's `200 Connection established` reaches `on_headers`
 *   before the origin's head; it counts once, like any final head.
 *
 * The counter never shrinks: it only moves while a final head is current, and
 * then to the count of final heads seen plus the sink's byte count, both of
 * which only grow.
 *
 * @internal Built by `VaultHttpClient` and `OAuthTokenManager` for one transfer
 *           each; never leaves them
 */
final class TransferProgress
{
    private ?ResponseInterface $head = null;

    private int $finalHeadsSeen = 0;

    private int $progress = 0;

    /**
     * @param Closure(): int $bodyBytes How many body bytes the sink has taken so far;
     *                                  must never shrink
     */
    public function __construct(
        private readonly Closure $bodyBytes,
    ) {}

    /**
     * The `on_headers` request option. Records only: a throw here would abort
     * the transfer from inside a curl callback.
     */
    public function onHeaders(ResponseInterface $response): void
    {
        if ($response->getStatusCode() < 200) {
            $this->head = null;

            return;
        }

        $this->head = $response;
        ++$this->finalHeadsSeen;
    }

    /**
     * The latest final head, or null while none is current.
     */
    public function head(): ?ResponseInterface
    {
        return $this->head;
    }

    /**
     * The counter `StreamingTransfer` reads after every tick.
     */
    public function count(): int
    {
        if ($this->head instanceof ResponseInterface) {
            $this->progress = $this->finalHeadsSeen + ($this->bodyBytes)();
        }

        return $this->progress;
    }
}
