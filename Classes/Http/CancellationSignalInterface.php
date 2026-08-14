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
 * A caller-owned "should this transfer stop?" question.
 *
 * `VaultHttpClient::sendCancellable()` polls this between ticks of the
 * transport event loop. It is deliberately the smallest possible contract: the
 * caller decides what cancellation means (a killed agent run, a closed
 * connection, a deadline of its own), and nr-vault never learns about it.
 *
 * Implementations MUST be cheap — the method is called on every loop iteration,
 * i.e. up to ten times a second per in-flight request — and MUST NOT throw. An
 * exception here would escape mid-transfer, after the credential has already
 * been injected and put on the wire, on a path whose whole purpose is to leave
 * an audit row for exactly that situation.
 *
 * A `deadline(): ?float` sibling was considered and deliberately left out: no
 * caller needs it yet, and the interface has room to grow when one does.
 *
 * @see CancellableHttpClientInterface::sendCancellable()
 */
interface CancellationSignalInterface
{
    /**
     * Return true to abort the in-flight request.
     *
     * MUST NOT throw. MUST be cheap.
     */
    public function isCancelled(): bool;
}
