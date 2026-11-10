<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http;

use InvalidArgumentException;

/**
 * A vault HTTP client that connects to a host only at addresses the caller
 * resolved and checked itself.
 *
 * For a consumer that runs its own destination check — resolve the host, vet
 * every address — and must not let a second DNS lookup pick a different
 * address before the connect (ADR-052). Separate from
 * `VaultHttpClientInterface` and additive, so a consumer feature-detects it:
 *
 *     $client = $vault->http()->withAuthentication('agent_token');
 *     if ($client instanceof PinnedAddressHttpClientInterface) {
 *         $client = $client->withPinnedAddresses('agent.example.com', $checkedAddresses);
 *     }
 *
 * A calling interface: a minor release may add methods to it.
 */
interface PinnedAddressHttpClientInterface
{
    /**
     * Return a client whose requests to `$host` connect only to `$addresses`.
     *
     * The returned client keeps the credential, reason and timeout of this
     * one, and every with-method called on it keeps the pin. All three sends —
     * `sendRequest()`, `sendCancellable()`, `sendStreaming()` — use it. The
     * addresses replace nr-vault's own DNS answer for that host and pass the
     * same range check, so a private or loopback address is still refused
     * unless the host has a literal `allowed_hosts` entry. A transfer that
     * cannot pin (no ext-curl) is refused rather than resolved by the
     * transport. Redirects are returned, not followed, and nothing is retried.
     * Requests to other hosts, and an OAuth token request, resolve as before.
     *
     * A client passed to the constructor is replaced by one built from the
     * factory, as `withTimeout()` does, because only that one carries the pin.
     *
     * @param string       $host      A host name, without scheme, port or brackets
     * @param list<string> $addresses Bare IPv4 or IPv6 addresses, at least one
     *
     * @throws InvalidArgumentException When the host is not a host name, or an
     *                                  address is not a bare IP address
     */
    public function withPinnedAddresses(string $host, array $addresses): static;
}
