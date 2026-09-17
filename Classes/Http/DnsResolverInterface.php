<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http;

/**
 * Thin seam over `dns_get_record()` so the SSRF / DNS-rebinding defence
 * can be exercised in unit tests without hitting the real DNS resolver.
 *
 * Two implementations:
 *  - {@see DefaultDnsResolver} for production (delegates to
 *    `dns_get_record(A | AAAA)`).
 *  - in-memory test doubles supplied by individual tests.
 */
interface DnsResolverInterface
{
    /**
     * Resolve the A + AAAA records for `$host`. Returns a list whose
     * entries each carry an `ip` (IPv4) or `ipv6` (IPv6) string field —
     * mirroring `dns_get_record()`'s shape so the SSRF defence can keep
     * iterating the same structure.
     *
     * Returns the empty list when the host cannot be resolved. That is
     * not evidence that the host is unreachable — an implementation that
     * speaks DNS cannot see `/etc/hosts`, NSS or mDNS, which the HTTP
     * transport's own resolver does read — so the caller reads it as "no
     * address was checked" and refuses the request. The one exception is
     * a host listed literally in `allowed_hosts`: there the operator has
     * opted in, the empty list yields no pin, and the transport's error
     * path is theirs. See ADR-038.
     *
     * @return list<array{ip?: string, ipv6?: string}>
     */
    public function resolve(string $host): array;
}
