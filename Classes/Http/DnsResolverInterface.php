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
     * Returns the empty list when the host cannot be resolved; the
     * caller treats that case as "let the HTTP client produce a normal
     * connection-failure error".
     *
     * @return list<array{ip?: string, ipv6?: string}>
     */
    public function resolve(string $host): array;
}
