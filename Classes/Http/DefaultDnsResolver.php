<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http;

/**
 * Production DNS resolver — delegates to PHP's `dns_get_record()` with
 * the `A | AAAA` filter so the SSRF defence sees both v4 and v6 records.
 *
 * Resolution failures (NXDOMAIN, SERVFAIL, timeouts, missing
 * `dns_get_record` extension support for a given record type) collapse
 * to the empty list — the caller treats that as "let the HTTP client
 * surface the usual connection-error path".
 */
final class DefaultDnsResolver implements DnsResolverInterface
{
    public function resolve(string $host): array
    {
        // Suppress DNS-lookup warnings (banned `@` operator per phpstan-strict-rules).
        set_error_handler(static fn (): bool => true);

        try {
            /** @var list<array<string, mixed>>|false $records */
            $records = dns_get_record($host, DNS_A | DNS_AAAA);
        } finally {
            restore_error_handler();
        }

        if (!\is_array($records) || $records === []) {
            return [];
        }

        $out = [];
        foreach ($records as $record) {
            $ip = $record['ip'] ?? null;
            $ipv6 = $record['ipv6'] ?? null;
            $entry = [];
            if (\is_string($ip)) {
                $entry['ip'] = $ip;
            }

            if (\is_string($ipv6)) {
                $entry['ipv6'] = $ipv6;
            }

            if ($entry !== []) {
                $out[] = $entry;
            }
        }

        return $out;
    }
}
