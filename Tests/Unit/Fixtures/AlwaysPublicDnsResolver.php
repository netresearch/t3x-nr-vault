<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Fixtures;

use Netresearch\NrVault\Http\DnsResolverInterface;

/**
 * Every host resolves to one address in TEST-NET-3 (RFC 5737), which is
 * reserved for documentation and lies outside every range the SSRF guard
 * refuses.
 *
 * It exists because the guard fails closed: a host that resolves to nothing
 * is rejected, so a test that merely wants to get past the host gate — the
 * OAuth and vault-client tests, which assert on requests and audit rows, not
 * on DNS — must say what the host resolves to. Left to the production
 * resolver those tests would ask the machine's real DNS for
 * `vault.example.com`, and then pass or fail depending on whether the network
 * they run on answers for it.
 *
 * Tests that are ABOUT resolution use {@see InMemoryDnsResolver} instead and
 * program each host deliberately.
 */
final class AlwaysPublicDnsResolver implements DnsResolverInterface
{
    public const ADDRESS = '203.0.113.10';

    public function resolve(string $host): array
    {
        return [['ip' => self::ADDRESS]];
    }
}
