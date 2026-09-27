<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Http\Fixtures;

use Netresearch\NrVault\Http\DnsResolverInterface;

/**
 * Answers every lookup with one fixed IPv4 address and counts the lookups.
 *
 * The name a test sends to lives under `.test` (RFC 6761), which no real
 * resolver answers — so a transfer that reaches the server at all reached it
 * through the `CURLOPT_RESOLVE` pin built from this answer, not through the
 * machine's own DNS.
 */
final class PinnedDnsResolver implements DnsResolverInterface
{
    private int $lookups = 0;

    public function __construct(private readonly string $address) {}

    public function resolve(string $host): array
    {
        ++$this->lookups;

        return [['ip' => $this->address]];
    }

    public function lookups(): int
    {
        return $this->lookups;
    }
}
