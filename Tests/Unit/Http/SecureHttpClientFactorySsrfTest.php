<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * SSRF defence — defence-in-depth IP / hostname / port-form rejection.
 */
#[CoversClass(SecureHttpClientFactory::class)]
final class SecureHttpClientFactorySsrfTest extends TestCase
{
    private const PRIVATE_IP = '10.0.0.42';

    private SecureHttpClientFactory $subject;

    private mixed $originalGlobals;

    protected function setUp(): void
    {
        parent::setUp();
        $this->subject = new SecureHttpClientFactory();
        $this->originalGlobals = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        // Ensure no allowlist is configured so the IP guards alone decide.
        $GLOBALS['TYPO3_CONF_VARS'] = ['HTTP' => []];
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        if ($this->originalGlobals !== null) {
            $GLOBALS['TYPO3_CONF_VARS'] = $this->originalGlobals;
        } else {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        }
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function dangerousIpProvider(): iterable
    {
        // IPv4 dangerous ranges
        yield 'ipv4 loopback' => ['127.0.0.1'];
        yield 'ipv4 loopback edge' => ['127.255.255.254'];
        yield 'aws metadata' => ['169.254.169.254'];
        yield 'rfc1918 /8' => ['10.0.0.1'];
        yield 'rfc1918 /12' => ['172.16.0.1'];
        yield 'rfc1918 /16' => ['192.168.1.1'];
        yield 'cgnat 100.64/10' => ['100.64.0.1'];
        yield 'zero net' => ['0.0.0.0'];
        yield 'multicast 224/4' => ['224.0.0.1'];
        yield 'reserved 240/4' => ['240.0.0.1'];
        yield 'benchmark 198.18/15' => ['198.18.0.1'];

        // IPv6 dangerous ranges
        yield 'ipv6 loopback' => ['::1'];
        yield 'ipv6 ula fc00::/7' => ['fc00::1'];
        yield 'ipv6 link-local fe80::/10' => ['fe80::1'];
        yield 'ipv6 multicast ff00::/8' => ['ff02::1'];

        // IPv6 transition forms — each embeds a dangerous IPv4 that a naive
        // range check would let through (CVE-2026-48736 class). The deny logic
        // decodes the embedded IPv4 and recurses into the v4 check.
        yield 'ipv4-mapped metadata ::ffff:169.254.169.254' => ['::ffff:169.254.169.254'];
        yield 'ipv4-mapped loopback ::ffff:127.0.0.1' => ['::ffff:127.0.0.1'];
        yield '6to4 metadata 2002:a9fe:a9fe::' => ['2002:a9fe:a9fe::'];
        yield 'nat64 metadata 64:ff9b::169.254.169.254' => ['64:ff9b::169.254.169.254'];
        yield 'ipv4-compatible loopback ::127.0.0.1' => ['::127.0.0.1'];
        // Teredo (2001:0::/32): server 8.8.8.8 (public), client 127.0.0.1
        // stored obfuscated (XOR 0xffffffff). The client IPv4 alone is enough
        // to deny: 127.0.0.1 ^ 0xffffffff packed back → 2001:0:808:808::80ff:fffe.
        yield 'teredo internal client 127.0.0.1' => ['2001:0:808:808::80ff:fffe'];

        // host:port / [ipv6]:port — port-stripping must not bypass the guard
        yield 'ipv4 with port' => ['127.0.0.1:8080'];
        yield 'aws metadata with port' => ['169.254.169.254:80'];
        yield 'ipv6 bracketed loopback' => ['[::1]'];
        yield 'ipv6 bracketed with port' => ['[::1]:8080'];
        yield 'ipv6 ula bracketed port' => ['[fc00::1]:443'];

        // Hygiene: trailing dot, whitespace, mixed case
        yield 'whitespace padded' => [" \t127.0.0.1\r\n"];
        yield 'mixed case ipv6' => ['FE80::1'];
    }

    #[Test]
    #[DataProvider('dangerousIpProvider')]
    public function isHostAllowedRejectsDangerousIpLiterals(string $host): void
    {
        self::assertFalse(
            $this->subject->isHostAllowed($host),
            \sprintf('Expected host %s to be blocked as dangerous, but it was allowed.', $host),
        );
    }

    #[Test]
    public function isHostAllowedReturnsFalseForEmptyHost(): void
    {
        self::assertFalse($this->subject->isHostAllowed(''));
        self::assertFalse($this->subject->isHostAllowed("\t \n"));
    }

    #[Test]
    public function isHostAllowedReturnsFalseForUnparsable(): void
    {
        // parse_url returning no host means we fail closed.
        self::assertFalse($this->subject->isHostAllowed('://no-scheme-no-host'));
    }

    #[Test]
    public function isHostAllowedAllowsPublicIpWithNoAllowlist(): void
    {
        // 8.8.8.8 is a public IPv4 — once IP guards pass and no allowlist is set,
        // the method must return true (default-allow gated by IP/DNS checks).
        self::assertTrue($this->subject->isHostAllowed('8.8.8.8'));
    }

    #[Test]
    public function isHostAllowedAllowsPublicIpv6WithNoAllowlist(): void
    {
        // 2606:4700:4700::1111 (Cloudflare) is a public IPv6 literal — it is
        // NOT a transition form and embeds no dangerous IPv4, so once the IPv6
        // guards pass and no allowlist is set it must be allowed. This is the
        // control that proves the transition-form deny rows aren't over-blocking
        // all IPv6.
        self::assertTrue($this->subject->isHostAllowed('2606:4700:4700::1111'));
    }

    #[Test]
    public function explicitAllowlistEntryOverridesPrivateIpBlock(): void
    {
        // On-prem use case: vault server on RFC1918 must be reachable via
        // an explicit filesystem-only allowlist entry.
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'HTTP' => ['allowed_hosts' => [self::PRIVATE_IP]],
        ];

        self::assertTrue($this->subject->isHostAllowed(self::PRIVATE_IP));
    }

    #[Test]
    public function wildcardAllowlistDoesNotOverridePrivateIpBlock(): void
    {
        // Wildcards cannot bypass the private-IP defence: an external wildcard
        // owner could otherwise pivot via internal DNS records under their zone.
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'HTTP' => ['allowed_hosts' => ['*.internal']],
        ];

        self::assertFalse($this->subject->isHostAllowed(self::PRIVATE_IP));
    }

    #[Test]
    public function explicitAllowlistEntryStillBlocksNonListedPrivateIp(): void
    {
        // Listing 10.0.0.42 must NOT implicitly allow 10.0.0.43.
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'HTTP' => ['allowed_hosts' => [self::PRIVATE_IP]],
        ];

        self::assertFalse($this->subject->isHostAllowed('10.0.0.43'));
    }
}
