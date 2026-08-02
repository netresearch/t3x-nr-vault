<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Http {
    use Netresearch\NrVault\Tests\Unit\Http\DefaultDnsResolverTest;

    /**
     * Namespaced shadow of the native `dns_get_record()`.
     *
     * `DefaultDnsResolver` calls the function unqualified, so PHP resolves it
     * against this namespace first — which lets the test drive the resolver
     * without a single real DNS query. With no handler installed the call is
     * forwarded to the global function, so any other code in this namespace
     * keeps its production behaviour.
     *
     * @param array<mixed>|null $authoritativeNameServers Accepted for signature
     *                                                    parity only — the resolver never asks for the diagnostic
     *                                                    record sets, so the fallback does not forward them.
     * @param array<mixed>|null $additionalRecords Accepted for signature parity only
     *
     * @return array<mixed>|false
     */
    function dns_get_record(
        string $hostname,
        int $type = DNS_ANY,
        ?array &$authoritativeNameServers = null,
        ?array &$additionalRecords = null,
        bool $raw = false,
    ): array|false {
        $handler = DefaultDnsResolverTest::$dnsHandler;

        if ($handler === null) {
            // Called through a variable so the global function is reached
            // without a `\` prefix: the CGL rule `native_function_invocation`
            // (strict, @compiler_optimized only) would strip that prefix and
            // turn the fallback into infinite self-recursion.
            $native = 'dns_get_record';
            $nativeNameServers = null;
            $nativeAdditionalRecords = null;

            return $native($hostname, $type, $nativeNameServers, $nativeAdditionalRecords, $raw);
        }

        return $handler($hostname, $type);
    }
}

namespace Netresearch\NrVault\Tests\Unit\Http {
    use Closure;
    use Netresearch\NrVault\Http\DefaultDnsResolver;
    use Netresearch\NrVault\Tests\Unit\TestCase;
    use PHPUnit\Framework\Attributes\CoversClass;
    use PHPUnit\Framework\Attributes\Test;
    use RuntimeException;

    /**
     * This resolver feeds the SSRF defence. Everything it returns is treated as
     * "an address this request may end up connecting to", so the tests below are
     * about what the mapping lets through: the lookup must ask for AAAA as well
     * as A (or an IPv6-only internal target would never be inspected), and any
     * record shape it cannot read as an address must be dropped rather than
     * forwarded half-formed.
     *
     * No real DNS traffic: the native lookup is shadowed by the namespaced
     * `dns_get_record()` declared above.
     */
    #[CoversClass(DefaultDnsResolver::class)]
    final class DefaultDnsResolverTest extends TestCase
    {
        /**
         * Installed lookup double, read by the namespaced `dns_get_record()`.
         *
         * @var (Closure(string, int): (array<mixed>|false))|null
         */
        public static ?Closure $dnsHandler = null;

        private DefaultDnsResolver $subject;

        protected function setUp(): void
        {
            parent::setUp();

            $this->subject = new DefaultDnsResolver();
        }

        protected function tearDown(): void
        {
            self::$dnsHandler = null;

            parent::tearDown();
        }

        /**
         * An A-only lookup would leave every AAAA-reachable internal target
         * uninspected by the SSRF guard.
         */
        #[Test]
        public function lookupAsksForBothAddressFamilies(): void
        {
            $requestedType = null;
            self::$dnsHandler = static function (string $host, int $type) use (&$requestedType): array {
                $requestedType = $type;

                return [];
            };

            $this->subject->resolve('vault.example.com');

            self::assertSame(DNS_A | DNS_AAAA, $requestedType);
        }

        #[Test]
        public function hostnameIsPassedThroughUnchanged(): void
        {
            $requestedHost = null;
            self::$dnsHandler = static function (string $host) use (&$requestedHost): array {
                $requestedHost = $host;

                return [];
            };

            $this->subject->resolve('vault.example.com');

            self::assertSame('vault.example.com', $requestedHost);
        }

        #[Test]
        public function bothAddressFamiliesAreReturned(): void
        {
            self::$dnsHandler = static fn (): array => [
                ['host' => 'vault.example.com', 'class' => 'IN', 'ttl' => 60, 'type' => 'A', 'ip' => '198.51.100.7'],
                ['host' => 'vault.example.com', 'class' => 'IN', 'ttl' => 60, 'type' => 'AAAA', 'ipv6' => '2001:db8::7'],
            ];

            self::assertSame(
                [['ip' => '198.51.100.7'], ['ipv6' => '2001:db8::7']],
                $this->subject->resolve('vault.example.com'),
            );
        }

        /**
         * Only the address fields survive: the SSRF guard iterates the result
         * and must not be handed TTL/type metadata it might key off.
         */
        #[Test]
        public function recordMetadataIsStrippedFromTheResult(): void
        {
            self::$dnsHandler = static fn (): array => [
                ['host' => 'vault.example.com', 'ttl' => 60, 'type' => 'A', 'ip' => '198.51.100.7'],
            ];

            self::assertSame([['ip' => '198.51.100.7']], $this->subject->resolve('vault.example.com'));
        }

        #[Test]
        public function recordCarryingBothFamiliesKeepsBothAddresses(): void
        {
            self::$dnsHandler = static fn (): array => [
                ['ip' => '198.51.100.7', 'ipv6' => '2001:db8::7'],
            ];

            self::assertSame(
                [['ip' => '198.51.100.7', 'ipv6' => '2001:db8::7']],
                $this->subject->resolve('vault.example.com'),
            );
        }

        /**
         * NXDOMAIN / SERVFAIL / timeout all surface as `false`. The empty list
         * hands the decision back to the HTTP client's normal connection-error
         * path instead of inventing an address.
         */
        #[Test]
        public function failedLookupYieldsTheEmptyList(): void
        {
            self::$dnsHandler = static fn (): false => false;

            self::assertSame([], $this->subject->resolve('nxdomain.example.invalid'));
        }

        #[Test]
        public function emptyRecordSetYieldsTheEmptyList(): void
        {
            self::$dnsHandler = static fn (): array => [];

            self::assertSame([], $this->subject->resolve('vault.example.com'));
        }

        /**
         * A record with no address field (CNAME/TXT shapes surface here when a
         * resolver answers loosely) must be dropped, not forwarded as an empty
         * entry the guard would then have to special-case.
         */
        #[Test]
        public function recordsWithoutAnAddressAreDropped(): void
        {
            self::$dnsHandler = static fn (): array => [
                ['host' => 'vault.example.com', 'type' => 'CNAME', 'target' => 'origin.example.com'],
                ['host' => 'vault.example.com', 'type' => 'TXT', 'txt' => 'v=spf1 -all'],
            ];

            self::assertSame([], $this->subject->resolve('vault.example.com'));
        }

        /**
         * A non-string address cannot be checked against the private-range
         * rules, so it is dropped rather than coerced into something that would
         * pass those checks by accident.
         */
        #[Test]
        public function nonStringAddressesAreDropped(): void
        {
            self::$dnsHandler = static fn (): array => [
                ['ip' => 2130706433],
                ['ipv6' => ['2001:db8::7']],
                ['ip' => null, 'ipv6' => null],
            ];

            self::assertSame([], $this->subject->resolve('vault.example.com'));
        }

        /**
         * Dropping records must not leave gaps in the keys — the contract is a
         * list, and a gapped array breaks callers that iterate positionally.
         */
        #[Test]
        public function resultStaysAListAfterRecordsAreDropped(): void
        {
            self::$dnsHandler = static fn (): array => [
                ['type' => 'CNAME', 'target' => 'origin.example.com'],
                ['ip' => '198.51.100.7'],
                ['type' => 'TXT', 'txt' => 'v=spf1 -all'],
                ['ipv6' => '2001:db8::7'],
            ];

            $resolved = $this->subject->resolve('vault.example.com');

            self::assertTrue(array_is_list($resolved));
            self::assertSame([['ip' => '198.51.100.7'], ['ipv6' => '2001:db8::7']], $resolved);
        }

        /**
         * `dns_get_record()` warns on a failed lookup. The resolver silences it
         * deliberately (the `@` operator is banned by the PHPStan ruleset) —
         * under `failOnWarning` an escaping diagnostic would fail this test.
         */
        #[Test]
        public function lookupDiagnosticsAreSuppressed(): void
        {
            self::$dnsHandler = static function (): false {
                trigger_error('DNS Query failed', E_USER_WARNING);

                return false;
            };

            self::assertSame([], $this->subject->resolve('nxdomain.example.invalid'));
        }

        #[Test]
        public function errorHandlerIsRestoredAfterTheLookup(): void
        {
            self::$dnsHandler = static fn (): array => [['ip' => '198.51.100.7']];

            $sentinel = static fn (): bool => true;
            set_error_handler($sentinel);

            $this->subject->resolve('vault.example.com');

            self::assertSame($sentinel, $this->currentErrorHandler());

            restore_error_handler();
        }

        /**
         * The suppression sits in a `try/finally`: an exception escaping the
         * lookup must not leave the whole request running under a swallow-all
         * error handler.
         */
        #[Test]
        public function errorHandlerIsRestoredWhenTheLookupThrows(): void
        {
            self::$dnsHandler = static function (): never {
                throw new RuntimeException('resolver exploded');
            };

            $sentinel = static fn (): bool => true;
            set_error_handler($sentinel);

            try {
                $this->subject->resolve('vault.example.com');
                self::fail('The exception from the lookup should propagate');
            } catch (RuntimeException) {
                self::assertSame($sentinel, $this->currentErrorHandler());
            } finally {
                restore_error_handler();
            }
        }

        /**
         * Reads the active error handler without changing the stack depth.
         */
        private function currentErrorHandler(): mixed
        {
            $current = set_error_handler(static fn (): bool => true);
            restore_error_handler();

            return $current;
        }
    }
}
