<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Netresearch\NrVault\Http\DnsResolverInterface;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\RequestInterface;
use ReflectionClass;
use TypeError;

/**
 * The short-lived DNS memo that collapses the double resolve per outbound
 * request (issue #304).
 *
 * Before the memo, every request resolved its host twice: once in the
 * caller-side `isHostAllowed()` gate and again in the `ssrf-dns-pin`
 * middleware. The memo lets the middleware reuse the gate's answer — but only
 * where issue #304's security constraint allows it: on the curl path every
 * memoised IP is still range-checked and then pinned, so the sharing changes
 * WHEN the answer was resolved, never whether it is checked. These tests pin
 * both halves: the lookup count, and that a memoised answer keeps being
 * checked.
 *
 * The ext-curl-less branch of `buildResolveEntries()` (fresh resolve, no
 * memo) cannot be exercised here — `\function_exists('curl_init')` cannot be
 * faked in-process, the same limitation the pin-attachment guard itself has.
 * The branch is three lines whose reasoning lives in the method's comment.
 */
#[CoversClass(SecureHttpClientFactory::class)]
final class SecureHttpClientFactoryDnsMemoTest extends TestCase
{
    private const PUBLIC_IP = '93.184.216.34';

    private const PUBLIC_IP_SECONDARY = '93.184.216.35';

    private const DOCKER_IP = '172.18.0.5';

    private const HOST = 'api.example';

    private SecureHttpClientFactory $subject;

    private SequencedDnsResolver $dnsResolver;

    private mixed $originalGlobals;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dnsResolver = new SequencedDnsResolver();
        $this->subject = new SecureHttpClientFactory($this->dnsResolver);
        $this->originalGlobals = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
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

    #[Test]
    public function theGateAndThePinShareOneResolverAnswer(): void
    {
        // The headline of issue #304: gate first, middleware second, ONE
        // dns_get_record between them.
        $this->dnsResolver->answer(self::HOST, [['ip' => self::PUBLIC_IP]]);

        self::assertTrue($this->subject->isHostAllowed(self::HOST));

        $client = $this->buildCapturingClient($capturedOptions);
        $client->get('https://' . self::HOST . '/v1/data');

        self::assertSame(1, $this->dnsResolver->queryCount(self::HOST), 'The middleware must reuse the gate\'s answer, not resolve again.');
        self::assertIsArray($capturedOptions);
        self::assertSame(
            [self::HOST . ':443:' . self::PUBLIC_IP],
            $capturedOptions['curl'][\CURLOPT_RESOLVE] ?? null,
            'The reused answer must still be pinned — sharing the lookup must not drop the pin.',
        );
    }

    #[Test]
    public function twoGateChecksInsideTheTtlShareOneAnswer(): void
    {
        $this->dnsResolver->answer(self::HOST, [['ip' => self::PUBLIC_IP]]);

        self::assertTrue($this->subject->isHostAllowed(self::HOST));
        self::assertTrue($this->subject->isHostAllowed(self::HOST));

        self::assertSame(1, $this->dnsResolver->queryCount(self::HOST));
    }

    #[Test]
    public function aMemoisedAnswerIsStillCheckedBeforeThePin(): void
    {
        // "Resolved once, compared" must not become "resolved once, trusted":
        // the middleware re-checks every IP it takes from the memo. A host the
        // gate already rejected is rejected again on the send path, from the
        // same single resolver answer.
        $this->dnsResolver->answer(self::HOST, [['ip' => self::DOCKER_IP]]);

        self::assertFalse($this->subject->isHostAllowed(self::HOST));

        $client = $this->buildCapturingClient($capturedOptions);

        try {
            $client->get('https://' . self::HOST . '/v1/data');
            self::fail('The middleware must reject a memoised dangerous answer.');
        } catch (RequestException $e) {
            self::assertStringContainsString('disallowed IP range', $e->getMessage());
        }

        self::assertSame(1, $this->dnsResolver->queryCount(self::HOST), 'Both rejections must come from one resolver answer.');
        self::assertNull($capturedOptions, 'Nothing may reach the transport.');
    }

    #[Test]
    public function aRebindInsideTheTtlConnectsToTheVettedAddressNotTheNewOne(): void
    {
        // An attacker who rebinds between the gate and the send gains nothing
        // on the curl path: the memo means the middleware pins the address the
        // gate CHECKED — the rebound answer is never even fetched, and curl
        // cannot connect anywhere else.
        $this->dnsResolver->answer(self::HOST, [['ip' => self::PUBLIC_IP]], [['ip' => self::DOCKER_IP]]);

        self::assertTrue($this->subject->isHostAllowed(self::HOST));

        $client = $this->buildCapturingClient($capturedOptions);
        $client->get('https://' . self::HOST . '/v1/data');

        self::assertSame(1, $this->dnsResolver->queryCount(self::HOST));
        self::assertIsArray($capturedOptions);
        self::assertSame(
            [self::HOST . ':443:' . self::PUBLIC_IP],
            $capturedOptions['curl'][\CURLOPT_RESOLVE] ?? null,
            'The pin must carry the vetted address, not the rebound one.',
        );
    }

    #[Test]
    public function anExpiredMemoEntryIsResolvedAgain(): void
    {
        $this->dnsResolver->answer(
            self::HOST,
            [['ip' => self::PUBLIC_IP]],
            [['ip' => self::PUBLIC_IP_SECONDARY]],
        );

        self::assertTrue($this->subject->isHostAllowed(self::HOST));
        $this->expireMemoEntry(self::HOST);
        self::assertTrue($this->subject->isHostAllowed(self::HOST));

        self::assertSame(2, $this->dnsResolver->queryCount(self::HOST), 'An expired entry must trigger a fresh lookup.');
    }

    #[Test]
    public function aFailedResolutionIsNotMemoised(): void
    {
        // Sequence: first NXDOMAIN, then a dangerous answer. If the failure
        // were memoised, the second gate check would reuse the empty answer
        // and pass a host whose fresh answer is dangerous.
        $this->dnsResolver->answer(self::HOST, [], [['ip' => self::DOCKER_IP]]);

        self::assertTrue($this->subject->isHostAllowed(self::HOST), 'An unresolvable host passes the gate (connection error surfaces later).');
        self::assertFalse($this->subject->isHostAllowed(self::HOST), 'The second check must see the fresh, dangerous answer.');

        self::assertSame(2, $this->dnsResolver->queryCount(self::HOST));
    }

    /**
     * Backdate the memo entry for `$host` so the next lookup sees it expired.
     * Reflection instead of sleeping: the TTL is seconds, and a sleeping test
     * is a flake generator.
     */
    private function expireMemoEntry(string $host): void
    {
        $property = (new ReflectionClass(SecureHttpClientFactory::class))->getProperty('dnsMemo');
        /** @var array<string, array{expiresAt: float, records: list<array{ip?: string, ipv6?: string}>}> $memo */
        $memo = $property->getValue($this->subject);
        self::assertArrayHasKey($host, $memo, 'Expected a memo entry to expire.');
        $memo[$host]['expiresAt'] = microtime(true) - 1.0;
        $property->setValue($this->subject, $memo);
    }

    /**
     * Build a Client whose factory-installed middleware stack is intact, but
     * the BOTTOM handler is replaced with a capturing stub — the same seam as
     * in SecureHttpClientFactoryRebindingTest.
     *
     * @param array<string, mixed>|null $capturedOptions
     *
     * @param-out array<string, mixed>|null $capturedOptions
     */
    private function buildCapturingClient(?array &$capturedOptions): Client
    {
        $capturedOptions = null;

        $client = $this->subject->create();
        self::assertInstanceOf(Client::class, $client);
        // The deprecated getConfig() seam is the suite's only in-process way
        // to reach the handler stack — same usage as in
        // SecureHttpClientFactoryRebindingTest (there via the baseline).
        /** @phpstan-ignore method.deprecated */
        $handler = $client->getConfig('handler');
        if (!$handler instanceof HandlerStack) {
            throw new TypeError('Factory must build a HandlerStack-backed client.', 7093840416);
        }

        $handler->setHandler(
            static function (RequestInterface $request, array $options) use (&$capturedOptions): PromiseInterface {
                $capturedOptions = $options;

                return Create::promiseFor(new Response(200, [], ''));
            },
        );

        return $client;
    }
}

/**
 * Test double returning a programmed SEQUENCE of answers per host — the
 * rebinding scenarios need the second lookup to answer differently from the
 * first, which `InMemoryDnsResolver`'s static programming cannot express.
 * The last programmed answer repeats once the sequence is exhausted.
 */
final class SequencedDnsResolver implements DnsResolverInterface
{
    /** @var array<string, list<list<array{ip?: string, ipv6?: string}>>> */
    private array $sequences = [];

    /** @var array<string, int> */
    private array $queries = [];

    /**
     * @param list<array{ip?: string, ipv6?: string}> ...$answers
     */
    public function answer(string $host, array ...$answers): void
    {
        $this->sequences[$host] = array_values($answers);
    }

    public function resolve(string $host): array
    {
        $index = $this->queries[$host] ?? 0;
        $this->queries[$host] = $index + 1;

        $sequence = $this->sequences[$host] ?? [];
        if ($sequence === []) {
            return [];
        }

        return $sequence[min($index, \count($sequence) - 1)];
    }

    public function queryCount(string $host): int
    {
        return $this->queries[$host] ?? 0;
    }
}
