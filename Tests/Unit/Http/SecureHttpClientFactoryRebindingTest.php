<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
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
 * DNS-rebinding defence tests.
 *
 * The middleware pushed by {@see SecureHttpClientFactory::create()} resolves
 * the request host AT REQUEST TIME and pins the resulting IP via curl's
 * `CURLOPT_RESOLVE` option, so the upstream client cannot re-resolve to a
 * different (internal) address between our check and the connect.
 *
 * These tests avoid hitting the real DNS by exercising the private
 * `buildResolveEntries` helper directly (via reflection) for the resolution-
 * outcome assertions, and by replacing the bottom handler of the factory's
 * HandlerStack for the wiring assertions.
 */
#[CoversClass(SecureHttpClientFactory::class)]
final class SecureHttpClientFactoryRebindingTest extends TestCase
{
    private const METADATA_IP = '169.254.169.254';

    private const DOCKER_IP = '172.18.0.5';

    private const PUBLIC_IP = '93.184.216.34';

    private const PUBLIC_IP_SECONDARY = '93.184.216.35';

    private SecureHttpClientFactory $subject;

    private InMemoryDnsResolver $dnsResolver;

    private mixed $originalGlobals;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dnsResolver = new InMemoryDnsResolver();
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
    public function buildResolveEntriesReturnsEmptyForIpLiteral(): void
    {
        // IPv4 and IPv6 literals are validated by isHostAllowed() — the
        // middleware doesn't need to add a pin entry.
        self::assertSame([], $this->callBuildResolveEntries(self::PUBLIC_IP, 443));
        self::assertSame([], $this->callBuildResolveEntries('::1', 443));
    }

    #[Test]
    public function buildResolveEntriesReturnsEmptyForUnresolvableHost(): void
    {
        // Resolver returns no records → middleware lets curl produce the
        // usual connection-failure error path.
        $entries = $this->callBuildResolveEntries('unknown.example', 443);

        self::assertSame([], $entries);
    }

    #[Test]
    public function buildResolveEntriesPinsSafeIpv4(): void
    {
        $this->dnsResolver->program('api.example.com', [['ip' => self::PUBLIC_IP]]);

        $entries = $this->callBuildResolveEntries('api.example.com', 443);

        self::assertSame(['api.example.com:443:93.184.216.34'], $entries);
    }

    #[Test]
    public function buildResolveEntriesBracketsIpv6(): void
    {
        // libcurl requires IPv6 addresses in CURLOPT_RESOLVE to be bracketed
        // (`host:port:[ip]`); without brackets curl misparses the colons.
        $this->dnsResolver->program('v6.example.com', [['ipv6' => '2001:db8::1']]);

        $entries = $this->callBuildResolveEntries('v6.example.com', 443);

        self::assertSame(['v6.example.com:443:[2001:db8::1]'], $entries);
    }

    #[Test]
    public function buildResolveEntriesJoinsDualStackRecordsIntoOneEntry(): void
    {
        // Regression for #190: curl keeps only the LAST resolve entry for a
        // given host:port (later entries replace earlier ones in its cache).
        // One entry per record therefore pinned only the final DNS record —
        // typically the AAAA — so a host without IPv6 connectivity failed
        // with cURL error 7 and never fell back to the discarded IPv4 pin.
        // All safe addresses must travel comma-joined in a SINGLE entry
        // (curl's multi-address form) so curl can fall back across families.
        $this->dnsResolver->program('dual.example.com', [
            ['ip' => self::PUBLIC_IP],
            ['ipv6' => '2001:db8::1'],
        ]);

        $entries = $this->callBuildResolveEntries('dual.example.com', 443);

        self::assertSame(['dual.example.com:443:93.184.216.34,[2001:db8::1]'], $entries);
    }

    #[Test]
    public function buildResolveEntriesJoinsMultipleARecordsIntoOneEntry(): void
    {
        // Same last-entry-wins rationale for an all-IPv4 multi-record host:
        // separate entries would silently discard every fallback address.
        $this->dnsResolver->program('multi.example.com', [
            ['ip' => self::PUBLIC_IP],
            ['ip' => self::PUBLIC_IP_SECONDARY],
        ]);

        $entries = $this->callBuildResolveEntries('multi.example.com', 443);

        self::assertSame(['multi.example.com:443:93.184.216.34,93.184.216.35'], $entries);
    }

    #[Test]
    public function buildResolveEntriesDeduplicatesRepeatedAddresses(): void
    {
        // Some resolvers return the same address more than once; the pin
        // entry must not repeat it.
        $this->dnsResolver->program('dup.example.com', [
            ['ip' => self::PUBLIC_IP],
            ['ip' => self::PUBLIC_IP],
        ]);

        $entries = $this->callBuildResolveEntries('dup.example.com', 443);

        self::assertSame(['dup.example.com:443:93.184.216.34'], $entries);
    }

    #[Test]
    public function buildResolveEntriesReturnsNullWhenAnyRecordIsDangerous(): void
    {
        // Split-horizon: resolver returns one public + one internal IP. ANY
        // dangerous answer must kill the request — curl could otherwise pick
        // the internal one and we'd leak.
        $this->dnsResolver->program('rebind.example.com', [
            ['ip' => self::PUBLIC_IP],
            ['ip' => self::METADATA_IP], // AWS metadata
        ]);

        $entries = $this->callBuildResolveEntries('rebind.example.com', 443);

        self::assertNull($entries);
    }

    #[Test]
    public function buildResolveEntriesPinsDangerousIpWhenExplicitlyAllowlisted(): void
    {
        // A host the operator has opted in to via a literal `allowed_hosts`
        // entry (e.g. a self-hosted Ollama reached by a docker service name)
        // resolves to a private IP. With the allowlist flag set, the request
        // is NOT rejected — the resolved IP is pinned so a later rebind to a
        // different address is still blocked.
        $this->dnsResolver->program('ollama', [['ip' => self::DOCKER_IP]]);

        $entries = $this->callBuildResolveEntries('ollama', 11434, true);

        self::assertSame(['ollama:11434:172.18.0.5'], $entries);
    }

    #[Test]
    public function buildResolveEntriesStillRejectsDangerousIpWhenNotAllowlisted(): void
    {
        // Same host, but without the allowlist opt-in: the private-IP guard
        // still rejects (this is the request-time middleware's default).
        $this->dnsResolver->program('ollama', [['ip' => self::DOCKER_IP]]);

        $entries = $this->callBuildResolveEntries('ollama', 11434);

        self::assertNull($entries);
    }

    #[Test]
    public function middlewareAllowsHostResolvingToDangerousIpWhenExplicitlyAllowlisted(): void
    {
        // End-to-end: a literal `allowed_hosts` entry lets the request-time
        // middleware reach a private-resolving host instead of throwing — this
        // is the gap that 0.6.0 left open (the middleware ignored allowed_hosts).
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = ['ollama'];
        $this->dnsResolver->program('ollama', [['ip' => self::DOCKER_IP]]);
        $client = $this->buildCapturingClient($capturedOptions);

        $client->get('http://ollama:11434/api/tags');

        // No exception; the resolved private IP is pinned for the trusted host.
        $curlOpts = $capturedOptions['curl'] ?? null;
        self::assertIsArray($curlOpts);
        self::assertSame(['ollama:11434:172.18.0.5'], $curlOpts[\CURLOPT_RESOLVE]);
    }

    #[Test]
    public function middlewareStillRejectsPrivateIpForWildcardAllowlistEntry(): void
    {
        // Wildcards must NEVER bypass the private-IP guard: a wildcard owner
        // could register an internal DNS record under their zone and pivot.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = ['*.example'];
        $this->dnsResolver->program('evil.example', [['ip' => self::METADATA_IP]]);
        $client = $this->buildCapturingClient($capturedOptions);

        $this->expectException(RequestException::class);
        $this->expectExceptionMessageMatches('/DNS rebinding defence/i');

        $client->get('http://evil.example/');
    }

    #[Test]
    public function middlewareIsRegisteredInTheHandlerStack(): void
    {
        $client = $this->subject->create();
        $handler = $client->getConfig('handler');

        self::assertInstanceOf(HandlerStack::class, $handler);
        self::assertStringContainsString(
            'ssrf-dns-pin',
            (string) $handler,
            'The factory must push the ssrf-dns-pin middleware onto the stack.',
        );
    }

    #[Test]
    public function middlewareDoesNotAddCurlResolveForIpLiteralHost(): void
    {
        $client = $this->buildCapturingClient($capturedOptions);

        // IP literal — buildResolveEntries returns [] and no pin is added.
        $client->get('http://93.184.216.34/');

        self::assertArrayNotHasKey('curl', $capturedOptions ?? []);
    }

    #[Test]
    public function middlewareRejectsRequestToHostResolvingToDangerousIp(): void
    {
        $this->dnsResolver->program('attacker.example', [['ip' => self::METADATA_IP]]);
        $client = $this->buildCapturingClient($capturedOptions);

        $this->expectException(RequestException::class);
        $this->expectExceptionMessageMatches('/DNS rebinding defence/i');

        $client->get('http://attacker.example/');
    }

    #[Test]
    public function middlewareAddsCurlResolvePinForResolvedHost(): void
    {
        $this->dnsResolver->program('safe.example', [['ip' => self::PUBLIC_IP]]);
        $client = $this->buildCapturingClient($capturedOptions);

        $client->get('https://safe.example/api');

        $curlOpts = $capturedOptions['curl'] ?? null;
        self::assertIsArray($curlOpts);
        self::assertArrayHasKey(\CURLOPT_RESOLVE, $curlOpts);
        self::assertSame(['safe.example:443:93.184.216.34'], $curlOpts[\CURLOPT_RESOLVE]);
    }

    #[Test]
    public function middlewarePinsDualStackHostAsSingleJoinedEntry(): void
    {
        // Regression for #190 at the layer curl actually sees: the option
        // array must carry ONE entry with both addresses — two entries for
        // the same host:port would make curl keep only the last (typically
        // the AAAA), breaking IPv4 fallback on IPv6-less hosts.
        $this->dnsResolver->program('dualstack.example', [
            ['ip' => self::PUBLIC_IP],
            ['ipv6' => '2001:db8::1'],
        ]);
        $client = $this->buildCapturingClient($capturedOptions);

        $client->get('https://dualstack.example/api');

        $curlOpts = $capturedOptions['curl'] ?? null;
        self::assertIsArray($curlOpts);
        self::assertArrayHasKey(\CURLOPT_RESOLVE, $curlOpts);
        self::assertSame(
            ['dualstack.example:443:93.184.216.34,[2001:db8::1]'],
            $curlOpts[\CURLOPT_RESOLVE],
        );
    }

    #[Test]
    public function middlewareNormalisesBracketedIpv6Host(): void
    {
        // PSR-7 getHost() returns IPv6 literals wrapped in brackets. Without
        // normalisation, `filter_var(..., FILTER_VALIDATE_IP)` would reject
        // `[::1]` and the middleware would try to resolve it via DNS — both
        // useless and a security regression (the IP-literal guard wouldn't
        // run). normaliseHost() strips the brackets first.
        //
        // Verified indirectly: send to a bracketed FQDN-style host that
        // resolves via the in-memory resolver. If normalisation runs, the
        // resolver receives the bare host and the pin is generated.
        $this->dnsResolver->program('safe.example', [['ip' => self::PUBLIC_IP]]);
        $client = $this->buildCapturingClient($capturedOptions);

        $client->get('http://safe.example/api');

        self::assertContains(
            'safe.example',
            $this->dnsResolver->queriedHosts(),
            'Middleware must call resolver with the bare host (no brackets).',
        );
    }

    /**
     * Build a Client whose factory-installed middleware stack is intact, but
     * the BOTTOM handler is replaced with a capturing stub. The SSRF
     * middleware still runs on top — we just observe what reaches the
     * imaginary curl handler.
     *
     * @param-out array<string, mixed>|null $capturedOptions
     */
    private function buildCapturingClient(?array &$capturedOptions): Client
    {
        $capturedOptions = null;

        $client = $this->subject->create();
        $handler = $client->getConfig('handler');
        if (!$handler instanceof HandlerStack) {
            throw new TypeError('Factory must build a HandlerStack-backed client.', 8206566209);
        }

        $handler->setHandler(
            static function (RequestInterface $request, array $options) use (&$capturedOptions): PromiseInterface {
                $capturedOptions = $options;

                return Create::promiseFor(new Response(200, [], ''));
            },
        );

        return $client;
    }

    /**
     * @return list<string>|null
     */
    private function callBuildResolveEntries(string $host, int $port, bool $allowlisted = false): ?array
    {
        $method = (new ReflectionClass(SecureHttpClientFactory::class))
            ->getMethod('buildResolveEntries');

        return $method->invoke($this->subject, $host, $port, $allowlisted);
    }
}

/**
 * Test double that returns programmed responses for specific hosts and
 * records every host queried — used by the rebinding tests above.
 */
final class InMemoryDnsResolver implements DnsResolverInterface
{
    /** @var array<string, list<array{ip?: string, ipv6?: string}>> */
    private array $programmed = [];

    /** @var list<string> */
    private array $queried = [];

    /**
     * @param list<array{ip?: string, ipv6?: string}> $records
     */
    public function program(string $host, array $records): void
    {
        $this->programmed[$host] = $records;
    }

    public function resolve(string $host): array
    {
        $this->queried[] = $host;

        return $this->programmed[$host] ?? [];
    }

    /**
     * @return list<string>
     */
    public function queriedHosts(): array
    {
        return $this->queried;
    }
}
