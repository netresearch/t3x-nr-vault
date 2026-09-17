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
use GuzzleHttp\Psr7\Request;
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

    /**
     * The redirect-hop tests deliberately speak plain http:// — the SSRF filter
     * must refuse the hop regardless of scheme, and forcing https here would
     * change what is being tested.
     */
    private const HTTP_SCHEME = 'http://';

    /** Allow-listed origin the redirect starts from. */
    private const SAFE_ORIGIN = 'http://safe.example/';

    private const IPV6_EXAMPLE = '2001:db8::1';

    /** Distinguishing fragment of the disallowed-range rejection. */
    private const DISALLOWED_RANGE = 'disallowed IP range';

    /** Distinguishing fragment of the no-verified-address rejection. */
    private const NOT_VERIFIABLE = 'could not be resolved to a verifiable';

    private const PUBLIC_IPV6 = '2606:4700:4700::1111';

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
    public function buildResolveEntriesReturnsEmptyForSafeIpLiteral(): void
    {
        // A literal in a public range needs no pin entry — there is no DNS
        // answer that could be rebound between check and connect.
        self::assertSame([], $this->callBuildResolveEntries(self::PUBLIC_IP, 443));
        self::assertSame([], $this->callBuildResolveEntries(self::PUBLIC_IPV6, 443));
    }

    #[Test]
    public function buildResolveEntriesRejectsDangerousIpLiteral(): void
    {
        // The middleware runs on every hop, including redirects that never
        // passed the caller-side isHostAllowed() gate, so the literal must be
        // range-checked here rather than assumed pre-validated.
        $this->assertRejects(self::DISALLOWED_RANGE, self::METADATA_IP, 80);
        $this->assertRejects(self::DISALLOWED_RANGE, '::1', 443);
    }

    #[Test]
    public function buildResolveEntriesAcceptsDangerousIpLiteralWhenExplicitlyAllowlisted(): void
    {
        // The operator opt-in stays intact: a literal `allowed_hosts` entry
        // (signalled by $allowlisted) keeps the private literal reachable.
        self::assertSame([], $this->callBuildResolveEntries(self::DOCKER_IP, 11434, true));
    }

    #[Test]
    public function buildResolveEntriesRejectsUnresolvableHost(): void
    {
        // Resolver returns no records. That is not "nothing is reachable" —
        // this factory resolves with dns_get_record(), which speaks DNS, while
        // the transport resolves with getaddrinfo(), which also reads
        // /etc/hosts, NSS and mDNS. Handing the name on would let it connect
        // to an address no range check ever saw, so the request stops here.
        $this->assertRejects(self::NOT_VERIFIABLE, 'unknown.example', 443);
    }

    #[Test]
    public function buildResolveEntriesPassesAnUnresolvableHostTheOperatorAllowlisted(): void
    {
        // A literal `allowed_hosts` entry is the documented opt-in, and it is
        // exactly what a host served by /etc/hosts rather than DNS needs. The
        // transport's own error path is then the operator's business.
        self::assertSame([], $this->callBuildResolveEntries('unknown.example', 443, true));
    }

    #[Test]
    public function buildResolveEntriesRejectsAnswersThatCarryNoWellFormedAddress(): void
    {
        // DnsResolverInterface is a public seam. An answer that is not a
        // parseable IP cannot be range-checked and cannot be pinned, so it
        // leaves the request in the same position as an empty answer —
        // unverified — and must end the same way rather than counting as safe.
        $this->dnsResolver->program('garbage.example.com', [['ip' => 'not-an-ip']]);

        $this->assertRejects(self::NOT_VERIFIABLE, 'garbage.example.com', 443);
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
        $this->dnsResolver->program('v6.example.com', [['ipv6' => self::IPV6_EXAMPLE]]);

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
            ['ipv6' => self::IPV6_EXAMPLE],
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
    public function buildResolveEntriesRejectsWhenAnyRecordIsDangerous(): void
    {
        // Split-horizon: resolver returns one public + one internal IP. ANY
        // dangerous answer must kill the request — curl could otherwise pick
        // the internal one and we'd leak.
        $this->dnsResolver->program('rebind.example.com', [
            ['ip' => self::PUBLIC_IP],
            ['ip' => self::METADATA_IP], // AWS metadata
        ]);

        $this->assertRejects(self::DISALLOWED_RANGE, 'rebind.example.com', 443);
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

        $this->assertRejects(self::DISALLOWED_RANGE, 'ollama', 11434);
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
    public function middlewareNeverCallsTheTransportForAnUnresolvableHost(): void
    {
        // The finding this test exists for: an empty resolver answer used to
        // mean "no pin, let curl report the connection error". curl does not
        // resolve through dns_get_record() — it resolves through getaddrinfo(),
        // which reads /etc/hosts, NSS and mDNS as well, so a name that is empty
        // here can still connect there, to an address nothing range-checked.
        //
        // Counting the handler rather than catching the exception is the point:
        // an exception thrown AFTER the transport ran would satisfy a message
        // assertion and leak the request anyway.
        $client = $this->buildRedirectingClient(self::SAFE_ORIGIN, $reachedHosts);

        try {
            $client->get(self::HTTP_SCHEME . 'unresolvable.example/');
            self::fail('Expected the middleware to refuse an unresolvable host.');
        } catch (RequestException $exception) {
            self::assertStringContainsString(self::NOT_VERIFIABLE, $exception->getMessage());
        }

        self::assertSame([], $reachedHosts, 'The transport must not be reached.');
        self::assertSame(['unresolvable.example'], $this->dnsResolver->queriedHosts());
    }

    #[Test]
    public function middlewareNeverCallsTheTransportOnARedirectHopThatCannotBeResolved(): void
    {
        // The middleware sits below Guzzle's RedirectMiddleware, so a hop that
        // never passed the caller-side gate re-enters it. An unresolvable hop
        // target must stop there for the same reason the first request does.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allow_redirects'] = true;
        $this->dnsResolver->program('safe.example', [['ip' => self::PUBLIC_IP]]);
        $client = $this->buildRedirectingClient(
            self::HTTP_SCHEME . 'unresolvable.example/',
            $reachedHosts,
        );

        try {
            $client->get(self::SAFE_ORIGIN);
            self::fail('Expected the middleware to refuse the unresolvable redirect target.');
        } catch (RequestException $exception) {
            self::assertStringContainsString(self::NOT_VERIFIABLE, $exception->getMessage());
        }

        self::assertSame(
            ['safe.example'],
            $reachedHosts,
            'The hop the gate never saw must not reach the transport either.',
        );
    }

    #[Test]
    public function isHostAllowedRefusesAHostThatResolvesToNothing(): void
    {
        // Same rule at the caller-side gate, so the two cannot disagree: a
        // consumer that asks first and sends later gets one answer, not a
        // "yes" the middleware then overrules.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [];

        self::assertFalse($this->subject->isHostAllowed('unresolvable.example'));
    }

    #[Test]
    public function isHostAllowedAcceptsAHostThatResolvesToAPublicAddress(): void
    {
        // The other half of the same assertion: the gate rejects for want of a
        // checked address, not for want of an allowlist.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP'] = [];
        $this->dnsResolver->program('api.example.com', [['ip' => self::PUBLIC_IP]]);

        self::assertTrue($this->subject->isHostAllowed('api.example.com'));
    }

    #[Test]
    public function isHostAllowedAcceptsAnUnresolvableHostListedLiterally(): void
    {
        // The documented escape hatch for a host served by /etc/hosts or
        // another non-DNS source.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = ['vault.internal'];

        self::assertTrue($this->subject->isHostAllowed('vault.internal'));
    }

    #[Test]
    public function isHostAllowedRefusesAnUnresolvableHostCoveredOnlyByAWildcard(): void
    {
        // A wildcard entry has never bypassed the IP guard — it cannot bypass
        // the address requirement either, or the guard would be optional for
        // anyone who owns a zone.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = ['*.internal'];

        self::assertFalse($this->subject->isHostAllowed('vault.internal'));
    }

    #[Test]
    public function middlewareIsRegisteredInTheHandlerStack(): void
    {
        $client = $this->subject->create();
        $handler = $client->getConfig('handler');

        self::assertInstanceOf(HandlerStack::class, $handler);

        // Guzzle 7 listed the middleware names in `HandlerStack::__toString()`;
        // Guzzle 8 removed that method and the stack is private, so the name
        // is only reachable through an operation that resolves it. `before()`
        // does, and throws `Middleware not found` when the name is absent --
        // which makes the failure say what is missing rather than that an
        // object cannot be cast to a string.
        $handler->before(
            'ssrf-dns-pin',
            static fn (callable $next): callable => $next,
            'ssrf-dns-pin-probe',
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
    public function middlewareRejectsLegacyNumericIpFormHost(): void
    {
        // "2130706433" is 127.0.0.1 to curl but a pseudo-hostname to PHP —
        // the middleware must reject it BEFORE the socket opens (#192), not
        // hand it to curl to resolve internally.
        $client = $this->buildCapturingClient($capturedOptions);

        try {
            $client->get('http://2130706433/'); // NOSONAR: rejection test — the request is refused before any socket opens; scheme is irrelevant
            self::fail('The middleware must refuse a legacy numeric IP form.');
        } catch (RequestException $e) {
            // All three parts of the refusal are asserted, not just the first:
            // the message has to name the host, say what curl would do with it,
            // and tell the operator the accepted form. A refusal that states
            // only the verdict leaves whoever hits it with nothing to act on,
            // and each part is a separate string the compiler is free to drop.
            self::assertStringContainsString('non-canonical numeric IP form', $e->getMessage());
            self::assertStringContainsString('2130706433', $e->getMessage());
            self::assertStringContainsString('bypassing the IP range', $e->getMessage());
            self::assertStringContainsString('canonical dotted-quad', $e->getMessage());
        }

        self::assertNull($capturedOptions, 'Nothing may reach the transport.');
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
            ['ipv6' => self::IPV6_EXAMPLE],
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

    #[Test]
    public function middlewareRejectsRedirectHopToDangerousIpLiteral(): void
    {
        // The ssrf-dns-pin middleware is pushed LAST, so it sits closest to
        // the transport — below Guzzle's RedirectMiddleware. Every redirect
        // hop therefore re-enters it, while only the FIRST URI ever passed
        // VaultHttpClient's isHostAllowed() gate. A `302 Location:
        // http://169.254.169.254/…` must be refused by the middleware itself,
        // otherwise the cloud-metadata response is handed back to the caller.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allow_redirects'] = true;
        $this->dnsResolver->program('safe.example', [['ip' => self::PUBLIC_IP]]);
        $client = $this->buildRedirectingClient(
            self::HTTP_SCHEME . self::METADATA_IP . '/latest/meta-data/iam/security-credentials/',
            $reachedHosts,
        );

        try {
            $client->get(self::SAFE_ORIGIN);
            self::fail('Expected the redirect hop to the metadata IP to be refused.');
        } catch (RequestException $e) {
            self::assertMatchesRegularExpression('/disallowed IP range/i', $e->getMessage());
        }

        self::assertSame(
            ['safe.example'],
            $reachedHosts,
            'The metadata host must never reach the transport.',
        );
    }

    #[Test]
    public function middlewareAllowsRedirectHopToSafeIpLiteral(): void
    {
        // Control: the per-hop literal check must not block ordinary
        // redirects to public addresses.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allow_redirects'] = true;
        $this->dnsResolver->program('safe.example', [['ip' => self::PUBLIC_IP]]);
        $client = $this->buildRedirectingClient(self::HTTP_SCHEME . self::PUBLIC_IP . '/next', $reachedHosts);

        $response = $client->get(self::SAFE_ORIGIN);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['safe.example', self::PUBLIC_IP], $reachedHosts);
    }

    #[Test]
    public function middlewareAllowsRedirectHopToAllowlistedPrivateIpLiteral(): void
    {
        // The documented opt-in still wins: an operator who listed the exact
        // literal in `allowed_hosts` keeps that internal target reachable,
        // redirect hop included.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allow_redirects'] = true;
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = [self::DOCKER_IP];
        $this->dnsResolver->program('safe.example', [['ip' => self::PUBLIC_IP]]);
        $client = $this->buildRedirectingClient(self::HTTP_SCHEME . self::DOCKER_IP . '/api/tags', $reachedHosts);

        $response = $client->get(self::SAFE_ORIGIN);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['safe.example', self::DOCKER_IP], $reachedHosts);
    }

    /**
     * Build a Client whose factory-installed middleware stack is intact and
     * whose BOTTOM handler answers the FIRST request with a 302 to $location
     * and every later request with a 200. Every host that actually reached
     * the transport is recorded in $reachedHosts.
     *
     * @param-out list<string> $reachedHosts
     */
    private function buildRedirectingClient(string $location, ?array &$reachedHosts): Client
    {
        $reachedHosts = [];

        $client = $this->subject->create();
        $handler = $client->getConfig('handler');
        if (!$handler instanceof HandlerStack) {
            throw new TypeError('Factory must build a HandlerStack-backed client.', 3059133054);
        }

        $handler->setHandler(
            static function (RequestInterface $request, array $options) use ($location, &$reachedHosts): PromiseInterface {
                $reachedHosts[] = $request->getUri()->getHost();

                return Create::promiseFor(
                    \count($reachedHosts) === 1
                        ? new Response(302, ['Location' => $location], '')
                        : new Response(200, [], 'body-of-the-redirect-target'),
                );
            },
        );

        return $client;
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
     * @return list<string>
     */
    private function callBuildResolveEntries(string $host, int $port, bool $allowlisted = false): array
    {
        $method = (new ReflectionClass(SecureHttpClientFactory::class))
            ->getMethod('buildResolveEntries');

        // The URI only has to carry the host so the exception can quote the
        // request; IPv6 literals need their brackets back to survive parsing.
        $uriHost = str_contains($host, ':') ? '[' . $host . ']' : $host;

        /** @var list<string> */
        return $method->invoke(
            $this->subject,
            new Request('GET', self::HTTP_SCHEME . $uriHost . '/'),
            $host,
            $port,
            $allowlisted,
        );
    }

    /**
     * The helper rejects by throwing, so every rejection assertion also pins
     * WHICH rejection it is. The two causes read alike from the outside and
     * mean opposite things to an operator: a disallowed range is a host that
     * answered with an address we refuse, an unverifiable one is a host that
     * answered with nothing at all — a typo in a configured URL looks exactly
     * like that, and must not be logged as a rebinding attempt.
     */
    private function assertRejects(
        string $expectedMessageFragment,
        string $host,
        int $port,
        bool $allowlisted = false,
    ): void {
        try {
            $this->callBuildResolveEntries($host, $port, $allowlisted);
        } catch (RequestException $exception) {
            self::assertStringContainsString($expectedMessageFragment, $exception->getMessage());

            return;
        }

        self::fail(\sprintf('Expected host "%s" to be rejected, but it was accepted.', $host));
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
