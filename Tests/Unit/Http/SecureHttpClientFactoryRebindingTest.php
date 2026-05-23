<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;
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
    private SecureHttpClientFactory $subject;

    private mixed $originalGlobals;

    protected function setUp(): void
    {
        parent::setUp();
        $this->subject = new SecureHttpClientFactory();
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
        self::assertSame([], $this->callBuildResolveEntries('93.184.216.34', 443));
        self::assertSame([], $this->callBuildResolveEntries('::1', 443));
    }

    #[Test]
    public function buildResolveEntriesReturnsEmptyForUnresolvableHost(): void
    {
        // Synthetic hostname that DNS cannot resolve — middleware lets curl
        // produce the usual connection-failure error path.
        $entries = $this->callBuildResolveEntries(
            'this-host-must-not-resolve.invalid',
            443,
        );

        self::assertSame([], $entries);
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
    public function middlewareRejectsRequestToHostResolvingToLoopback(): void
    {
        $client = $this->buildCapturingClient($capturedOptions);

        $this->expectException(RequestException::class);
        $this->expectExceptionMessageMatches('/DNS rebinding defence/i');

        // `localhost` reliably resolves to 127.0.0.1 (loopback) — the
        // middleware must refuse to dispatch the request.
        $client->get('http://localhost/');
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
    private function callBuildResolveEntries(string $host, int $port): ?array
    {
        $method = (new ReflectionClass(SecureHttpClientFactory::class))
            ->getMethod('buildResolveEntries');

        return $method->invoke($this->subject, $host, $port);
    }
}
