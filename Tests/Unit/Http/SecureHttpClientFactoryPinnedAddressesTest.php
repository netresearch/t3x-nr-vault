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
use InvalidArgumentException;
use Netresearch\NrVault\Http\DnsResolverInterface;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\RequestInterface;
use TypeError;

use const CURLOPT_RESOLVE;

/**
 * `SecureHttpClientFactory::withPinnedAddresses()` (ADR-052): addresses a
 * caller resolved and checked itself replace the resolver's answer for one
 * host, and pass the same range check and the same pin as that answer.
 *
 * The bottom handler of the factory-built stack is replaced by a capturing
 * stub, as in `SecureHttpClientFactoryDnsMemoTest`: the middleware runs for
 * real, and the test reads the `CURLOPT_RESOLVE` entry it would hand to curl.
 */
#[CoversClass(SecureHttpClientFactory::class)]
final class SecureHttpClientFactoryPinnedAddressesTest extends TestCase
{
    private const HOST = 'agent.example';

    private const OTHER_HOST = 'other.example';

    private const PINNED_IP = '93.184.216.34';

    private const PINNED_IPV6 = '2606:2800:220:1:248:1893:25c8:1946';

    private const RESOLVED_IP = '198.51.100.7';

    private const PRIVATE_IP = '10.0.0.5';

    private CountingDnsResolver $dnsResolver;

    private SecureHttpClientFactory $subject;

    private mixed $originalGlobals;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dnsResolver          = new CountingDnsResolver();
        $this->subject              = new SecureHttpClientFactory($this->dnsResolver);
        $this->originalGlobals      = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
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
    public function thePinnedHostIsPinnedToTheGivenAddressesAndNeverResolved(): void
    {
        $this->dnsResolver->answers[self::HOST] = [['ip' => self::RESOLVED_IP]];

        $pinned = $this->subject->withPinnedAddresses(self::HOST, [self::PINNED_IP, self::PINNED_IPV6]);

        self::assertSame(
            [self::HOST . ':443:' . self::PINNED_IP . ',[' . self::PINNED_IPV6 . ']'],
            $this->sendThrough($pinned, 'https://' . self::HOST . '/v1'),
        );
        self::assertSame(0, $this->dnsResolver->queries(self::HOST), 'A pinned host is answered by the pin, not by DNS.');
    }

    #[Test]
    public function thePinCoversAnyPortOfTheHost(): void
    {
        $pinned = $this->subject->withPinnedAddresses(self::HOST, [self::PINNED_IP]);

        self::assertSame(
            [self::HOST . ':8443:' . self::PINNED_IP],
            $this->sendThrough($pinned, 'https://' . self::HOST . ':8443/v1'),
        );
    }

    #[Test]
    public function theAllowedHostsGateChecksThePinnedAddresses(): void
    {
        $pinned = $this->subject->withPinnedAddresses(self::HOST, [self::PINNED_IP]);

        self::assertTrue($pinned->isHostAllowed(self::HOST), 'The pin is the answer the gate checks.');
        self::assertFalse($this->subject->isHostAllowed(self::HOST), 'The original factory has no pin and no DNS answer.');
        self::assertSame(1, $this->dnsResolver->queries(self::HOST), 'Only the original factory asked the resolver.');
    }

    #[Test]
    public function aPinnedPrivateAddressIsRefusedLikeAResolvedOne(): void
    {
        $pinned = $this->subject->withPinnedAddresses(self::HOST, [self::PINNED_IP, self::PRIVATE_IP]);

        self::assertFalse($pinned->isHostAllowed(self::HOST));

        try {
            $this->sendThrough($pinned, 'https://' . self::HOST . '/v1');
            self::fail('A pinned private address must be refused before the transport.');
        } catch (RequestException $e) {
            self::assertStringContainsString('disallowed IP range', $e->getMessage());
        }
    }

    #[Test]
    public function aPinnedPrivateAddressPassesWithALiteralAllowedHostsEntry(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = [self::HOST];

        $pinned = $this->subject->withPinnedAddresses(self::HOST, [self::PRIVATE_IP]);

        self::assertTrue($pinned->isHostAllowed(self::HOST));
        self::assertSame(
            [self::HOST . ':443:' . self::PRIVATE_IP],
            $this->sendThrough($pinned, 'https://' . self::HOST . '/v1'),
            'The opt-in admits the address and still pins it.',
        );
    }

    #[Test]
    public function aStreamedTransferToAPinnedHostIsRefused(): void
    {
        $pinned = $this->subject->withPinnedAddresses(self::HOST, [self::PINNED_IP]);

        try {
            $this->sendThrough($pinned, 'https://' . self::HOST . '/v1', ['stream' => true]);
            self::fail('A transfer that cannot honour the pin must not reach the transport.');
        } catch (RequestException $e) {
            self::assertSame(
                'Refused to send request: host "' . self::HOST . '" has pinned addresses, but this transfer '
                . 'cannot honour a CURLOPT_RESOLVE pin (ext-curl missing, or a streamed transfer), so the '
                . 'transport would resolve the name itself.',
                $e->getMessage(),
            );
        }
    }

    #[Test]
    public function aStreamedTransferToAnotherHostIsNotAffectedByThePin(): void
    {
        $this->dnsResolver->answers[self::OTHER_HOST] = [['ip' => self::RESOLVED_IP]];
        $pinned                                       = $this->subject->withPinnedAddresses(self::HOST, [self::PINNED_IP]);

        self::assertNull(
            $this->sendThrough($pinned, 'https://' . self::OTHER_HOST . '/v1', ['stream' => true]),
            'An unpinned host keeps the existing pinless stream path.',
        );
    }

    #[Test]
    public function otherHostsStillResolveThroughTheResolver(): void
    {
        $this->dnsResolver->answers[self::OTHER_HOST] = [['ip' => self::RESOLVED_IP]];
        $pinned                                       = $this->subject->withPinnedAddresses(self::HOST, [self::PINNED_IP]);

        self::assertSame(
            [self::OTHER_HOST . ':443:' . self::RESOLVED_IP],
            $this->sendThrough($pinned, 'https://' . self::OTHER_HOST . '/v1'),
        );
        self::assertSame(1, $this->dnsResolver->queries(self::OTHER_HOST));
    }

    #[Test]
    public function theOriginalFactoryIsUnchanged(): void
    {
        $this->dnsResolver->answers[self::HOST] = [['ip' => self::RESOLVED_IP]];

        $this->subject->withPinnedAddresses(self::HOST, [self::PINNED_IP]);

        self::assertSame(
            [self::HOST . ':443:' . self::RESOLVED_IP],
            $this->sendThrough($this->subject, 'https://' . self::HOST . '/v1'),
        );
    }

    #[Test]
    public function anAnswerTheOriginalFactoryMemoisedDoesNotOutrankThePin(): void
    {
        $this->dnsResolver->answers[self::HOST] = [['ip' => self::RESOLVED_IP]];
        self::assertTrue($this->subject->isHostAllowed(self::HOST), 'Precondition: the memo holds the resolved answer.');

        $pinned = $this->subject->withPinnedAddresses(self::HOST, [self::PINNED_IP]);

        self::assertSame(
            [self::HOST . ':443:' . self::PINNED_IP],
            $this->sendThrough($pinned, 'https://' . self::HOST . '/v1'),
        );
    }

    #[Test]
    public function pinsAccumulateAndASecondPinForTheSameHostReplacesTheFirst(): void
    {
        $pinned = $this->subject
            ->withPinnedAddresses(self::HOST, [self::RESOLVED_IP])
            ->withPinnedAddresses(self::OTHER_HOST, [self::RESOLVED_IP])
            ->withPinnedAddresses(self::HOST, [self::PINNED_IP]);

        self::assertSame([self::HOST . ':443:' . self::PINNED_IP], $this->sendThrough($pinned, 'https://' . self::HOST . '/v1'));
        self::assertSame([self::OTHER_HOST . ':443:' . self::RESOLVED_IP], $this->sendThrough($pinned, 'https://' . self::OTHER_HOST . '/v1'));
        self::assertSame(0, $this->dnsResolver->queries(self::HOST) + $this->dnsResolver->queries(self::OTHER_HOST));
    }

    #[Test]
    public function theHostIsNormalisedTheWayARequestHostIs(): void
    {
        $pinned = $this->subject->withPinnedAddresses(" Agent.Example.\t", [self::PINNED_IP]);

        self::assertSame([self::HOST . ':443:' . self::PINNED_IP], $this->sendThrough($pinned, 'https://AGENT.example./v1'));
        self::assertSame(0, $this->dnsResolver->queries(self::HOST));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function hostsThatAreNotHostNames(): iterable
    {
        yield 'empty' => [''];
        yield 'blank' => ['  '];
        yield 'IPv4 literal' => ['93.184.216.34'];
        yield 'IPv6 literal' => ['::1'];
        yield 'bracketed IPv6' => ['[::1]'];
        yield 'dword IPv4' => ['2130706433'];
        yield 'hex IPv4' => ['0x7f.1'];
        yield 'with port' => ['agent.example:443'];
        yield 'with scheme' => ['https://agent.example'];
        yield 'with path' => ['agent.example/v1'];
    }

    #[Test]
    #[DataProvider('hostsThatAreNotHostNames')]
    public function aHostThatIsNotAHostNameIsRefused(string $host): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(1794317201);

        $this->subject->withPinnedAddresses($host, [self::PINNED_IP]);
    }

    /**
     * @return iterable<string, array{array<mixed>, int}>
     */
    public static function addressListsThatAreRefused(): iterable
    {
        yield 'no address' => [[], 1794317203];
        yield 'a host name' => [['agent.example'], 1794317202];
        yield 'bracketed IPv6' => [['[::1]'], 1794317202];
        yield 'with port' => [['93.184.216.34:443'], 1794317202];
        yield 'not a string' => [[2130706433], 1794317202];
        yield 'one bad among good' => [['93.184.216.34', 'nope'], 1794317202];
    }

    /**
     * @param array<mixed> $addresses
     */
    #[Test]
    #[DataProvider('addressListsThatAreRefused')]
    public function anAddressListThatIsNotBareIpAddressesIsRefused(array $addresses, int $code): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode($code);

        $this->subject->withPinnedAddresses(self::HOST, $addresses);
    }

    /**
     * Send one GET through a client of `$factory` whose bottom handler only
     * records the options, and return the `CURLOPT_RESOLVE` entry it saw —
     * null when the request reached the handler without one.
     *
     * @param array{stream?: bool} $options
     *
     * @return list<string>|null
     */
    private function sendThrough(SecureHttpClientFactory $factory, string $url, array $options = []): ?array
    {
        $client = $factory->create();
        self::assertInstanceOf(Client::class, $client);
        /** @phpstan-ignore method.deprecated */
        $handler = $client->getConfig('handler');
        if (!$handler instanceof HandlerStack) {
            throw new TypeError('Factory must build a HandlerStack-backed client.', 1794317301);
        }

        $captured = null;
        $handler->setHandler(
            static function (RequestInterface $request, array $options) use (&$captured): PromiseInterface {
                $captured = $options;

                return Create::promiseFor(new Response(200));
            },
        );

        $client->get($url, $options);
        self::assertIsArray($captured, 'The request must have reached the transport.');

        $curl = $captured['curl'] ?? [];
        self::assertIsArray($curl);
        if (!isset($curl[CURLOPT_RESOLVE])) {
            return null;
        }

        self::assertIsArray($curl[CURLOPT_RESOLVE]);
        $entries = [];
        foreach ($curl[CURLOPT_RESOLVE] as $entry) {
            self::assertIsString($entry);
            $entries[] = $entry;
        }

        return $entries;
    }
}

/**
 * Answers from a fixed map and counts lookups per host.
 */
final class CountingDnsResolver implements DnsResolverInterface
{
    /** @var array<string, list<array{ip?: string, ipv6?: string}>> */
    public array $answers = [];

    /** @var array<string, int> */
    private array $queries = [];

    public function resolve(string $host): array
    {
        $this->queries[$host] = $this->queries($host) + 1;

        return $this->answers[$host] ?? [];
    }

    public function queries(string $host): int
    {
        return $this->queries[$host] ?? 0;
    }
}
