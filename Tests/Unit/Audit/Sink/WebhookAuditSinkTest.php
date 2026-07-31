<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Sink;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\Sink\WebhookAuditSink;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\AuditSinkException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Throwable;

#[CoversClass(WebhookAuditSink::class)]
final class WebhookAuditSinkTest extends TestCase
{
    private const ENDPOINT = 'https://siem.example.com/ingest';

    #[Test]
    public function identifierIsStable(): void
    {
        self::assertSame('webhook', $this->createSubject()->getIdentifier());
    }

    #[Test]
    public function disabledConfigurationReportsNotEnabled(): void
    {
        self::assertFalse($this->createSubject(enabled: false)->isEnabled());
    }

    #[Test]
    public function enabledConfigurationWithHttpsUrlReportsEnabled(): void
    {
        self::assertTrue($this->createSubject()->isEnabled());
    }

    /**
     * An enabled-but-unconfigured webhook would report itself as external
     * evidence while delivering nothing — exactly the false confidence the
     * hardened-profile check exists to catch.
     */
    #[Test]
    #[DataProvider('unusableUrlProvider')]
    public function unusableUrlReportsNotEnabled(string $url): void
    {
        self::assertFalse($this->createSubject(url: $url)->isEnabled());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableUrlProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'no scheme' => ['siem.example.com/ingest'];
        yield 'no host' => ['https://'];
        yield 'file scheme' => ['file:///etc/passwd'];
        yield 'php wrapper' => ['php://output'];
        yield 'data uri' => ['data://text/plain,x'];
        yield 'ftp scheme' => ['ftp://siem.example.com/ingest'];
    }

    #[Test]
    public function plainHttpIsAcceptedForOnPremiseCollectors(): void
    {
        self::assertTrue($this->createSubject(url: 'http://collector.internal/ingest')->isEnabled());
    }

    #[Test]
    public function publishPostsJsonToTheConfiguredEndpoint(): void
    {
        $client = new RecordingClient(new Response(202));

        $this->createSubject(client: $client)->publish($this->createEntry(), 'tip-1');

        $request = $client->lastRequest;
        self::assertInstanceOf(RequestInterface::class, $request);
        self::assertSame('POST', $request->getMethod());
        self::assertSame(self::ENDPOINT, (string) $request->getUri());
        self::assertSame('application/json', $request->getHeaderLine('Content-Type'));
    }

    #[Test]
    public function entryPayloadCarriesTypeUidAndChainTip(): void
    {
        $client = new RecordingClient(new Response(200));

        $this->createSubject(client: $client)->publish($this->createEntry(uid: 55), 'tip-55');

        $payload = $client->decodeBody();
        self::assertSame('entry', $payload['type']);
        self::assertSame('nr-vault', $payload['source']);
        self::assertSame(55, $payload['uid']);
        self::assertSame('tip-55', $payload['chainTip']);
        self::assertIsArray($payload['entry']);
    }

    #[Test]
    public function anchorPayloadCarriesTheAnchorFields(): void
    {
        $client = new RecordingClient(new Response(200));

        $this->createSubject(client: $client)->publishAnchor(
            new ChainTipAnchor(sequence: 12, chainTip: 'anchor-tip', timestamp: 1_750_000_000, hmacEpoch: 3),
        );

        $payload = $client->decodeBody();
        self::assertSame('anchor', $payload['type']);
        self::assertSame(12, $payload['anchor']['sequence']);
        self::assertSame('anchor-tip', $payload['anchor']['chainTip']);
        self::assertSame(3, $payload['anchor']['hmacEpoch']);
    }

    #[Test]
    public function alertPayloadCarriesReasonCodeAndTamperFlag(): void
    {
        $client = new RecordingClient(new Response(200));

        $this->createSubject(client: $client)->publishAlert(
            AuditIntegrityAlert::create(AuditIntegrityReason::UidGap, '3 rows missing', ['missingUidCount' => 3]),
        );

        $payload = $client->decodeBody();
        self::assertSame('alert', $payload['type']);
        self::assertSame('UID_GAP', $payload['alert']['reason']);
        self::assertTrue($payload['alert']['tamperEvidence']);
        self::assertSame(3, $payload['alert']['context']['missingUidCount']);
    }

    /**
     * Every record kind must be routable by a single collector endpoint, so the
     * discriminator has to be present on all three.
     */
    #[Test]
    public function everyRecordKindIsTaggedWithItsType(): void
    {
        $client = new RecordingClient(new Response(200));
        $subject = $this->createSubject(client: $client);

        $subject->publish($this->createEntry(), 'tip');
        $entryType = $client->decodeBody()['type'];

        $subject->publishAnchor(new ChainTipAnchor(1, 'tip', 1, 3));
        $anchorType = $client->decodeBody()['type'];

        $subject->publishAlert(AuditIntegrityAlert::create(AuditIntegrityReason::SinkFailure, 'x'));
        $alertType = $client->decodeBody()['type'];

        self::assertSame(['entry', 'anchor', 'alert'], [$entryType, $anchorType, $alertType]);
    }

    #[Test]
    #[DataProvider('acceptedStatusProvider')]
    public function twoHundredRangeResponsesAreAccepted(int $status): void
    {
        $subject = $this->createSubject(client: new RecordingClient(new Response($status)));

        $subject->publish($this->createEntry(), 'tip');

        // No exception thrown — the record was accepted.
        $this->expectNotToPerformAssertions();
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function acceptedStatusProvider(): iterable
    {
        yield '200 OK' => [200];
        yield '201 Created' => [201];
        yield '202 Accepted' => [202];
        yield '204 No Content' => [204];
    }

    /**
     * A rejected record must surface. Treating a 4xx/5xx as delivered would mean
     * the audit trail silently stops reaching the SIEM.
     */
    #[Test]
    #[DataProvider('rejectedStatusProvider')]
    public function nonSuccessResponseThrowsWithTheStatusCode(int $status): void
    {
        $subject = $this->createSubject(client: new RecordingClient(new Response($status)));

        $this->expectException(AuditSinkException::class);
        $this->expectExceptionMessage((string) $status);

        $subject->publish($this->createEntry(), 'tip');
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function rejectedStatusProvider(): iterable
    {
        yield '301 redirect' => [301];
        yield '400 bad request' => [400];
        yield '401 unauthorized' => [401];
        yield '404 not found' => [404];
        yield '500 server error' => [500];
    }

    #[Test]
    public function transportFailureIsWrappedInAnAuditSinkException(): void
    {
        $subject = $this->createSubject(
            client: new ThrowingClient(new TestClientException('connection refused')),
        );

        $this->expectException(AuditSinkException::class);
        $this->expectExceptionMessage('transport failed');

        $subject->publish($this->createEntry(), 'tip');
    }

    /**
     * The SSRF guard rejects a request before the socket opens, and a
     * PSR-17 implementation can reject a malformed URI with a plain
     * InvalidArgumentException. Neither is a ClientExceptionInterface, so both
     * must still be normalised rather than escaping as a foreign type.
     */
    #[Test]
    public function nonPsrThrowableFromTheClientIsAlsoNormalised(): void
    {
        $subject = $this->createSubject(
            client: new ThrowingClient(new RuntimeException('resolves to a disallowed IP range')),
        );

        $this->expectException(AuditSinkException::class);
        $this->expectExceptionMessage('disallowed IP range');

        $subject->publish($this->createEntry(), 'tip');
    }

    /**
     * A URL carrying a collector token must not reach the log through the
     * exception message.
     */
    #[Test]
    public function exceptionMessageDoesNotLeakTheEndpointUrl(): void
    {
        $subject = $this->createSubject(
            url: 'https://siem.example.com/ingest?token=super-secret-token',
            client: new ThrowingClient(new TestClientException('connection refused')),
        );

        try {
            $subject->publish($this->createEntry(), 'tip');
            self::fail('Expected AuditSinkException');
        } catch (AuditSinkException $e) {
            self::assertStringNotContainsString('super-secret-token', $e->getMessage());
            self::assertStringNotContainsString('siem.example.com', $e->getMessage());
        }
    }

    #[Test]
    public function publishingWithAnUnusableUrlThrowsRatherThanSendingNowhere(): void
    {
        $subject = $this->createSubject(url: '', client: new RecordingClient(new Response(200)));

        $this->expectException(AuditSinkException::class);

        $subject->publish($this->createEntry(), 'tip');
    }

    /**
     * Invalid UTF-8 arrives from request headers (user agent). Failing the whole
     * delivery on it would drop a legitimate audit record.
     */
    #[Test]
    public function invalidUtf8IsSubstitutedRatherThanFailingTheDelivery(): void
    {
        $client = new RecordingClient(new Response(200));

        $this->createSubject(client: $client)->publish(
            $this->createEntry(userAgent: "Mozilla\xC3\x28"),
            'tip',
        );

        self::assertIsString($client->decodeBody()['entry']['userAgent']);
    }

    private function createSubject(
        bool $enabled = true,
        string $url = self::ENDPOINT,
        ?ClientInterface $client = null,
    ): WebhookAuditSink {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('isAuditSinkWebhookEnabled')->willReturn($enabled);
        $configuration->method('getAuditSinkWebhookUrl')->willReturn($url);

        $factory = new HttpFactory();

        return new WebhookAuditSink(
            $configuration,
            $client ?? new RecordingClient(new Response(200)),
            $factory,
            $factory,
        );
    }

    private function createEntry(int $uid = 1, string $userAgent = 'Mozilla/5.0'): AuditLogEntry
    {
        return new AuditLogEntry(
            uid: $uid,
            secretIdentifier: 'api/stripe',
            action: 'read',
            success: true,
            errorMessage: null,
            reason: null,
            actorUid: 7,
            actorType: 'be_user',
            actorUsername: 'editor',
            actorRole: 'groups:1',
            ipAddress: '203.0.113.7',
            userAgent: $userAgent,
            requestId: 'req-1',
            previousHash: 'prev',
            entryHash: 'hash-' . $uid,
            hashBefore: '',
            hashAfter: '',
            crdate: 1_750_000_000,
            context: [],
        );
    }
}

/**
 * Records the last request and returns a canned response.
 *
 * A hand-written stub rather than a PHPUnit mock: the assertions here are about
 * the request that was BUILT (method, URI, headers, body), and capturing it in a
 * property reads better than an `->with()` callback that has to assert inside
 * itself.
 *
 * @internal test helper
 */
final class RecordingClient implements ClientInterface
{
    public ?RequestInterface $lastRequest = null;

    public function __construct(private readonly ResponseInterface $response) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->lastRequest = $request;

        return $this->response;
    }

    /**
     * @return array<string, mixed>
     */
    public function decodeBody(): array
    {
        $body = (string) $this->lastRequest?->getBody();
        $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

        /** @var array<string, mixed> $decoded */
        return \is_array($decoded) ? $decoded : [];
    }
}

/**
 * @internal test helper
 */
final readonly class ThrowingClient implements ClientInterface
{
    public function __construct(private Throwable $error) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        throw $this->error;
    }
}

/**
 * @internal test helper
 */
final class TestClientException extends RuntimeException implements ClientExceptionInterface {}
