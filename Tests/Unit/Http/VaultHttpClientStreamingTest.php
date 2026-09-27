<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use Closure;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface as GuzzleClientInterface;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\Utils as PromiseUtils;
use GuzzleHttp\Psr7\BufferStream;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use Netresearch\NrVault\Audit\AuditContextInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\RequestCancelledException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\CancellableTransport;
use Netresearch\NrVault\Http\CancellationSignalInterface;
use Netresearch\NrVault\Http\DnsResolverInterface;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\StreamingHttpClientInterface;
use Netresearch\NrVault\Http\StreamingResponseBody;
use Netresearch\NrVault\Http\StreamingTransfer;
use Netresearch\NrVault\Http\TransportTickerInterface;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
use ReflectionClass;
use ReflectionMethod;
use RuntimeException;

/**
 * The streaming send, driven without a socket.
 *
 * The transport under test is the REAL one the factory builds — hardened
 * option set and `ssrf-dns-pin` middleware included — with only its bottom
 * handler replaced by a stub that plays the curl handler's part: it calls
 * `on_headers`, writes into the `sink` it was handed and settles its promise,
 * each on the tick a test chooses. The ticker is a closure that tells the stub
 * what to do on the Nth tick. No sleeps, no wall clock except where a test
 * sets a zero budget on purpose.
 *
 * What only a socket can show — the first bytes readable before the server
 * finished, the pin deciding which address is reached, a redirect never
 * followed on the wire, a stall ended by libcurl, the handle removed from a
 * real multi handle — is in `Tests/Functional/Http/StreamingSendTest.php`.
 */
#[CoversClass(VaultHttpClient::class)]
#[CoversClass(StreamingTransfer::class)]
#[CoversClass(StreamingResponseBody::class)]
final class VaultHttpClientStreamingTest extends TestCase
{
    use GuzzleClientConfigTrait;

    private const API_URL = 'https://api.example.com/v1/stream';

    private const API_HOST = 'api.example.com';

    private const PUBLIC_IP = '93.184.216.34';

    private const CANCELLED_BEFORE_SEND_MESSAGE
        = 'Request cancelled before send: nothing egressed and no secret was retrieved';

    private const CANCELLED_IN_FLIGHT_MESSAGE
        = 'Request cancelled after send began: credential injected and transfer handed to the transport';

    private const BUDGET_EXHAUSTED_MESSAGE = 'Streaming transfer exceeded its wall-clock budget and was aborted';

    private const NO_RESPONSE_MESSAGE = 'Streaming transport settled with a value that is not an HTTP response';

    private const REJECTED_MESSAGE = 'Streaming transfer was rejected';

    private const UNEXPECTED_OUTCOME_MESSAGE
        = 'Streaming transfer aborted by an unexpected error after the credential was injected';

    private const BODY_CANCELLED_MESSAGE = 'Streaming response cancelled while the body was being read';

    private const BODY_FAILED_MESSAGE = 'Streaming transfer failed after the headers arrived; the body is incomplete';

    private const BODY_CLOSED_MESSAGE = 'Streaming response body is closed';

    private VaultServiceInterface&MockObject $vaultService;

    private AuditLogServiceInterface&Stub $auditLogService;

    private SecureHttpClientFactory $clientFactory;

    private mixed $originalGlobals;

    /** @var list<array{action: string, success: bool, error: ?string, status: mixed}> */
    private array $auditRows = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->auditLogService = self::createStub(AuditLogServiceInterface::class);
        $this->clientFactory = new SecureHttpClientFactory(new StreamOnePublicAddressResolver(self::PUBLIC_IP));

        $this->originalGlobals = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = ['HTTP' => []];

        $this->auditRows = [];
        $this->auditLogService->method('log')->willReturnCallback(
            function (
                string $identifier,
                string $action,
                bool $success,
                ?string $error = null,
                ?string $reason = null,
                ?string $hashBefore = null,
                ?string $hashAfter = null,
                ?AuditContextInterface $context = null,
            ): void {
                $this->auditRows[] = [
                    'action' => $action,
                    'success' => $success,
                    'error' => $error,
                    'status' => $context?->toArray()['status_code'] ?? null,
                ];
            },
        );
    }

    protected function tearDown(): void
    {
        if ($this->originalGlobals === null) {
            unset($GLOBALS['TYPO3_CONF_VARS']);
        } else {
            $GLOBALS['TYPO3_CONF_VARS'] = $this->originalGlobals;
        }

        parent::tearDown();
    }

    // =========================================================================
    // The head, then the body as it arrives
    // =========================================================================

    #[Test]
    public function itReturnsAtTheHeadAndReadsTheBodyAsItArrives(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->deliverHead(200, ['Content-Type' => 'text/event-stream']),
            2 => static fn (StreamStubTransfer $t) => $t->deliverBytes("data: one\n"),
            3 => static fn (StreamStubTransfer $t) => $t->deliverBytes("data: two\n"),
            4 => static fn (StreamStubTransfer $t) => $t->complete(),
        ]);

        $response = $this->clientWithTransport($this->transportWith($transfer, $ticker))
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendStreaming(new Request('GET', self::API_URL));

        self::assertSame(1, $ticker->ticks(), 'sendStreaming() must return on the tick that delivered the head.');
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('text/event-stream', $response->getHeaderLine('Content-Type'));
        self::assertSame(
            [['action' => 'http_call', 'success' => true, 'error' => null, 'status' => 200]],
            $this->auditRows,
            'The row is written when the head arrived, not when the body ends.',
        );

        $body = $response->getBody();
        self::assertInstanceOf(StreamingResponseBody::class, $body);
        self::assertFalse($body->eof(), 'Nothing is at an end while the transfer runs.');

        self::assertSame("data: one\n", $body->read(8192));
        self::assertSame(2, $ticker->ticks(), 'A read steps the transport only until bytes are there.');
        self::assertSame(10, $body->tell());

        self::assertSame('da', $body->read(2), 'A short read leaves the rest in the buffer.');
        self::assertSame("ta: two\n", $body->read(8192));
        self::assertSame(3, $ticker->ticks(), 'Buffered bytes are served without another step.');
        self::assertSame(20, $body->tell());

        self::assertSame('', $body->read(8192), 'A completed transfer ends with an empty read.');
        self::assertTrue($body->eof());
        self::assertSame('', $body->read(8192), 'And stays ended.');

        self::assertSame(0, $transfer->waitCalls(), 'wait() would block until every transfer on the handler ends.');
        self::assertSame(0, $transfer->cancelCalls(), 'A completed transfer is not cancelled.');
        self::assertCount(1, $this->auditRows, 'Reading the body writes no further row.');
    }

    #[Test]
    public function theTransportGetsSinkAndOnHeadersAndNeverTheStreamOption(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');
        // An operator who enables redirects platform-wide must not turn them on
        // for this path: a followed redirect leaves the pin behind.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allow_redirects'] = true;

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->deliverHead(200),
        ]);

        $this->clientWithTransport($this->transportWith($transfer, $ticker))
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendStreaming(new Request('GET', self::API_URL));

        $options = $transfer->options();
        self::assertIsArray($options);
        self::assertArrayNotHasKey('stream', $options, 'stream => true routes to the StreamHandler, which ignores the pin.');
        self::assertArrayNotHasKey('synchronous', $options);
        self::assertFalse($options['allow_redirects'] ?? null);
        self::assertFalse($options['http_errors'] ?? null);
        self::assertSame(
            30,
            $options['timeout'] ?? null,
            'The transfer keeps the client timeout; a stream without one could hold the worker indefinitely.',
        );
        self::assertInstanceOf(StreamInterface::class, $options['sink'] ?? null);
        self::assertIsCallable($options['on_headers'] ?? null);

        $curl = $options['curl'] ?? null;
        self::assertIsArray($curl);
        self::assertSame(
            [self::API_HOST . ':443:' . self::PUBLIC_IP],
            $curl[\CURLOPT_RESOLVE] ?? null,
            'The ssrf-dns-pin middleware must have pinned the vetted address on this path too.',
        );
    }

    #[Test]
    public function theCredentialIsInjectedOnTheRequestTheTransportSends(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->with('api_key')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->deliverHead(200),
        ]);

        $this->clientWithTransport($this->transportWith($transfer, $ticker))
            ->withAuthentication('api_key', SecretPlacement::Header, ['headerName' => 'X-Token', 'prefix' => 'Key '])
            ->sendStreaming(new Request('POST', self::API_URL));

        self::assertSame('Key s3cret', $transfer->request()?->getHeaderLine('X-Token'));
    }

    #[Test]
    public function anInterimHeadIsSkippedAndTheFinalOneReturned(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->deliverHead(100),
            2 => static fn (StreamStubTransfer $t) => $t->deliverHead(201),
        ]);

        $response = $this->clientWithTransport($this->transportWith($transfer, $ticker))
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendStreaming(new Request('POST', self::API_URL));

        self::assertSame(201, $response->getStatusCode());
        self::assertSame(2, $ticker->ticks());
        self::assertSame(201, $this->auditRows[0]['status'] ?? null);
    }

    #[Test]
    public function aResponseThatSettlesWithoutPassingOnHeadersIsReturnedAsItIs(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $settled = new Response(203, [], 'complete');
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->settleWithValue($settled),
        ]);

        $response = $this->clientWithTransport($this->transportWith($transfer, $ticker))
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendStreaming(new Request('GET', self::API_URL));

        self::assertSame(203, $response->getStatusCode());
        self::assertSame('complete', (string) $response->getBody());
        self::assertSame([['action' => 'http_call', 'success' => true, 'error' => null, 'status' => 203]], $this->auditRows);
    }

    // =========================================================================
    // Everything that can end the call before the head
    // =========================================================================

    #[Test]
    public function anAlreadyCancelledSignalReadsNoSecretAndSendsNothing(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');

        $transfer = new StreamStubTransfer();
        $client = $this->clientWithTransport($this->transportWith($transfer, new StreamStepTicker($transfer, [])))
            ->withAuthentication('api_key', SecretPlacement::Bearer);

        try {
            $client->sendStreaming(new Request('GET', self::API_URL), new StreamCountdownSignal(0));
            self::fail('Expected the pre-flight signal to refuse the call.');
        } catch (RequestCancelledException $e) {
            self::assertSame(1790475701, $e->getCode());
            self::assertSame(self::CANCELLED_BEFORE_SEND_MESSAGE, $e->getMessage());
        }

        self::assertFalse($transfer->wasReached());
        self::assertSame(
            [['action' => 'http_call_cancelled_before_send', 'success' => false, 'error' => self::CANCELLED_BEFORE_SEND_MESSAGE, 'status' => 0]],
            $this->auditRows,
        );
    }

    #[Test]
    public function theSchemeGuardRefusesBeforeAnySecretIsReadOrAnythingIsSent(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');

        $transfer = new StreamStubTransfer();
        $client = $this->clientWithTransport($this->transportWith($transfer, new StreamStepTicker($transfer, [])))
            ->withAuthentication('api_key', SecretPlacement::Bearer);

        try {
            $client->sendStreaming(new Request('GET', 'file:///etc/passwd'));
            self::fail('Expected the scheme guard to refuse a file:// URI.');
        } catch (VaultException $e) {
            self::assertSame(1735858523, $e->getCode());
        }

        self::assertFalse($transfer->wasReached());
        self::assertSame(
            [[
                'action' => 'http_call',
                'success' => false,
                'error' => 'Request refused before any secret was read: unsupported URI scheme "file"',
                'status' => 0,
            ]],
            $this->auditRows,
        );
    }

    #[Test]
    public function theHostAllowlistRefusesBeforeAnySecretIsReadOrAnythingIsSent(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = ['other.example.com'];

        $transfer = new StreamStubTransfer();
        $client = $this->clientWithTransport($this->transportWith($transfer, new StreamStepTicker($transfer, [])))
            ->withAuthentication('api_key', SecretPlacement::Bearer);

        try {
            $client->sendStreaming(new Request('GET', self::API_URL));
            self::fail('Expected the allowlist to refuse a host it does not list.');
        } catch (VaultException $e) {
            self::assertSame(1735858522, $e->getCode());
        }

        self::assertFalse($transfer->wasReached());
        self::assertSame(
            [[
                'action' => 'http_call',
                'success' => false,
                'error' => 'Request refused before any secret was read: host is not in the allowed hosts list',
                'status' => 0,
            ]],
            $this->auditRows,
        );
    }

    #[Test]
    public function aSignalBeforeTheHeadAbortsTheTransferAndAuditsItAsCancelled(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, []);

        // Pre-flight, then two steps, then cancelled.
        $signal = new StreamCountdownSignal(3);

        try {
            $this->clientWithTransport($this->transportWith($transfer, $ticker))
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendStreaming(new Request('GET', self::API_URL), $signal);
            self::fail('Expected the signal to abort the transfer.');
        } catch (RequestCancelledException $e) {
            self::assertSame(1790475702, $e->getCode());
            self::assertSame(self::CANCELLED_IN_FLIGHT_MESSAGE, $e->getMessage());
        }

        self::assertSame(2, $ticker->ticks());
        self::assertSame(1, $transfer->cancelCalls(), 'The transfer must be torn down.');
        self::assertSame(0, $transfer->waitCalls());
        self::assertSame(
            [['action' => 'http_call_cancelled', 'success' => false, 'error' => self::CANCELLED_IN_FLIGHT_MESSAGE, 'status' => 0]],
            $this->auditRows,
        );
    }

    #[Test]
    public function anExhaustedBudgetBeforeTheHeadAbortsTheTransferAndAuditsAFailure(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, []);

        try {
            $this->clientWithTransport($this->transportWith($transfer, $ticker, 0.0))
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendStreaming(new Request('GET', self::API_URL));
            self::fail('Expected the wall-clock bound to end the call.');
        } catch (VaultException $e) {
            self::assertNotInstanceOf(RequestCancelledException::class, $e);
            self::assertSame(1790475709, $e->getCode());
            self::assertSame(self::BUDGET_EXHAUSTED_MESSAGE, $e->getMessage());
        }

        self::assertSame(0, $ticker->ticks(), 'An exhausted bound is checked before the transport is stepped.');
        self::assertSame(1, $transfer->cancelCalls());
        self::assertSame(
            [['action' => 'http_call', 'success' => false, 'error' => self::BUDGET_EXHAUSTED_MESSAGE, 'status' => 0]],
            $this->auditRows,
        );
    }

    #[Test]
    public function aTransportRejectionBeforeTheHeadIsRethrownAndAudited(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $failure = new RequestException('cURL error 7: connection refused', new Request('GET', self::API_URL));
        $ticker = new StreamStepTicker($transfer, [
            2 => static fn (StreamStubTransfer $t) => $t->fail($failure),
        ]);

        try {
            $this->clientWithTransport($this->transportWith($transfer, $ticker))
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendStreaming(new Request('GET', self::API_URL));
            self::fail('Expected the transport failure.');
        } catch (RequestException $e) {
            self::assertSame($failure, $e, 'The transport reason reaches the caller unchanged, as on sendRequest().');
        }

        self::assertSame(
            [['action' => 'http_call', 'success' => false, 'error' => 'cURL error 7: connection refused', 'status' => 0]],
            $this->auditRows,
        );
    }

    #[Test]
    public function aHeadAndAFailureInTheSameStepAreReportedAsTheFailure(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $failure = new RequestException('cURL error 18: transfer closed', new Request('GET', self::API_URL));
        $ticker = new StreamStepTicker($transfer, [
            1 => static function (StreamStubTransfer $t) use ($failure): void {
                $t->deliverHead(200);
                $t->deliverBytes('partial');
                $t->fail($failure);
            },
        ]);

        try {
            $this->clientWithTransport($this->transportWith($transfer, $ticker))
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendStreaming(new Request('GET', self::API_URL));
            self::fail('A transfer already known to have failed must not be returned as a response.');
        } catch (RequestException $e) {
            self::assertSame($failure, $e);
        }

        self::assertFalse($this->auditRows[0]['success'] ?? true);
    }

    #[Test]
    public function aRejectionWithoutAThrowableIsRefusedWithAFixedLiteral(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->rejectWithValue('not a throwable'),
        ]);

        try {
            $this->clientWithTransport($this->transportWith($transfer, $ticker))
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendStreaming(new Request('GET', self::API_URL));
            self::fail('Expected the rejection to be refused.');
        } catch (VaultException $e) {
            self::assertSame(1790475710, $e->getCode());
            self::assertSame(self::REJECTED_MESSAGE, $e->getMessage());
        }

        self::assertSame(self::REJECTED_MESSAGE, $this->auditRows[0]['error'] ?? null);
    }

    #[Test]
    public function aSettlementThatIsNotAResponseIsRefused(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->settleWithValue('not a response'),
        ]);

        try {
            $this->clientWithTransport($this->transportWith($transfer, $ticker))
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendStreaming(new Request('GET', self::API_URL));
            self::fail('Expected the settlement to be refused.');
        } catch (VaultException $e) {
            self::assertSame(1790475711, $e->getCode());
            self::assertSame(self::NO_RESPONSE_MESSAGE, $e->getMessage());
        }

        self::assertSame(
            [['action' => 'http_call', 'success' => false, 'error' => self::NO_RESPONSE_MESSAGE, 'status' => 0]],
            $this->auditRows,
        );
    }

    #[Test]
    public function aThrowFromTheSendItselfStillLeavesARow(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transport = new CancellableTransport(
            new StreamThrowingOnSendClient(),
            new StreamStepTicker(new StreamStubTransfer(), []),
            5.0,
        );

        try {
            $this->clientWithTransport($transport)
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendStreaming(new Request('GET', self::API_URL));
            self::fail('Expected the send to throw.');
        } catch (InvalidArgumentException $e) {
            self::assertSame(1790475901, $e->getCode());
        }

        self::assertSame(
            [[
                'action' => 'http_call',
                'success' => false,
                'error' => self::UNEXPECTED_OUTCOME_MESSAGE . ': sendAsync refused the option set',
                'status' => 0,
            ]],
            $this->auditRows,
        );
    }

    #[Test]
    public function aSignalThatThrowsBeforeTheHeadStillLeavesARowAndTearsTheTransferDown(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();

        try {
            $this->clientWithTransport($this->transportWith($transfer, new StreamStepTicker($transfer, [])))
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendStreaming(new Request('GET', self::API_URL), new StreamThrowingSignal(2));
            self::fail('Expected the signal to throw.');
        } catch (RuntimeException $e) {
            self::assertSame(1790475902, $e->getCode());
        }

        self::assertSame(1, $transfer->cancelCalls());
        self::assertSame(
            [[
                'action' => 'http_call',
                'success' => false,
                'error' => self::UNEXPECTED_OUTCOME_MESSAGE . ": the caller's signal blew up",
                'status' => 0,
            ]],
            $this->auditRows,
        );
    }

    // =========================================================================
    // The body after the head
    // =========================================================================

    #[Test]
    public function aFailureAfterTheHeadThrowsFromReadOnceTheArrivedBytesAreOut(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $failure = new RequestException('cURL error 18: transfer closed', new Request('GET', self::API_URL));
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->deliverHead(200),
            2 => static function (StreamStubTransfer $t) use ($failure): void {
                $t->deliverBytes('partial');
                $t->fail($failure);
            },
        ]);

        $body = $this->clientWithTransport($this->transportWith($transfer, $ticker))
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendStreaming(new Request('GET', self::API_URL))
            ->getBody();

        self::assertSame('partial', $body->read(8192), 'The bytes that arrived are handed out first.');
        self::assertFalse($body->eof(), 'A failed transfer never reports end of stream.');

        try {
            $body->read(8192);
            self::fail('A failed transfer must throw, not end as a short body.');
        } catch (VaultException $e) {
            self::assertSame(1790475706, $e->getCode());
            self::assertSame(self::BODY_FAILED_MESSAGE, $e->getMessage());
            self::assertSame($failure, $e->getPrevious());
        }

        self::assertCount(1, $this->auditRows, 'The row was written at the head; the body writes none.');
    }

    #[Test]
    public function getContentsAndToStringThrowInsteadOfReturningAShortBody(): void
    {
        $this->vaultService->expects(self::exactly(2))->method('retrieve')->willReturn('s3cret');

        $readers = [
            'getContents' => static fn (StreamInterface $body): string => $body->getContents(),
            '__toString' => static fn (StreamInterface $body): string => (string) $body,
        ];

        foreach ($readers as $method => $readAll) {
            $transfer = new StreamStubTransfer();
            $ticker = new StreamStepTicker($transfer, [
                1 => static fn (StreamStubTransfer $t) => $t->deliverHead(200),
                2 => static fn (StreamStubTransfer $t) => $t->deliverBytes('half'),
                3 => static fn (StreamStubTransfer $t) => $t->rejectWithValue('gone'),
            ]);

            $body = $this->clientWithTransport($this->transportWith($transfer, $ticker))
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendStreaming(new Request('GET', self::API_URL))
                ->getBody();

            try {
                $readAll($body);
                self::fail($method . '() must not return what arrived before the failure.');
            } catch (VaultException $e) {
                self::assertSame(1790475706, $e->getCode(), $method);
                self::assertNull($e->getPrevious(), 'A rejection reason that is not a Throwable is not attached.');
            }
        }
    }

    #[Test]
    public function getContentsReturnsTheWholeBodyOfACompletedTransfer(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->deliverHead(200),
            2 => static fn (StreamStubTransfer $t) => $t->deliverBytes('one,'),
            3 => static fn (StreamStubTransfer $t) => $t->deliverBytes(str_repeat('x', 9000)),
            4 => static fn (StreamStubTransfer $t) => $t->complete(),
        ]);

        $body = $this->clientWithTransport($this->transportWith($transfer, $ticker))
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendStreaming(new Request('GET', self::API_URL))
            ->getBody();

        self::assertSame('one,' . str_repeat('x', 9000), $body->getContents());
        self::assertTrue($body->eof());
    }

    #[Test]
    public function aSignalWhileReadingAbortsTheTransferAndClosesTheBody(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->deliverHead(200),
        ]);
        // Pre-flight, the step that delivers the head, then cancelled.
        $signal = new StreamCountdownSignal(2);

        $body = $this->clientWithTransport($this->transportWith($transfer, $ticker))
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendStreaming(new Request('GET', self::API_URL), $signal)
            ->getBody();

        try {
            $body->read(8192);
            self::fail('Expected the signal to abort the read.');
        } catch (RequestCancelledException $e) {
            self::assertSame(1790475704, $e->getCode());
            self::assertSame(self::BODY_CANCELLED_MESSAGE, $e->getMessage());
        }

        self::assertSame(1, $transfer->cancelCalls());
        self::assertFalse($body->isReadable());
        self::assertTrue($body->eof());
        $this->assertReadRefusedAsClosed($body);
        self::assertSame([['action' => 'http_call', 'success' => true, 'error' => null, 'status' => 200]], $this->auditRows);
    }

    #[Test]
    public function closingTheBodyCancelsTheTransfer(): void
    {
        $body = $this->bodyAfterHead($transfer);

        self::assertTrue($body->isReadable());
        $body->close();

        self::assertSame(1, $transfer->cancelCalls());
        self::assertFalse($body->isReadable());
        self::assertTrue($body->eof());
        $this->assertReadRefusedAsClosed($body);

        $body->close();
        self::assertSame(1, $transfer->cancelCalls(), 'A second close() cancels nothing more.');
    }

    #[Test]
    public function detachingTheBodyCancelsTheTransferAndHandsOutNoResource(): void
    {
        $body = $this->bodyAfterHead($transfer);

        self::assertNull($body->detach());
        self::assertSame(1, $transfer->cancelCalls());
        $this->assertReadRefusedAsClosed($body);
    }

    #[Test]
    public function droppingTheResponseCancelsTheTransfer(): void
    {
        $response = $this->responseAfterHead($transfer);
        self::assertSame(0, $transfer->cancelCalls());

        unset($response);

        self::assertSame(1, $transfer->cancelCalls(), 'A body nobody holds must not keep its transfer on the transport.');
    }

    #[Test]
    public function theBodyIsNeitherSeekableNorWritableAndExposesNoMetadata(): void
    {
        $body = $this->bodyAfterHead($transfer);

        self::assertFalse($body->isSeekable());
        self::assertFalse($body->isWritable());
        self::assertNull($body->getSize());
        self::assertSame(0, $body->tell());
        self::assertSame([], $body->getMetadata());
        self::assertNull($body->getMetadata('uri'), 'The request URI can carry the secret; it is never exposed.');

        try {
            $body->seek(0);
            self::fail('Seeking must be refused.');
        } catch (VaultException $e) {
            self::assertSame(1790475707, $e->getCode());
        }

        try {
            $body->rewind();
            self::fail('Rewinding must be refused.');
        } catch (VaultException $e) {
            self::assertSame(1790475707, $e->getCode());
        }

        try {
            $body->write('x');
            self::fail('Writing must be refused.');
        } catch (VaultException $e) {
            self::assertSame(1790475708, $e->getCode());
        }

        self::assertSame(0, $transfer->cancelCalls(), 'None of these touches the transfer.');
    }

    #[Test]
    public function anExhaustedBudgetWhileReadingEndsTheRead(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');

        $transfer = new StreamStubTransfer();
        $promise = $transfer->handler()(new Request('GET', self::API_URL), []);
        $ticker = new StreamStepTicker($transfer, []);

        $body = new StreamingResponseBody(
            new StreamingTransfer($promise, $ticker, 0.0, null),
            new BufferStream(),
        );

        try {
            $body->read(8192);
            self::fail('Expected the wall-clock bound to end the read.');
        } catch (VaultException $e) {
            self::assertNotInstanceOf(RequestCancelledException::class, $e);
            self::assertSame(1790475705, $e->getCode());
            self::assertSame(self::BUDGET_EXHAUSTED_MESSAGE, $e->getMessage());
        }

        self::assertSame(0, $ticker->ticks());
        self::assertSame(1, $transfer->cancelCalls());
        $this->assertReadRefusedAsClosed($body);
    }

    #[Test]
    public function aTransferRejectedSynchronouslyIsSettledWithoutATick(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');

        $failure = new RequestException('refused before the socket', new Request('GET', self::API_URL));
        $ticker = new StreamStepTicker(new StreamStubTransfer(), []);

        $transfer = new StreamingTransfer(
            Create::rejectionFor($failure),
            $ticker,
            5.0,
            null,
        );

        self::assertTrue($transfer->isSettled());
        self::assertTrue($transfer->isRejected());
        self::assertSame($failure, $transfer->settledValue());
        self::assertSame(0, $ticker->ticks());
    }

    // =========================================================================
    // Capability and surface
    // =========================================================================

    #[Test]
    public function aFactoryBuiltClientReportsStreamingSupport(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            secureHttpClientFactory: $this->clientFactory,
        );

        self::assertTrue(
            (new ReflectionClass(VaultHttpClient::class))->implementsInterface(StreamingHttpClientInterface::class),
            'Consumers feature-detect on the interface.',
        );
        self::assertTrue($client->supportsStreaming());
    }

    #[Test]
    public function aCallerSuppliedClientDegradesToABlockingSendWithACompleteBody(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $inner = new StreamRecordingPsr18Client(new Response(200, [], 'whole body'));
        $client = (new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $inner,
            secureHttpClientFactory: $this->clientFactory,
        ))->withAuthentication('api_key', SecretPlacement::Bearer);

        self::assertFalse($client->supportsStreaming());

        $response = $client->sendStreaming(new Request('GET', self::API_URL), new StreamCountdownSignal(1_000));

        self::assertSame('whole body', (string) $response->getBody());
        self::assertSame('Bearer s3cret', $inner->lastRequest()?->getHeaderLine('Authorization'));
        self::assertSame([['action' => 'http_call', 'success' => true, 'error' => null, 'status' => 200]], $this->auditRows);
    }

    #[Test]
    public function sendStreamingTakesTheRequestAndTheSignalAndNothingElse(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');

        // No per-request option surface: a caller-supplied `stream` or `curl`
        // array could drop or overwrite the vetted CURLOPT_RESOLVE pin.
        $method = new ReflectionMethod(VaultHttpClient::class, 'sendStreaming');

        self::assertSame(2, $method->getNumberOfParameters());
        self::assertSame(ResponseInterface::class, (string) $method->getReturnType());
    }

    // =========================================================================
    // Harness
    // =========================================================================

    private function assertReadRefusedAsClosed(StreamInterface $body): void
    {
        try {
            $body->read(1);
            self::fail('A closed body must refuse to read.');
        } catch (VaultException $e) {
            self::assertSame(1790475703, $e->getCode());
            self::assertSame(self::BODY_CLOSED_MESSAGE, $e->getMessage());
        }
    }

    /**
     * @param-out StreamStubTransfer $transfer
     */
    private function responseAfterHead(?StreamStubTransfer &$transfer): ResponseInterface
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StreamStubTransfer();
        $ticker = new StreamStepTicker($transfer, [
            1 => static fn (StreamStubTransfer $t) => $t->deliverHead(200),
        ]);

        return $this->clientWithTransport($this->transportWith($transfer, $ticker))
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendStreaming(new Request('GET', self::API_URL));
    }

    /**
     * @param-out StreamStubTransfer $transfer
     */
    private function bodyAfterHead(?StreamStubTransfer &$transfer): StreamInterface
    {
        return $this->responseAfterHead($transfer)->getBody();
    }

    /**
     * The REAL cancellable transport with only its bottom handler and its
     * ticker replaced.
     */
    private function transportWith(
        StreamStubTransfer $transfer,
        TransportTickerInterface $ticker,
        ?float $budget = null,
    ): CancellableTransport {
        $real = $this->clientFactory->createCancellable();
        self::assertInstanceOf(CancellableTransport::class, $real);

        $client = $real->client();
        self::assertInstanceOf(Client::class, $client);

        $handler = $this->getGuzzleConfig($client)['handler'] ?? null;
        self::assertInstanceOf(HandlerStack::class, $handler);
        $handler->setHandler($transfer->handler());

        return new CancellableTransport($client, $ticker, $budget ?? $real->wallClockBudgetSeconds());
    }

    private function clientWithTransport(CancellableTransport $transport): VaultHttpClient
    {
        return new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            secureHttpClientFactory: $this->clientFactory,
            cancellableTransport: $transport,
        );
    }
}

/**
 * Answers every lookup with one public address.
 */
final readonly class StreamOnePublicAddressResolver implements DnsResolverInterface
{
    public function __construct(private string $address) {}

    public function resolve(string $host): array
    {
        return [['ip' => $this->address]];
    }
}

/**
 * The bottom handler, playing the curl handler's part.
 *
 * It keeps the `on_headers` callback and the `sink` it is handed, and a test
 * decides on which tick the head arrives, which bytes are written and how the
 * promise settles.
 */
final class StreamStubTransfer
{
    private ?RequestInterface $request = null;

    /** @var array<int|string, mixed>|null */
    private ?array $options = null;

    private ?Promise $promise = null;

    private int $cancelCalls = 0;

    private int $waitCalls = 0;

    /**
     * @return Closure(RequestInterface, array<int|string, mixed>): PromiseInterface
     */
    public function handler(): Closure
    {
        return function (RequestInterface $request, array $options): PromiseInterface {
            $this->request = $request;
            $this->options = $options;

            $promise = new Promise(
                function (): void {
                    ++$this->waitCalls;
                },
                function (): void {
                    ++$this->cancelCalls;
                },
            );
            $this->promise = $promise;

            return $promise;
        };
    }

    /**
     * @param array<string, string> $headers
     */
    public function deliverHead(int $status, array $headers = []): void
    {
        $onHeaders = $this->options['on_headers'] ?? null;
        $sink = $this->options['sink'] ?? null;
        \assert(\is_callable($onHeaders) && $sink instanceof StreamInterface);

        $onHeaders(new Response($status, $headers, $sink));
    }

    public function deliverBytes(string $bytes): void
    {
        $sink = $this->options['sink'] ?? null;
        \assert($sink instanceof StreamInterface);

        $written = $sink->write($bytes);
        \assert($written === \strlen($bytes), 'The sink must accept every byte, or curl aborts the transfer.');
    }

    public function complete(): void
    {
        $sink = $this->options['sink'] ?? null;
        \assert($sink instanceof StreamInterface);

        $this->settleWithValue(new Response(200, [], $sink));
    }

    public function settleWithValue(mixed $value): void
    {
        $this->promise?->resolve($value);
        PromiseUtils::queue()->run();
    }

    public function fail(RequestException $reason): void
    {
        $this->rejectWithValue($reason);
    }

    public function rejectWithValue(mixed $reason): void
    {
        $this->promise?->reject($reason);
        PromiseUtils::queue()->run();
    }

    public function cancelCalls(): int
    {
        return $this->cancelCalls;
    }

    public function waitCalls(): int
    {
        return $this->waitCalls;
    }

    public function wasReached(): bool
    {
        return $this->request instanceof RequestInterface;
    }

    public function request(): ?RequestInterface
    {
        return $this->request;
    }

    /**
     * @return array<int|string, mixed>|null
     */
    public function options(): ?array
    {
        return $this->options;
    }
}

/**
 * Runs the scripted action for each tick, by 1-based tick number.
 */
final class StreamStepTicker implements TransportTickerInterface
{
    private int $ticks = 0;

    /**
     * @param array<int, Closure(StreamStubTransfer): void> $script
     */
    public function __construct(
        private readonly StreamStubTransfer $transfer,
        private readonly array $script,
    ) {}

    public function tick(): void
    {
        ++$this->ticks;

        // A loop that lost its bound would otherwise spin until the runner's
        // timeout; fail it as a test instead.
        if ($this->ticks > 10_000) {
            throw new RuntimeException('The transport was ticked without end; nothing bounded the loop.', 1790475903);
        }

        $step = $this->script[$this->ticks] ?? null;
        if ($step !== null) {
            $step($this->transfer);
        }
    }

    public function ticks(): int
    {
        return $this->ticks;
    }
}

/**
 * False for the first `$falseAnswers` questions, true from then on.
 */
final class StreamCountdownSignal implements CancellationSignalInterface
{
    private int $asked = 0;

    public function __construct(private readonly int $falseAnswers) {}

    public function isCancelled(): bool
    {
        ++$this->asked;

        return $this->asked > $this->falseAnswers;
    }
}

/**
 * Breaks the "MUST NOT throw" contract on the question after `$falseAnswers`.
 */
final class StreamThrowingSignal implements CancellationSignalInterface
{
    private int $asked = 0;

    public function __construct(private readonly int $falseAnswers) {}

    public function isCancelled(): bool
    {
        ++$this->asked;

        if ($this->asked > $this->falseAnswers) {
            throw new RuntimeException("the caller's signal blew up", 1790475902);
        }

        return false;
    }
}

/**
 * A transport client whose `sendAsync()` throws, as a real Guzzle client does
 * for an option set `Client::applyOptions()` refuses.
 */
final class StreamThrowingOnSendClient implements GuzzleClientInterface
{
    /**
     * @param array<array-key, mixed> $options
     */
    public function send(RequestInterface $request, array $options = []): ResponseInterface
    {
        throw new InvalidArgumentException('sendAsync refused the option set', 1790475901);
    }

    /**
     * @param array<array-key, mixed> $options
     */
    public function sendAsync(RequestInterface $request, array $options = []): PromiseInterface
    {
        throw new InvalidArgumentException('sendAsync refused the option set', 1790475901);
    }

    /**
     * @param string|UriInterface $uri
     * @param array<array-key, mixed> $options
     */
    public function request(string $method, $uri, array $options = []): ResponseInterface
    {
        throw new InvalidArgumentException('sendAsync refused the option set', 1790475901);
    }

    /**
     * @param string|UriInterface $uri
     * @param array<array-key, mixed> $options
     */
    public function requestAsync(string $method, $uri, array $options = []): PromiseInterface
    {
        throw new InvalidArgumentException('sendAsync refused the option set', 1790475901);
    }

    public function getConfig(?string $option = null): mixed
    {
        return null;
    }
}

/**
 * A caller-supplied PSR-18 client that answers with a fixed response.
 */
final class StreamRecordingPsr18Client implements ClientInterface
{
    private ?RequestInterface $lastRequest = null;

    public function __construct(private readonly ResponseInterface $response) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->lastRequest = $request;

        return $this->response;
    }

    public function lastRequest(): ?RequestInterface
    {
        return $this->lastRequest;
    }
}
