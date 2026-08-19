<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use Closure;
use Error;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface as GuzzleClientInterface;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\FulfilledPromise;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\Utils as PromiseUtils;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use Netresearch\NrVault\Audit\AuditContextInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HttpCallContext;
use Netresearch\NrVault\Exception\RequestCancelledException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\CancellableHttpClientInterface;
use Netresearch\NrVault\Http\CancellableTransport;
use Netresearch\NrVault\Http\CancellationSignalInterface;
use Netresearch\NrVault\Http\DnsResolverInterface;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Http\OAuth\OAuthTokenManager;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\TransportTickerInterface;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Http\VaultHttpClientFactory;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
use ReflectionClass;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionProperty;
use RuntimeException;
use stdClass;

/**
 * The cancellable outbound send.
 *
 * Every test here is deterministic: no sockets, no sleeps, no wall-clock
 * dependence. The transport under test is the REAL one the factory builds —
 * full hardened option set, `ssrf-dns-pin` middleware installed — with only its
 * bottom handler replaced by a stub that returns a promise nobody settles, and
 * its ticker replaced by a closure that settles that promise on the Nth call.
 *
 * Requires ext-curl and deliberately does not skip without it: the factory
 * returns no transport when `curl_multi_exec` is missing, so these tests would
 * silently stop covering the feature on a platform where it degrades. CI has
 * the extension — `SecureHttpClientFactoryRebindingTest` has asserted on the
 * `\CURLOPT_RESOLVE` constant unguarded for as long as that file has existed —
 * and a run without it should be loud, not green.
 *
 * That second substitution is why `TransportTickerInterface` exists. The
 * suite's established seam (`HandlerStack::setHandler()`) destroys the
 * `CurlMultiHandler` a cancellation loop would have to tick, so a primitive
 * holding that handler privately could not be exercised by any unit test at
 * all — only asserted at by reading it.
 *
 * @see CancellableHttpClientInterface
 */
#[CoversClass(VaultHttpClient::class)]
#[CoversClass(CancellableTransport::class)]
final class VaultHttpClientCancellableTest extends TestCase
{
    use GuzzleClientConfigTrait;

    private const API_URL = 'https://api.example.com/v1/things';

    private const API_HOST = 'api.example.com';

    private const PUBLIC_IP = '93.184.216.34';

    /**
     * The literals the class under test raises and audits.
     *
     * Copied rather than read from the class: they are private constants there,
     * and a test that reads its expectation out of the subject cannot notice
     * the subject changing. Asserted twice on purpose — once on the audit row,
     * once on `getMessage()` of the exception handed back to the caller. Only
     * the row passes `AuditLogService::sanitizeErrorMessage()`, so an exception
     * message that started carrying the URI would be redacted nowhere, and for
     * `SecretPlacement::QueryParam` that URI carries the secret.
     */
    private const CANCELLED_BEFORE_SEND_MESSAGE
        = 'Request cancelled before send: nothing egressed and no secret was retrieved';

    private const CANCELLED_IN_FLIGHT_MESSAGE
        = 'Request cancelled after send began: credential injected and transfer handed to the transport';

    private const TICK_BUDGET_EXHAUSTED_MESSAGE
        = 'Cancellable transfer exceeded its wall-clock budget and was aborted';

    private const NON_RESPONSE_SETTLEMENT_MESSAGE
        = 'Cancellable transport settled with a value that is not an HTTP response';

    private const REJECTED_WITHOUT_THROWABLE_MESSAGE = 'Cancellable transfer was rejected';

    private const TRANSPORT_RESOLUTION_FAILED_MESSAGE
        = 'Cancellable transport could not be built; nothing was sent';

    private VaultServiceInterface&MockObject $vaultService;

    private AuditLogServiceInterface&MockObject $auditLogService;

    private ProgrammedDnsResolver $dnsResolver;

    private SecureHttpClientFactory $clientFactory;

    private mixed $originalGlobals;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $this->dnsResolver = new ProgrammedDnsResolver();
        $this->dnsResolver->program(self::API_HOST, [['ip' => self::PUBLIC_IP]]);

        $this->clientFactory = new SecureHttpClientFactory($this->dnsResolver);

        $this->originalGlobals = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = ['HTTP' => []];
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
    // 1 — the abort itself
    // =========================================================================

    #[Test]
    public function cancellingMidFlightAbortsTheTransferAndAuditsItAsCancelled(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StubbedTransfer();
        // Never settles: the only way out of the loop is the signal.
        $transport = $this->transportWith($transfer, new ClosureTicker(static function (): void {}));

        // The pre-flight check consumes the first answer, so three falses put
        // the abort on the third pass through the loop.
        $signal = new CountdownSignal(3);

        $auditedActions = [];
        $this->recordAuditActions($auditedActions);

        $client = $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer);

        try {
            $client->sendCancellable(new Request('GET', self::API_URL), $signal);
            self::fail('Expected the signal to abort the transfer.');
        } catch (RequestCancelledException $e) {
            self::assertSame(1786579202, $e->getCode());
            self::assertSame(self::CANCELLED_IN_FLIGHT_MESSAGE, $e->getMessage());
        }

        self::assertSame(1, $transfer->cancelCalls(), 'The promise cancel function must have run.');
        self::assertSame(
            0,
            $transfer->waitCalls(),
            'wait() would run CurlMultiHandler::execute() and leave no cancellation window at all.',
        );
        self::assertSame(
            [['http_call_cancelled', false]],
            $auditedActions,
            'A mid-flight cancellation writes exactly one row, under its own action.',
        );
    }

    // =========================================================================
    // 2 — the happy path is unaffected
    // =========================================================================

    #[Test]
    public function anUncancelledCallReturnsTheResponseAndAuditsAnOrdinaryHttpCall(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith(
            $transfer,
            new ClosureTicker(static function (int $tick) use ($transfer): void {
                if ($tick >= 2) {
                    $transfer->settleWith(new Response(200, [], 'ok'));
                }
            }),
        );

        $auditedActions = [];
        $this->recordAuditActions($auditedActions);

        $response = $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(0, $transfer->cancelCalls(), 'Nothing may be cancelled when the signal stays false.');
        self::assertSame([['http_call', true]], $auditedActions);
    }

    // =========================================================================
    // 3 + 4 — the two guards that are statements in the sending method, not
    //         middleware, and therefore had to be re-executed on this path
    // =========================================================================

    #[Test]
    public function schemeGuardRunsOnTheCancellablePathBeforeAnySecretIsRead(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith($transfer, new ClosureTicker(static function (): void {}));

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        $client = $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer);

        try {
            $client->sendCancellable(new Request('GET', 'file:///etc/passwd'), new NeverCancelledSignal());
            self::fail('Expected the scheme guard to refuse a file:// URI.');
        } catch (VaultException $e) {
            self::assertSame(1735858523, $e->getCode());
        }

        self::assertFalse($transfer->wasReached(), 'The transport must never see the request.');
        self::assertSame(
            [[
                'http_call',
                false,
                'Request refused before any secret was read: unsupported URI scheme "file"',
            ]],
            $auditedRows,
            'A refused scheme is a call that was asked for, so it leaves a row here too.',
        );
    }

    #[Test]
    public function hostAllowlistRunsOnTheCancellablePathBeforeAnySecretIsRead(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = ['allowed.example'];

        $this->vaultService->expects(self::never())->method('retrieve');

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith($transfer, new ClosureTicker(static function (): void {}));

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        $client = $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer);

        try {
            $client->sendCancellable(new Request('GET', 'https://blocked.example/x'), new NeverCancelledSignal());
            self::fail('Expected the allowlist to refuse the host.');
        } catch (VaultException $e) {
            self::assertSame(1735858522, $e->getCode());
        }

        self::assertFalse($transfer->wasReached(), 'The transport must never see the request.');
        self::assertSame(
            [[
                'http_call',
                false,
                'Request refused before any secret was read: host is not in the allowed hosts list',
            ]],
            $auditedRows,
        );
    }

    #[Test]
    public function aFailedCredentialInjectionOnTheCancellablePathLeavesARow(): void
    {
        // The third window in which a call could be asked for and leave no
        // trace: the vault read sits between the allowlist and the send, and
        // `sendCancellably()`'s `finally` only opens after it.
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn(null);

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith($transfer, new ClosureTicker(static function (): void {}));

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        $client = $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer);

        try {
            $client->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());
            self::fail('Expected the missing secret to refuse the send.');
        } catch (SecretNotFoundException $e) {
            self::assertSame(1735858521, $e->getCode());
        }

        self::assertFalse($transfer->wasReached(), 'Nothing may egress without a credential.');
        self::assertSame(
            [['http_call', false, 'Credential injection failed; nothing was sent: api_key']],
            $auditedRows,
        );
    }

    // =========================================================================
    // 5 — credential injection
    // =========================================================================

    #[Test]
    public function credentialInjectionRunsOnTheCancellablePath(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');
        $this->auditLogService->expects(self::once())->method('log');

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith(
            $transfer,
            new ClosureTicker(static function (int $tick) use ($transfer): void {
                if ($tick >= 1) {
                    $transfer->settleWith(new Response(200));
                }
            }),
        );

        $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());

        $sent = $transfer->request();
        self::assertInstanceOf(RequestInterface::class, $sent);
        self::assertSame('Bearer s3cret', $sent->getHeaderLine('Authorization'));
    }

    // =========================================================================
    // 6 — the DNS pin survives the new handler stack
    // =========================================================================

    #[Test]
    public function ssrfDnsPinIsInstalledOnTheCancellableTransport(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');
        $this->auditLogService->expects(self::once())->method('log');

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith(
            $transfer,
            new ClosureTicker(static function (int $tick) use ($transfer): void {
                if ($tick >= 1) {
                    $transfer->settleWith(new Response(200));
                }
            }),
        );

        $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());

        $options = $transfer->options();
        self::assertIsArray($options);
        self::assertArrayHasKey('curl', $options, 'The ssrf-dns-pin middleware did not run.');
        $curlOptions = $options['curl'];
        self::assertIsArray($curlOptions);
        self::assertArrayHasKey(\CURLOPT_RESOLVE, $curlOptions);
        self::assertSame(
            [self::API_HOST . ':443:' . self::PUBLIC_IP],
            $curlOptions[\CURLOPT_RESOLVE],
        );
    }

    // =========================================================================
    // 7 — the async/sync redirect divergence
    // =========================================================================

    #[Test]
    public function redirectsStayOffOnTheCancellablePathEvenWhenTypo3EnablesThem(): void
    {
        // An async send inherits the CLIENT default for allow_redirects, where a
        // PSR-18 send pins false per request. On an install that turned redirects
        // on, this path alone would follow them — past a DNS pin computed for the
        // original host. sendCancellable() re-pins false per request; this is the
        // regression guard for that pin.
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allow_redirects'] = true;
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');
        $this->auditLogService->expects(self::once())->method('log');

        $transfer = new StubbedTransfer();
        // Answers the FIRST transfer with the 302 and any further transfer with a
        // 200, so a followed redirect settles instead of hanging the loop: with
        // the pin removed this test fails on the status, immediately, rather than
        // by timing out.
        $transport = $this->transportWith(
            $transfer,
            new ClosureTicker(static function () use ($transfer): void {
                $transfer->settleWith(
                    $transfer->transferCount() === 1
                        ? new Response(302, ['Location' => 'https://api.example.com/moved'])
                        : new Response(200),
                );
            }),
        );

        $response = $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());

        self::assertSame(302, $response->getStatusCode(), 'The redirect must not be followed.');
        self::assertSame(1, $transfer->transferCount(), 'Exactly one request may reach the transport.');
    }

    // =========================================================================
    // 8 — pre-flight cancellation
    // =========================================================================

    #[Test]
    public function cancellingBeforeSendReadsNoSecretAndStillLeavesADistinguishableRow(): void
    {
        // Decision on this feature: a pre-flight cancellation DOES leave a trace,
        // so the log is complete with respect to CALLS and not merely to egress.
        // The distinction from a mid-flight abort — the one an auditor cares
        // about, because only the other one put a credential on the wire — is
        // carried by the ACTION, not by the message: an action can be filtered
        // and counted, a message is free text. The literal is pinned as well
        // because the audit module renders it next to the badge
        // (Audit/List.html:116-117).
        $this->vaultService->expects(self::never())->method('retrieve');

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith($transfer, new ClosureTicker(static function (): void {}));

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        $client = $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer);

        try {
            $client->sendCancellable(new Request('GET', self::API_URL), new AlreadyCancelledSignal());
            self::fail('Expected the pre-flight signal to refuse the send.');
        } catch (RequestCancelledException $e) {
            self::assertSame(1786579201, $e->getCode());
            self::assertSame(self::CANCELLED_BEFORE_SEND_MESSAGE, $e->getMessage());
        }

        self::assertFalse($transfer->wasReached(), 'Nothing may egress on a pre-flight cancellation.');
        self::assertSame(0, $transfer->cancelCalls(), 'There is no transfer to cancel yet.');
        self::assertSame(
            [['http_call_cancelled_before_send', false, self::CANCELLED_BEFORE_SEND_MESSAGE]],
            $auditedRows,
        );
    }

    /**
     * The audited status code for a call that never reached the wire.
     *
     * Zero is the only honest value here — there was no response — and it is
     * what an auditor filters on to separate "never sent" from a real HTTP
     * outcome. Any other number would read as a status the server returned.
     * The row's action and message are pinned above; nothing pinned the
     * context the row carries.
     */
    #[Test]
    public function aPreFlightCancellationIsAuditedWithoutAStatusCode(): void
    {
        $transfer = new StubbedTransfer();
        $transport = $this->transportWith($transfer, new ClosureTicker(static function (): void {}));

        $statusCodes = [];
        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->willReturnCallback(
                static function (
                    string $identifier,
                    string $action,
                    bool $success,
                    ?string $error = null,
                    ?string $reason = null,
                    ?string $hashBefore = null,
                    ?string $hashAfter = null,
                    ?AuditContextInterface $context = null,
                ) use (&$statusCodes): void {
                    self::assertInstanceOf(HttpCallContext::class, $context);
                    $statusCodes[] = $context->statusCode;
                },
            );

        $client = $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer);

        try {
            $client->sendCancellable(new Request('GET', self::API_URL), new AlreadyCancelledSignal());
            self::fail('Expected the pre-flight signal to refuse the send.');
        } catch (RequestCancelledException) {
            // The refusal itself is asserted by the test above.
        }

        self::assertSame([0], $statusCodes);
    }

    #[Test]
    public function theTwoCancellationOutcomesAreToldApartByTheirAction(): void
    {
        // The question the feature exists to answer — which calls were abandoned
        // AFTER their credential went out — is a query on one action value. That
        // only works while `http_call_cancelled` means the in-flight abort and
        // nothing else, so this pins the action of the outcome that must be the
        // ONLY one under it. The pre-flight row's action is pinned in the test
        // above; a copy-paste of one into the other fails one of the two.
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith($transfer, new ClosureTicker(static function (): void {}));

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        $client = $this->clientWithTransport($transport)
            ->withAuthentication('api_key', SecretPlacement::Bearer);

        try {
            $client->sendCancellable(new Request('GET', self::API_URL), new CountdownSignal(1));
            self::fail('Expected the signal to abort the transfer.');
        } catch (RequestCancelledException $e) {
            self::assertSame(1786579202, $e->getCode());
            self::assertSame(self::CANCELLED_IN_FLIGHT_MESSAGE, $e->getMessage());
        }

        self::assertSame(
            [['http_call_cancelled', false, self::CANCELLED_IN_FLIGHT_MESSAGE]],
            $auditedRows,
        );
    }

    // =========================================================================
    // 9 — withTimeout() must not carry a stale transport across
    // =========================================================================

    #[Test]
    public function withTimeoutDropsTheTransportAndRemembersTheOverride(): void
    {
        // The failure this guards: a client rebuilt with a new timeout while the
        // caller keeps ticking the event loop of the PREVIOUS client. That loop
        // serves nothing and spins to its wall-clock bound. Asserting identity
        // rather than behaviour, because building a transport for real would put
        // the timeout clone on a socket.
        $this->vaultService->expects(self::never())->method('retrieve');
        $this->auditLogService->expects(self::once())->method('log');

        $transfer = new StubbedTransfer();
        $ticker = new ClosureTicker(static function (int $tick) use ($transfer): void {
            if ($tick >= 1) {
                $transfer->settleWith(new Response(200));
            }
        });
        $transport = $this->transportWith($transfer, $ticker);

        $client = $this->clientWithTransport($transport);

        // The instance that OWNS the transport uses exactly that transport.
        $client->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());
        self::assertGreaterThan(0, $ticker->ticks(), 'The injected transport must be the one driven.');

        $timeoutClient = $client->withTimeout(5);

        $transportProperty = new ReflectionProperty(VaultHttpClient::class, 'cancellableTransport');
        $timeoutProperty = new ReflectionProperty(VaultHttpClient::class, 'timeoutSeconds');

        self::assertSame(
            $transport,
            $transportProperty->getValue($client),
            'The original instance keeps its transport.',
        );
        self::assertNull(
            $transportProperty->getValue($timeoutClient),
            'A transport built for the previous timeout must not survive withTimeout().',
        );
        self::assertSame(
            5,
            $timeoutProperty->getValue($timeoutClient),
            'The override must be remembered, or a transport built later would ignore it.',
        );
    }

    // =========================================================================
    // 10 — degradation
    // =========================================================================

    #[Test]
    public function aNonGuzzleInnerClientDegradesToABlockingSendWithAnOrdinaryAuditRow(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $innerClient = $this->createMock(ClientInterface::class);
        $innerClient->expects(self::once())
            ->method('sendRequest')
            ->willReturn(new Response(204));

        $auditedActions = [];
        $this->recordAuditActions($auditedActions);

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $innerClient,
            secureHttpClientFactory: $this->clientFactory,
        );

        self::assertFalse(
            $client->supportsCancellation(),
            'A client that cannot be ticked must say so instead of pretending.',
        );

        $response = $client
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());

        self::assertSame(204, $response->getStatusCode());
        self::assertSame([['http_call', true]], $auditedActions);
    }

    #[Test]
    public function aPreFlightSignalIsHonouredEvenWhenCancellationIsUnsupported(): void
    {
        // Degrading means the transfer cannot be interrupted once it runs. It
        // does NOT mean the signal is ignored: nothing has egressed before the
        // send, so refusing is always possible, and the refusal is the same
        // row and the same exception as on the supported path.
        $this->vaultService->expects(self::never())->method('retrieve');

        $innerClient = $this->createMock(ClientInterface::class);
        $innerClient->expects(self::never())->method('sendRequest');

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $innerClient,
            secureHttpClientFactory: $this->clientFactory,
        );

        self::assertFalse($client->supportsCancellation());

        try {
            $client
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendCancellable(new Request('GET', self::API_URL), new AlreadyCancelledSignal());
            self::fail('Expected the pre-flight signal to refuse the send.');
        } catch (RequestCancelledException $e) {
            self::assertSame(1786579201, $e->getCode());
            self::assertSame(self::CANCELLED_BEFORE_SEND_MESSAGE, $e->getMessage());
        }

        self::assertSame(
            [['http_call_cancelled_before_send', false, self::CANCELLED_BEFORE_SEND_MESSAGE]],
            $auditedRows,
        );
    }

    #[Test]
    public function aThrowFromTheDegradedBlockingSendStillLeavesAnAuditRow(): void
    {
        // The degraded branch must honour the same promise the cancellable one
        // does — "every call leaves exactly one row". `Client::applyOptions()`
        // raises InvalidArgumentException OUTSIDE `Client::transfer()`'s
        // try/catch, so a bad option set leaves the blocking send as a throw
        // that is not a PSR-18 ClientExceptionInterface; catching only that
        // interface would drop the row for a call whose credential was already
        // injected. `sendRequest()` runs the same helper, so this guards both.
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $innerClient = $this->createMock(ClientInterface::class);
        $innerClient->expects(self::once())
            ->method('sendRequest')
            ->willThrowException(new InvalidArgumentException('sendRequest refused the option set'));

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $innerClient,
            secureHttpClientFactory: $this->clientFactory,
        );

        try {
            $client
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());
            self::fail('Expected the blocking send to throw.');
        } catch (InvalidArgumentException $e) {
            self::assertSame('sendRequest refused the option set', $e->getMessage());
        }

        self::assertCount(1, $auditedRows, 'A post-injection throw must still leave exactly one row.');
        self::assertSame('http_call', $auditedRows[0][0]);
        self::assertFalse($auditedRows[0][1]);
        self::assertSame(
            'Blocking send aborted by an unexpected error after the credential was injected: '
            . 'sendRequest refused the option set',
            (string) $auditedRows[0][2],
            'The fixed literal identifies the situation; the original message says what threw.',
        );
    }

    #[Test]
    public function withTimeoutRebuildsACallerSuppliedClientAndTurnsCancellationOn(): void
    {
        // The limit of "a client you injected is never replaced": it holds on
        // the cancellable path, and `withTimeout()` is where it stops. PSR-18
        // carries no per-request options, so the override has to be baked into
        // a client — and the one that gets built comes from the factory, which
        // drops the caller's client and flips supportsCancellation() to true.
        // Documented on `withTimeout()` itself; pinned here so the two cannot
        // drift apart and so the docs can point at something.
        $this->vaultService->expects(self::never())->method('retrieve');
        $this->auditLogService->expects(self::never())->method('log');

        $callerClient = $this->createMock(ClientInterface::class);

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $callerClient,
            secureHttpClientFactory: $this->clientFactory,
        );

        self::assertFalse($client->supportsCancellation());

        $rebuilt = $client->withTimeout(5);

        $inner = (new ReflectionProperty(VaultHttpClient::class, 'innerClient'))->getValue($rebuilt);
        self::assertNotSame($callerClient, $inner, 'withTimeout() cannot keep a client it must reconfigure.');
        self::assertInstanceOf(Client::class, $inner);
        self::assertTrue(
            $rebuilt->supportsCancellation(),
            'The rebuilt client is factory-built, and says so.',
        );
    }

    #[Test]
    public function theCredentialBearingClientExportsNoTransportAndNoPromise(): void
    {
        // What keeps the four inline protections — scheme allowlist, host
        // allowlist, credential injection, audit write — from being bypassable:
        // no public method of the class that attaches the secret returns
        // anything a caller could send with. Every one returns a configured
        // clone, a PSR-7 response or a bool. A future method handing back the
        // inner client, the transport or the promise fails here.
        $publicMethods = (new ReflectionClass(VaultHttpClient::class))->getMethods(ReflectionMethod::IS_PUBLIC);

        foreach ($publicMethods as $method) {
            if ($method->isConstructor()) {
                continue;
            }

            $returnType = $method->getReturnType();
            self::assertInstanceOf(
                ReflectionNamedType::class,
                $returnType,
                \sprintf('%s() must declare a single, named return type.', $method->getName()),
            );
            self::assertContains(
                $returnType->getName(),
                ['static', ResponseInterface::class, 'bool'],
                \sprintf('%s() exports something a caller could send with.', $method->getName()),
            );
        }

        // The second half of the same rule: no per-request option surface, so
        // no caller-supplied `stream` or `curl` array can reach the transport
        // and drop the vetted CURLOPT_RESOLVE pin.
        self::assertSame(
            2,
            (new ReflectionMethod(VaultHttpClient::class, 'sendCancellable'))->getNumberOfParameters(),
            'sendCancellable() takes the request and the signal, and nothing else.',
        );
    }

    #[Test]
    public function aClientWhoseTransportItBuiltItselfReportsCancellationSupport(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');
        $this->auditLogService->expects(self::never())->method('log');

        // No inner client: the constructor builds one from the factory, so
        // swapping in a cancellable sibling replaces nothing a caller chose.
        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            secureHttpClientFactory: $this->clientFactory,
        );

        self::assertTrue($client->supportsCancellation());
    }

    #[Test]
    public function cancellationSurvivesTheWithersAndTheProductionFactory(): void
    {
        // The withers forward the inner client, so the "this one is mine" fact
        // has to travel with it or the primary use case —
        // `$vault->http()->withAuthentication(...)->sendCancellable(...)` —
        // would silently degrade to a blocking send.
        $this->vaultService->expects(self::never())->method('retrieve');
        $this->auditLogService->expects(self::never())->method('log');

        $client = (new VaultHttpClientFactory($this->auditLogService, $this->clientFactory))
            ->create($this->vaultService);

        self::assertInstanceOf(CancellableHttpClientInterface::class, $client);
        self::assertTrue($client->supportsCancellation(), 'A client from the DI factory must be cancellable.');

        $configured = $client
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->withReason('MCP tool call')
            ->withTimeout(15);

        // No second instanceof check: the withers return `static`, so the
        // narrowing above carries over.
        self::assertTrue($configured->supportsCancellation(), 'The withers must not drop cancellation.');
    }

    #[Test]
    public function anInjectedGuzzleClientIsNeverSwappedForACancellableTransport(): void
    {
        // The hazard: an injected Guzzle client can carry a caller's own
        // middleware, proxy or handler. Building a factory transport for the
        // cancellable path would drop all of it, on that path only — the worst
        // place for a difference to hide. So the client stays the one that
        // sends and supportsCancellation() says false, which is exactly what its
        // own comment promises. Here the injected client answers 204 from a
        // stubbed bottom handler; a substituted transport would try to reach
        // api.example.com instead and never see it.
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $innerClient = $this->clientFactory->create();
        self::assertInstanceOf(Client::class, $innerClient);
        $handler = $this->getGuzzleConfig($innerClient)['handler'] ?? null;
        self::assertInstanceOf(HandlerStack::class, $handler);
        $handler->setHandler(static fn (): PromiseInterface => new FulfilledPromise(new Response(204)));

        $auditedActions = [];
        $this->recordAuditActions($auditedActions);

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $innerClient,
            secureHttpClientFactory: $this->clientFactory,
        );

        self::assertFalse(
            $client->supportsCancellation(),
            'A caller-supplied client cannot be ticked, and must not be replaced by one that can.',
        );

        $response = $client
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());

        self::assertSame(204, $response->getStatusCode(), 'The injected client must be the one that answered.');
        self::assertSame([['http_call', true]], $auditedActions);
    }

    #[Test]
    public function aThrowFromTheSendItselfStillLeavesAnAuditRow(): void
    {
        // The window this closes: injectAuthentication() has already run when
        // sendCancellably() is entered, and `Client::applyOptions()` raises
        // InvalidArgumentException OUTSIDE `Client::transfer()`'s own try/catch
        // — so a bad option set leaves sendAsync() as a THROW, not as a rejected
        // promise. With the try opening after the send, that throw would be a
        // post-injection call with no audit row: precisely the hole the
        // pre-flight decision exists to close.
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $ticker = new ClosureTicker(static function (): void {});
        $transport = new CancellableTransport(new ThrowingOnSendClient(), $ticker, 5.0);

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            secureHttpClientFactory: $this->clientFactory,
            cancellableTransport: $transport,
        );

        try {
            $client
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());
            self::fail('Expected the send to throw.');
        } catch (InvalidArgumentException $e) {
            self::assertSame('sendAsync refused the option set', $e->getMessage());
        }

        self::assertSame(0, $ticker->ticks(), 'Nothing was started, so nothing may be ticked.');
        self::assertCount(1, $auditedRows, 'A post-injection throw must still leave exactly one row.');
        self::assertSame('http_call', $auditedRows[0][0]);
        self::assertFalse($auditedRows[0][1]);
        self::assertStringStartsWith(
            'Cancellable transfer aborted by an unexpected error after the credential was injected',
            (string) $auditedRows[0][2],
        );
    }

    #[Test]
    public function theTransportTheClientResolvesForItselfCarriesTheRememberedTimeout(): void
    {
        // Cancellation is an early exit, so the cancellable transport must never
        // be allowed to run LONGER than the blocking send. Both halves are
        // asserted against ONE client: the inner client it built, and the
        // transport IT resolves — not a second transport the test built from a
        // hard-coded number, which would still read 5 if
        // resolveCancellableTransport() stopped forwarding `$this->timeoutSeconds`
        // altogether. A factory spy recording the argument would say the same
        // thing more directly; SecureHttpClientFactory is final, so the seam is
        // the resolve method.
        $this->vaultService->expects(self::never())->method('retrieve');
        $this->auditLogService->expects(self::never())->method('log');

        $resolve = new ReflectionMethod(VaultHttpClient::class, 'resolveCancellableTransport');

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            secureHttpClientFactory: $this->clientFactory,
            timeoutSeconds: 5,
        );

        $innerClient = (new ReflectionProperty(VaultHttpClient::class, 'innerClient'))->getValue($client);
        self::assertInstanceOf(Client::class, $innerClient);
        self::assertSame(5, $this->getGuzzleConfig($innerClient)['timeout']);

        $transport = $resolve->invoke($client);
        self::assertInstanceOf(CancellableTransport::class, $transport);
        $transportClient = $transport->client();
        self::assertInstanceOf(Client::class, $transportClient);
        self::assertSame(
            5,
            $this->getGuzzleConfig($transportClient)['timeout'],
            'Both send paths must carry the same deadline.',
        );

        // The control that makes the assertion above load-bearing: an instance
        // with no override resolves a transport at the platform default, so 5
        // cannot have arrived by coincidence.
        $platformDefaultClient = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            secureHttpClientFactory: $this->clientFactory,
        );

        $platformDefaultTransport = $resolve->invoke($platformDefaultClient);
        self::assertInstanceOf(CancellableTransport::class, $platformDefaultTransport);
        $platformDefaultTransportClient = $platformDefaultTransport->client();
        self::assertInstanceOf(Client::class, $platformDefaultTransportClient);
        self::assertSame(
            30,
            $this->getGuzzleConfig($platformDefaultTransportClient)['timeout'],
            'Without an override the resolved transport must carry the platform default.',
        );
    }

    #[Test]
    public function anInjectedTransportNeverDisplacesACallerSuppliedClient(): void
    {
        // The `cancellableTransport` constructor parameter is an @internal test
        // seam, and it must not be a way around the rule the parameter above it
        // enforces. An instance whose inner client came from the caller stays
        // blocking on that client even when a transport is handed in: the
        // factory-built check runs BEFORE the injected transport is read.
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $callerClient = $this->createMock(ClientInterface::class);
        $callerClient->expects(self::once())
            ->method('sendRequest')
            ->willReturn(new Response(204));

        $transfer = new StubbedTransfer();
        $ticker = new ClosureTicker(static function (): void {});
        $transport = $this->transportWith($transfer, $ticker);

        $auditedActions = [];
        $this->recordAuditActions($auditedActions);

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $callerClient,
            secureHttpClientFactory: $this->clientFactory,
            cancellableTransport: $transport,
        );

        self::assertFalse(
            $client->supportsCancellation(),
            'An injected transport must not make a caller-supplied client claim cancellation.',
        );

        $response = $client
            ->withAuthentication('api_key', SecretPlacement::Bearer)
            ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());

        self::assertSame(204, $response->getStatusCode(), 'The caller-supplied client must be the one that answered.');
        self::assertSame(0, $ticker->ticks(), 'The injected transport must not have been driven.');
        self::assertFalse($transfer->wasReached(), 'Nothing may reach the injected transport.');
        self::assertSame([['http_call', true]], $auditedActions);
    }

    #[Test]
    public function aCallerCannotAssertTheFactoryBuiltFactByCloningFromAnotherInstance(): void
    {
        // `$clonedFrom` is what carries the factory-built fact across the
        // withers. It inherits that fact ONLY when the forwarded client is the
        // very object the prototype holds — otherwise a caller could pair their
        // own client with a legitimate instance and get a cancellable transport
        // built behind their back.
        $this->vaultService->expects(self::never())->method('retrieve');
        $this->auditLogService->expects(self::never())->method('log');

        $legitimate = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            secureHttpClientFactory: $this->clientFactory,
        );
        self::assertTrue($legitimate->supportsCancellation());

        $forged = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $this->clientFactory->create(),
            secureHttpClientFactory: $this->clientFactory,
            clonedFrom: $legitimate,
        );

        self::assertFalse(
            $forged->supportsCancellation(),
            'A prototype must not launder a client it does not hold.',
        );
    }

    #[Test]
    public function theFactoryBuildsACancellableTransportWithABudgetAboveTheTransferDeadlines(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');
        $this->auditLogService->expects(self::never())->method('log');

        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['timeout'] = 20;
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['connect_timeout'] = 4;

        $transport = $this->clientFactory->createCancellable();

        self::assertInstanceOf(CancellableTransport::class, $transport);
        self::assertGreaterThan(
            24.0,
            $transport->wallClockBudgetSeconds(),
            'The defensive bound must sit strictly above timeout + connect_timeout.',
        );
    }

    #[Test]
    public function theBlockingAndCancellableTransportsCarryTheSameOptions(): void
    {
        // `create()`'s option block moved into a shared private `buildOptions()`
        // so the two transports cannot drift apart. Nothing enforced that but
        // the fact that one method calls the other — this does: every request
        // option must match, the handler excepted, which is the one thing that
        // differs on purpose.
        $this->vaultService->expects(self::never())->method('retrieve');
        $this->auditLogService->expects(self::never())->method('log');

        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['connect_timeout'] = 7;

        $blocking = $this->clientFactory->create(11);
        self::assertInstanceOf(Client::class, $blocking);

        $cancellable = $this->clientFactory->createCancellable(11);
        self::assertInstanceOf(CancellableTransport::class, $cancellable);
        $cancellableClient = $cancellable->client();
        self::assertInstanceOf(Client::class, $cancellableClient);

        $blockingConfig = $this->getGuzzleConfig($blocking);
        $cancellableConfig = $this->getGuzzleConfig($cancellableClient);
        unset($blockingConfig['handler'], $cancellableConfig['handler']);

        self::assertSame($blockingConfig, $cancellableConfig);
        self::assertSame(11, $blockingConfig['timeout'], 'The override must be in the compared set.');
        self::assertSame(7, $blockingConfig['connect_timeout']);
    }

    // =========================================================================
    // 13 — the promise that is already rejected before the loop starts
    // =========================================================================

    #[Test]
    public function anSsrfRejectionSettlesBeforeTheFirstTickAndStillWritesItsRow(): void
    {
        // The host gives the allowlist gate no usable answer and the middleware
        // a loopback one a moment later. (Until the DNS memo of #304 this
        // scenario answered the gate with a PUBLIC address — but a non-empty
        // gate answer is now memoised and reused by the middleware, whose
        // re-check then pins the vetted address instead of rejecting; that
        // behaviour has its own test in SecureHttpClientFactoryDnsMemoTest.
        // A FAILED resolution is never memoised, so the middleware still
        // resolves fresh here and still rejects.) The middleware throws inside
        // Client::transfer(), so sendAsync() returns an ALREADY-REJECTED promise
        // whose handler is merely QUEUED. Two things must hold and neither is
        // free: the loop must drain that queue before it ticks (there is no
        // transfer on the handler to advance), and the rejection must still
        // produce an audit row, because this is a call that was refused after
        // the credential had been injected.
        $this->dnsResolver->programSequence(self::API_HOST, [
            [],
            [['ip' => '127.0.0.1']],
        ]);

        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StubbedTransfer();
        $ticker = new ClosureTicker(static function (): void {});
        $transport = $this->transportWith($transfer, $ticker);

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        try {
            $this->clientWithTransport($transport)
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());
            self::fail('Expected the ssrf-dns-pin middleware to refuse the rebound host.');
        } catch (RequestException $e) {
            self::assertStringContainsString('disallowed IP range', $e->getMessage());
        }

        self::assertSame(0, $ticker->ticks(), 'A settled-before-the-loop promise must not tick a dead handler.');
        self::assertFalse($transfer->wasReached(), 'The middleware rejected below no bottom handler.');
        self::assertCount(1, $auditedRows, 'A refused call still gets exactly one row.');
        self::assertSame('http_call', $auditedRows[0][0]);
        self::assertFalse($auditedRows[0][1]);
        self::assertStringContainsString('disallowed IP range', (string) $auditedRows[0][2]);
    }

    // =========================================================================
    // 14 — the transport settles with something that is not a response
    // =========================================================================

    #[Test]
    public function aNonResponseSettlementIsRefusedInsteadOfReturned(): void
    {
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith(
            $transfer,
            new ClosureTicker(static function (int $tick) use ($transfer): void {
                if ($tick >= 1) {
                    $transfer->settleWithValue('not a response at all');
                }
            }),
        );

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        try {
            $this->clientWithTransport($transport)
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());
            self::fail('Expected a non-response settlement to be refused.');
        } catch (VaultException $e) {
            self::assertSame(1786579205, $e->getCode());
            self::assertSame(self::NON_RESPONSE_SETTLEMENT_MESSAGE, $e->getMessage());
        }

        self::assertSame(
            [['http_call', false, self::NON_RESPONSE_SETTLEMENT_MESSAGE]],
            $auditedRows,
        );
    }

    // =========================================================================
    // 15 — the defensive wall-clock bound
    // =========================================================================

    #[Test]
    public function anExhaustedWallClockBudgetAbortsTheTransferAndAuditsIt(): void
    {
        // A budget of zero makes the bound trip on the first pass: the loop
        // compares two microtime() readings, so this is a deterministic
        // comparison and not a timing-dependent test. What it pins is that the
        // bound aborts (rather than hanging a TYPO3 request) and that it is
        // audited as a FAILURE — `http_call` / success = false — not as a
        // cancellation. Nobody asked for it: the bound only trips when the
        // handler stopped settling its promise. Filing it under
        // `http_call_cancelled` would put a second meaning on the action and
        // make "which calls did a caller abandon?" over-count.
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StubbedTransfer();
        $ticker = new ClosureTicker(static function (): void {});
        $client = $this->transportWith($transfer, $ticker)->client();
        $transport = new CancellableTransport($client, $ticker, 0.0);

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        try {
            $this->clientWithTransport($transport)
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());
            self::fail('Expected the wall-clock bound to abort the transfer.');
        } catch (VaultException $e) {
            self::assertSame(1786579203, $e->getCode());
            self::assertSame(self::TICK_BUDGET_EXHAUSTED_MESSAGE, $e->getMessage());
        }

        self::assertSame(1, $transfer->cancelCalls(), 'The bound must tear the transfer down, not just give up on it.');
        self::assertSame(0, $ticker->ticks(), 'An exhausted budget must not tick first.');
        self::assertSame(
            [['http_call', false, self::TICK_BUDGET_EXHAUSTED_MESSAGE]],
            $auditedRows,
        );
    }

    #[Test]
    public function aRejectionWithoutAThrowableIsRefusedWithAFixedLiteral(): void
    {
        // The fifth and last exception code the cancellable path raises. A
        // rejection reason that is not a Throwable cannot be rethrown, so the
        // class raises its own — and it does NOT carry the reason, in the
        // exception or in the row: a transport error string on this client can
        // quote the URL it failed on, which for `SecretPlacement::QueryParam`
        // is the secret. The reason programmed below is exactly that shape.
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith(
            $transfer,
            new ClosureTicker(static function (int $tick) use ($transfer): void {
                if ($tick >= 1) {
                    $transfer->rejectWithValue('https://api.example.com/v1/things?api_key=s3cret refused');
                }
            }),
        );

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        try {
            $this->clientWithTransport($transport)
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                ->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());
            self::fail('Expected a non-throwable rejection to be refused.');
        } catch (VaultException $e) {
            self::assertSame(1786579204, $e->getCode());
            self::assertSame(self::REJECTED_WITHOUT_THROWABLE_MESSAGE, $e->getMessage());
        }

        self::assertSame(
            [['http_call', false, self::REJECTED_WITHOUT_THROWABLE_MESSAGE]],
            $auditedRows,
        );
    }

    // =========================================================================
    // 16 — the row survives a throw from code this class does not own
    // =========================================================================

    #[Test]
    public function aSignalThatThrowsMidFlightStillLeavesAnAuditRow(): void
    {
        // `CancellationSignalInterface` says MUST NOT throw, but a docblock is
        // not an enforcement and the signal is written by the caller. It is
        // polled AFTER the credential has been injected and handed to the
        // transport, so a throw here would otherwise be the one outbound call
        // that leaves no trace — exactly the hole this feature exists to close.
        //
        // The row is a FAILURE (`http_call` / success = false), not a
        // cancellation: the signal never said "cancel", it broke. Only a signal
        // that actually reports true reaches `http_call_cancelled`.
        $this->vaultService->expects(self::once())->method('retrieve')->willReturn('s3cret');

        $transfer = new StubbedTransfer();
        $transport = $this->transportWith($transfer, new ClosureTicker(static function (): void {}));

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        try {
            $this->clientWithTransport($transport)
                ->withAuthentication('api_key', SecretPlacement::Bearer)
                // False once for the pre-flight check, then throws inside the loop.
                ->sendCancellable(new Request('GET', self::API_URL), new ThrowingSignal(1));
            self::fail('Expected the signal to throw.');
        } catch (RuntimeException $e) {
            self::assertSame("the caller's signal blew up", $e->getMessage());
        }

        self::assertSame(1, $transfer->cancelCalls(), 'A transfer nobody is waiting for must be torn down.');
        self::assertCount(1, $auditedRows);
        self::assertSame('http_call', $auditedRows[0][0]);
        self::assertFalse($auditedRows[0][1]);
        self::assertStringStartsWith(
            'Cancellable transfer aborted by an unexpected error after the credential was injected',
            (string) $auditedRows[0][2],
        );
    }

    // =========================================================================
    // 17 — the transport build is inside the audited region too
    // =========================================================================

    #[Test]
    public function aThrowFromTheTransportResolutionLeavesAnAuditRow(): void
    {
        // `resolveCancellableTransport()` runs after the guards and before the
        // credential injection, i.e. between two audited regions and inside
        // neither. A throw out of `SecureHttpClientFactory::createCancellable()`
        // therefore used to leave no row at all, and "every sendCancellable()
        // leaves exactly one row" had an outcome nobody had enumerated.
        //
        // Nothing egressed and no secret was read on this path, so the row is
        // `http_call` / success = false — the same tuple as a refused host.
        $this->vaultService->expects(self::never())->method('retrieve');

        // No injected transport: the send has to BUILD one, which is the call
        // under test. The inner client is factory-built, so the build happens.
        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            secureHttpClientFactory: $this->clientFactory,
        );
        $client = $client->withAuthentication('api_key', SecretPlacement::Bearer);
        self::assertTrue($client->supportsCancellation());

        $auditedRows = [];
        $this->recordAuditRows($auditedRows);

        // The factory reads the platform configuration every time it builds, and
        // `buildOptions()` subscripts it without a type check. Broken AFTER the
        // constructor, which builds the blocking client through the same
        // method; `isHostAllowed()` type-checks and is unaffected, so the two
        // guards still pass and the throw lands exactly where this test needs
        // it. This is the only in-process way to make that build fail — which
        // is also why the branch had no test until it had this one.
        $GLOBALS['TYPO3_CONF_VARS'] = new stdClass();

        $thrown = '';

        try {
            $client->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());
            self::fail('Expected the transport build to throw.');
        } catch (Error $e) {
            // Rethrown unchanged, like every other throw this class does not raise.
            $thrown = $e->getMessage();
            self::assertStringContainsString('as array', $thrown);
        }

        // The whole row, not just its prefix: the literal, the separator and the
        // original message in that order.
        self::assertSame(
            [['http_call', false, self::TRANSPORT_RESOLUTION_FAILED_MESSAGE . ': ' . $thrown]],
            $auditedRows,
            'A call whose transport could not be built still gets exactly one row.',
        );
    }

    // =========================================================================
    // 16 — the OAuth token leg rides the same signal (issue #303)
    // =========================================================================

    #[Test]
    public function theSignalRoutesTheOAuthTokenLegThroughACancellableTransport(): void
    {
        // Credentials for the token leg: the manager reads client id + secret.
        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(static fn (string $id): ?string => match ($id) {
                'oauth/cid' => 'client-id-value',
                'oauth/csec' => 'client-secret-value',
                default => null,
            });

        // The manager's own cancellable transport: the token POST settles with
        // a token on the first tick of ITS ticker.
        $tokenTransfer = new StubbedTransfer();
        $tokenTicker = new ClosureTicker(static function (int $tick) use ($tokenTransfer): void {
            if ($tick >= 1) {
                $tokenTransfer->settleWith(new Response(200, ['Content-Type' => 'application/json'], (string) json_encode([
                    'access_token' => 'token-from-cancellable-leg',
                    'token_type' => 'Bearer',
                    'expires_in' => 3600,
                ])));
            }
        });
        $tokenTransport = new CancellableTransport(
            new Client(['handler' => HandlerStack::create($tokenTransfer->handler())]),
            $tokenTicker,
            45.0,
        );

        // The manager's BLOCKING client must not serve a signalled call: that
        // it stays untouched is the proof the signal reached the token leg.
        $tokenBlockingClient = $this->createMock(ClientInterface::class);
        $tokenBlockingClient->expects(self::never())->method('sendRequest');

        $manager = new OAuthTokenManager(
            $this->vaultService,
            $tokenBlockingClient,
            $this->clientFactory,
            auditLogService: $this->auditLogService,
            cancellableTransport: $tokenTransport,
        );

        // The API transfer settles on the first tick of its own ticker.
        $apiTransfer = new StubbedTransfer();
        $apiTicker = new ClosureTicker(static function (int $tick) use ($apiTransfer): void {
            if ($tick >= 1) {
                $apiTransfer->settleWith(new Response(200, [], 'api-payload'));
            }
        });
        $apiTransport = $this->transportWith($apiTransfer, $apiTicker);

        $rows = [];
        $this->auditLogService
            ->method('log')
            ->willReturnCallback(
                static function (
                    string $identifier,
                    string $action,
                    bool $success,
                ) use (&$rows): void {
                    $rows[] = [$action, $success];
                },
            );

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            oauthConfig: OAuthConfig::clientCredentials(
                tokenEndpoint: 'https://auth.example.com/token',
                clientIdSecret: 'oauth/cid',
                clientSecretSecret: 'oauth/csec',
            ),
            oauthManager: $manager,
            secureHttpClientFactory: $this->clientFactory,
            cancellableTransport: $apiTransport,
        );

        $response = $client->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($tokenTransfer->wasReached(), 'The token POST must ride the cancellable transport when a signal is in play.');
        self::assertTrue($apiTransfer->wasReached());
        self::assertSame(
            [['oauth_token_request', true], ['http_call', true]],
            $rows,
            'The token leg and the call each leave their own row, in send order.',
        );
    }

    #[Test]
    public function theOAuthTokenLegStaysBlockingWhenTheCallItselfIsDegraded(): void
    {
        // A caller-supplied inner client degrades the whole call to blocking —
        // and the token leg with it: the signal is deliberately NOT passed to
        // the manager, so the two legs cannot disagree on abortability.
        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(static fn (string $id): ?string => match ($id) {
                'oauth/cid' => 'client-id-value',
                'oauth/csec' => 'client-secret-value',
                default => null,
            });

        $tokenTransfer = new StubbedTransfer();
        $tokenTransport = new CancellableTransport(
            new Client(['handler' => HandlerStack::create($tokenTransfer->handler())]),
            new ClosureTicker(static function (): void {}),
            45.0,
        );

        $tokenBlockingClient = $this->createMock(ClientInterface::class);
        $tokenBlockingClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn(new Response(200, ['Content-Type' => 'application/json'], (string) json_encode([
                'access_token' => 'token-from-blocking-leg',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
            ])));

        $manager = new OAuthTokenManager(
            $this->vaultService,
            $tokenBlockingClient,
            $this->clientFactory,
            auditLogService: $this->auditLogService,
            cancellableTransport: $tokenTransport,
        );

        $callerSuppliedClient = $this->createMock(ClientInterface::class);
        $callerSuppliedClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn(new Response(200, [], 'api-payload'));

        $client = new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            innerClient: $callerSuppliedClient,
            oauthConfig: OAuthConfig::clientCredentials(
                tokenEndpoint: 'https://auth.example.com/token',
                clientIdSecret: 'oauth/cid',
                clientSecretSecret: 'oauth/csec',
            ),
            oauthManager: $manager,
            secureHttpClientFactory: $this->clientFactory,
        );

        $response = $client->sendCancellable(new Request('GET', self::API_URL), new NeverCancelledSignal());

        self::assertSame(200, $response->getStatusCode());
        self::assertFalse(
            $tokenTransfer->wasReached(),
            'A degraded call must not route its token leg through a cancellable transport the API leg does not have.',
        );
    }

    // =========================================================================
    // Harness
    // =========================================================================

    /**
     * Build the REAL cancellable transport, then replace only its bottom handler
     * and its ticker.
     *
     * Everything above the bottom handler — the hardened option set and the
     * `ssrf-dns-pin` middleware — is the production article, which is what makes
     * tests 6 and 7 meaningful.
     */
    private function transportWith(StubbedTransfer $transfer, TransportTickerInterface $ticker): CancellableTransport
    {
        $real = $this->clientFactory->createCancellable();
        self::assertInstanceOf(CancellableTransport::class, $real);

        $client = $real->client();
        self::assertInstanceOf(Client::class, $client);

        $handler = $this->getGuzzleConfig($client)['handler'] ?? null;
        self::assertInstanceOf(HandlerStack::class, $handler);
        $handler->setHandler($transfer->handler());

        return new CancellableTransport($client, $ticker, $real->wallClockBudgetSeconds());
    }

    private function clientWithTransport(CancellableTransport $transport): VaultHttpClient
    {
        // No inner client: the constructor builds one from the factory, which is
        // what makes the instance factory-built. An injected transport is only
        // honoured for such an instance — see
        // `anInjectedTransportNeverDisplacesACallerSuppliedClient()` — so
        // passing one here would be testing the degraded path by accident.
        return new VaultHttpClient(
            vaultService: $this->vaultService,
            auditLogService: $this->auditLogService,
            secureHttpClientFactory: $this->clientFactory,
            cancellableTransport: $transport,
        );
    }

    /**
     * Record every audit row as `[action, success]`.
     *
     * @param list<array{0: string, 1: bool}> $actions
     *
     * @param-out list<array{0: string, 1: bool}> $actions
     */
    private function recordAuditActions(array &$actions): void
    {
        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->willReturnCallback(
                static function (
                    string $identifier,
                    string $action,
                    bool $success,
                    ?string $error = null,
                    ?string $reason = null,
                    ?string $hashBefore = null,
                    ?string $hashAfter = null,
                    ?AuditContextInterface $context = null,
                ) use (&$actions): void {
                    $actions[] = [$action, $success];
                },
            );
    }

    /**
     * Record every audit row as `[action, success, errorMessage]`.
     *
     * The message matters on this path: with a single cancellation action it is
     * what tells an operator whether a credential was involved, and the audit
     * module renders it in the row.
     *
     * @param list<array{0: string, 1: bool, 2: ?string}> $rows
     *
     * @param-out list<array{0: string, 1: bool, 2: ?string}> $rows
     */
    private function recordAuditRows(array &$rows): void
    {
        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->willReturnCallback(
                static function (
                    string $identifier,
                    string $action,
                    bool $success,
                    ?string $error = null,
                    ?string $reason = null,
                    ?string $hashBefore = null,
                    ?string $hashAfter = null,
                    ?AuditContextInterface $context = null,
                ) use (&$rows): void {
                    $rows[] = [$action, $success, $error];
                },
            );
    }
}

/**
 * A DNS resolver that answers from a programmed table and never touches the
 * network.
 */
final class ProgrammedDnsResolver implements DnsResolverInterface
{
    /** @var array<string, list<array{ip?: string, ipv6?: string}>> */
    private array $programmed = [];

    /** @var array<string, list<list<array{ip?: string, ipv6?: string}>>> */
    private array $sequences = [];

    /** @var array<string, int> */
    private array $calls = [];

    /**
     * @param list<array{ip?: string, ipv6?: string}> $records
     */
    public function program(string $host, array $records): void
    {
        $this->programmed[$host] = $records;
    }

    /**
     * Answer the same host differently on successive lookups.
     *
     * This is DNS rebinding: `isHostAllowed()` resolves the host once, the
     * `ssrf-dns-pin` middleware resolves it again a moment later, and an
     * attacker who controls the zone can answer the two lookups differently.
     * The last programmed answer repeats for any further lookup.
     *
     * @param list<list<array{ip?: string, ipv6?: string}>> $answers
     */
    public function programSequence(string $host, array $answers): void
    {
        $this->sequences[$host] = $answers;
        $this->calls[$host] = 0;
    }

    public function resolve(string $host): array
    {
        if (isset($this->sequences[$host])) {
            $answers = $this->sequences[$host];
            $index = min($this->calls[$host] ?? 0, \count($answers) - 1);
            $this->calls[$host] = ($this->calls[$host] ?? 0) + 1;

            return $answers[$index];
        }

        return $this->programmed[$host] ?? [];
    }
}

/**
 * The bottom handler of the stack under test.
 *
 * Returns a promise that never settles on its own — the only two ways out are
 * the ticker settling it or the cancellation loop cancelling it, which is
 * exactly the choice the loop is supposed to make.
 */
final class StubbedTransfer
{
    private ?RequestInterface $request = null;

    /** @var array<int|string, mixed>|null */
    private ?array $options = null;

    private int $transferCount = 0;

    private ?Promise $promise = null;

    /**
     * Incremented every time the promise's cancel function runs — the only
     * in-process evidence that an abort reached the transport.
     */
    private int $cancelCalls = 0;

    /**
     * Incremented if anything ever forced the promise to settle by waiting on
     * it — the one thing the loop must not do.
     */
    private int $waitCalls = 0;

    /**
     * @return Closure(RequestInterface, array<int|string, mixed>): PromiseInterface
     */
    public function handler(): Closure
    {
        return function (RequestInterface $request, array $options): PromiseInterface {
            $this->request = $request;
            /** @var array<int|string, mixed> $options */
            $this->options = $options;
            ++$this->transferCount;

            $promise = new Promise(
                function (): void {
                    // Must stay at zero. Guzzle runs this from `wait()`, whose
                    // implementation here is `CurlMultiHandler::execute()` —
                    // it loops until every handle on the handler completes and
                    // leaves no window in which the signal could be observed.
                    // A loop that called wait() would still pass most of these
                    // tests while being uncancellable in production.
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

    public function settleWith(Response $response): void
    {
        $this->settleWithValue($response);
    }

    /**
     * Settle with something that is not a PSR-7 response.
     *
     * No handler this package builds can do that; the branch exists so such a
     * value can never be returned to a caller as if it were a response, and a
     * branch with no test is a branch nobody has read.
     */
    public function settleWithValue(mixed $value): void
    {
        $this->promise?->resolve($value);
        // Propagate through the middleware `then()` chain: Guzzle queues handler
        // callbacks rather than running them inline, and it is normally
        // CurlMultiHandler::tick() that drains that queue.
        PromiseUtils::queue()->run();
    }

    /**
     * Reject with a reason that is not a Throwable.
     *
     * Guzzle's own handlers reject with a `RequestException`, but the promise
     * contract allows any value, and the branch that refuses one exists so such
     * a reason can never be rethrown or copied into the row.
     */
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
        return $this->transferCount > 0;
    }

    public function transferCount(): int
    {
        return $this->transferCount;
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
 * A transport client whose `sendAsync()` throws instead of returning a promise.
 *
 * Not a contrived shape: `Client::applyOptions()` raises
 * `InvalidArgumentException` outside `Client::transfer()`'s own try/catch, so a
 * real Guzzle client does exactly this for a bad option set — the throw escapes
 * the call rather than becoming a rejected promise.
 */
final class ThrowingOnSendClient implements GuzzleClientInterface
{
    /**
     * @param array<array-key, mixed> $options
     */
    public function send(RequestInterface $request, array $options = []): ResponseInterface
    {
        throw new InvalidArgumentException('sendAsync refused the option set', 1786579302);
    }

    /**
     * @param array<array-key, mixed> $options
     */
    public function sendAsync(RequestInterface $request, array $options = []): PromiseInterface
    {
        throw new InvalidArgumentException('sendAsync refused the option set', 1786579302);
    }

    /**
     * @param string|UriInterface $uri
     * @param array<array-key, mixed> $options
     */
    public function request(string $method, $uri, array $options = []): ResponseInterface
    {
        throw new InvalidArgumentException('sendAsync refused the option set', 1786579302);
    }

    /**
     * @param string|UriInterface $uri
     * @param array<array-key, mixed> $options
     */
    public function requestAsync(string $method, $uri, array $options = []): PromiseInterface
    {
        throw new InvalidArgumentException('sendAsync refused the option set', 1786579302);
    }

    public function getConfig(?string $option = null): mixed
    {
        return null;
    }
}

/**
 * Drives the loop from a closure instead of a curl multi handle.
 */
final class ClosureTicker implements TransportTickerInterface
{
    private int $ticks = 0;

    /**
     * @param Closure(int): void $onTick Receives the 1-based tick number
     */
    public function __construct(private readonly Closure $onTick) {}

    public function tick(): void
    {
        ++$this->ticks;
        ($this->onTick)($this->ticks);
    }

    public function ticks(): int
    {
        return $this->ticks;
    }
}

/**
 * False for the first `$falseAnswers` questions, true from then on.
 */
final class CountdownSignal implements CancellationSignalInterface
{
    private int $asked = 0;

    public function __construct(private readonly int $falseAnswers) {}

    public function isCancelled(): bool
    {
        ++$this->asked;

        return $this->asked > $this->falseAnswers;
    }
}

final class NeverCancelledSignal implements CancellationSignalInterface
{
    public function isCancelled(): bool
    {
        return false;
    }
}

final class AlreadyCancelledSignal implements CancellationSignalInterface
{
    public function isCancelled(): bool
    {
        return true;
    }
}

/**
 * Breaks the interface's "MUST NOT throw" contract on the Nth question.
 *
 * A caller-supplied object that misbehaves is not hypothetical, and the
 * contract is a docblock, not an enforcement. What must hold anyway: the row
 * still gets written, because the credential is already out by then.
 */
final class ThrowingSignal implements CancellationSignalInterface
{
    private int $asked = 0;

    public function __construct(private readonly int $falseAnswers) {}

    public function isCancelled(): bool
    {
        ++$this->asked;

        if ($this->asked > $this->falseAnswers) {
            throw new RuntimeException("the caller's signal blew up", 1786579301);
        }

        return false;
    }
}
