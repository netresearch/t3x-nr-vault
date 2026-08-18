<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http\OAuth;

use Closure;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\Utils as PromiseUtils;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Netresearch\NrVault\Audit\AuditContextInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\OAuthException;
use Netresearch\NrVault\Exception\RequestCancelledException;
use Netresearch\NrVault\Http\CancellableTransport;
use Netresearch\NrVault\Http\CancellationSignalInterface;
use Netresearch\NrVault\Http\DnsResolverInterface;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Http\OAuth\OAuthTokenManager;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\TransportTickerInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;

/**
 * The cancellable OAuth token round trip (issue #303).
 *
 * Mirrors the determinism rules of `VaultHttpClientCancellableTest`: no
 * sockets, no sleeps — the transport's bottom handler is a stub whose promise
 * nobody settles, and the ticker is a closure that settles it on the Nth call.
 * The literals asserted below are copied from `OAuthTokenManager` rather than
 * read from it, so a change to the subject is a change to a test.
 *
 * Not covered here, by the same in-process limitation the other cancellable
 * suite documents: the degraded branch where `createCancellable()` returns
 * null (no `curl_multi_*` on the platform) — `\function_exists()` cannot be
 * faked, and the branch is a two-line fallback to the blocking client.
 */
#[CoversClass(OAuthTokenManager::class)]
final class OAuthTokenManagerCancellableTest extends TestCase
{
    private const TOKEN_ENDPOINT = 'https://auth.example.com/token';

    private const CLIENT_ID_SECRET = 'oauth/client-id';

    private const CLIENT_SECRET_SECRET = 'oauth/client-secret';

    /** Copied from OAuthTokenManager — see the class docblock above. */
    private const CANCELLED_BEFORE_SEND_MESSAGE
        = 'OAuth token request cancelled before send: nothing egressed';

    private const CANCELLED_IN_FLIGHT_MESSAGE
        = 'OAuth token request cancelled after send began: the client credential was handed to the transport';

    private const TICK_BUDGET_EXHAUSTED_MESSAGE
        = 'Cancellable OAuth token transfer exceeded its wall-clock budget and was aborted';

    private VaultServiceInterface&MockObject $vaultService;

    private ClientInterface&MockObject $blockingClient;

    private mixed $originalGlobals;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->blockingClient = $this->createMock(ClientInterface::class);

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

    #[Test]
    public function aCompletedCancellableTokenFetchReturnsTheTokenAndAuditsSuccess(): void
    {
        $this->programCredentialReads();

        $transfer = new TokenTransfer();
        $ticker = new TokenLoopTicker(static function (int $tick) use ($transfer): void {
            if ($tick >= 1) {
                $transfer->settleWith(self::tokenResponse('cancellable-access-token'));
            }
        });

        $rows = [];
        $subject = $this->managerWith($transfer, $ticker, $rows);

        // The blocking client must not serve a signalled call — that it is
        // never consulted IS the proof the signal routed the send through the
        // cancellable transport.
        $this->blockingClient->expects(self::never())->method('sendRequest');

        $token = $subject->getAccessToken($this->config(), new TokenNeverCancelledSignal());

        self::assertSame('cancellable-access-token', $token);
        self::assertTrue($transfer->wasReached());
        self::assertSame(0, $transfer->cancelCalls(), 'A completed transfer needs no teardown.');
        self::assertSame(0, $transfer->waitCalls(), 'The loop must never wait() the promise settled.');
        self::assertCount(1, $rows);
        [, $action, $success] = $rows[0];
        self::assertSame('oauth_token_request', $action);
        self::assertTrue($success);
    }

    #[Test]
    public function anInFlightCancellationAbortsTheTokenTransferAndAuditsIt(): void
    {
        $this->programCredentialReads();

        $transfer = new TokenTransfer();
        // Never settles: the only way out of the loop is the signal.
        $ticker = new TokenLoopTicker(static function (): void {});

        $rows = [];
        $subject = $this->managerWith($transfer, $ticker, $rows);

        // Question 1: the pre-read check in getAccessToken(). Question 2: the
        // pre-send check in dispatchTokenRequest(). Question 3: the loop's
        // first pass. Three falses put the abort on the loop's second pass —
        // after the transfer was handed to the transport.
        try {
            $subject->getAccessToken($this->config(), new TokenCountdownSignal(3));
            self::fail('Expected the in-flight cancellation to throw.');
        } catch (RequestCancelledException $e) {
            self::assertSame(self::CANCELLED_IN_FLIGHT_MESSAGE, $e->getMessage());
            self::assertSame(1786579303, $e->getCode());
        }

        self::assertTrue($transfer->wasReached());
        self::assertSame(1, $transfer->cancelCalls(), 'The abort must tear the transfer down exactly once.');
        self::assertCount(1, $rows);
        [, $action, $success, $error] = $rows[0];
        self::assertSame('oauth_token_request', $action);
        self::assertFalse($success);
        self::assertSame(self::CANCELLED_IN_FLIGHT_MESSAGE, $error);
    }

    #[Test]
    public function aPreSendCancellationReadsCredentialsButEgressesNothing(): void
    {
        $this->programCredentialReads();

        $transfer = new TokenTransfer();
        $rows = [];
        $subject = $this->managerWith($transfer, new TokenLoopTicker(static function (): void {}), $rows);

        $this->blockingClient->expects(self::never())->method('sendRequest');

        // Question 1 (pre-read): false. Question 2 (pre-send): true.
        try {
            $subject->getAccessToken($this->config(), new TokenCountdownSignal(1));
            self::fail('Expected the pre-send cancellation to throw.');
        } catch (RequestCancelledException $e) {
            self::assertSame(self::CANCELLED_BEFORE_SEND_MESSAGE, $e->getMessage());
            self::assertSame(1786579302, $e->getCode());
        }

        self::assertFalse($transfer->wasReached(), 'Nothing may reach the transport.');
        self::assertCount(1, $rows, 'The credentials were read, so the round trip leaves its row.');
        [, $action, $success, $error] = $rows[0];
        self::assertSame('oauth_token_request', $action);
        self::assertFalse($success);
        self::assertSame(self::CANCELLED_BEFORE_SEND_MESSAGE, $error);
    }

    #[Test]
    public function anAlreadyCancelledCallReadsNoSecretAndLeavesNoRow(): void
    {
        $this->vaultService->expects(self::never())->method('retrieve');

        $transfer = new TokenTransfer();
        $rows = [];
        $subject = $this->managerWith($transfer, new TokenLoopTicker(static function (): void {}), $rows);

        try {
            $subject->getAccessToken($this->config(), new TokenAlreadyCancelledSignal());
            self::fail('Expected the pre-read cancellation to throw.');
        } catch (RequestCancelledException $e) {
            self::assertSame(self::CANCELLED_BEFORE_SEND_MESSAGE, $e->getMessage());
            self::assertSame(1786579301, $e->getCode());
        }

        self::assertFalse($transfer->wasReached());
        self::assertSame([], $rows, 'No credentials in hand, no round trip, no row.');
    }

    #[Test]
    public function anExhaustedWallClockBudgetIsAFailureNotACancellation(): void
    {
        $this->programCredentialReads();

        $transfer = new TokenTransfer();
        $rows = [];
        // Budget zero: the deadline has passed on the loop's first check.
        $subject = $this->managerWith(
            $transfer,
            new TokenLoopTicker(static function (): void {}),
            $rows,
            wallClockBudgetSeconds: 0.0,
        );

        try {
            $subject->getAccessToken($this->config(), new TokenNeverCancelledSignal());
            self::fail('Expected the wall-clock bound to throw.');
        } catch (OAuthException $e) {
            self::assertSame(self::TICK_BUDGET_EXHAUSTED_MESSAGE, $e->getMessage());
            self::assertSame(1786579304, $e->getCode());
        }

        self::assertSame(1, $transfer->cancelCalls(), 'The bound must still tear the transfer down.');
        self::assertCount(1, $rows);
        [, $action, $success, $error] = $rows[0];
        self::assertSame('oauth_token_request', $action);
        self::assertFalse($success);
        self::assertSame(self::TICK_BUDGET_EXHAUSTED_MESSAGE, $error);
    }

    #[Test]
    public function aRejectedTransferSurfacesLikeABlockingFailureWithRedaction(): void
    {
        $this->programCredentialReads();

        $transfer = new TokenTransfer();
        $ticker = new TokenLoopTicker(static function (int $tick) use ($transfer): void {
            if ($tick >= 1) {
                $transfer->rejectWith(new RequestException(
                    'cURL error 7 while sending client_secret=super-secret-value',
                    $transfer->request() ?? new Request('POST', self::TOKEN_ENDPOINT),
                ));
            }
        });

        $rows = [];
        $subject = $this->managerWith($transfer, $ticker, $rows);

        try {
            $subject->getAccessToken($this->config(), new TokenNeverCancelledSignal());
            self::fail('Expected the rejected transfer to throw.');
        } catch (OAuthException $e) {
            self::assertStringContainsString('[REDACTED]', $e->getMessage());
            self::assertStringNotContainsString('super-secret-value', $e->getMessage());
        }

        self::assertCount(1, $rows);
        [, $action, $success, $error] = $rows[0];
        self::assertSame('oauth_token_request', $action);
        self::assertFalse($success);
        self::assertIsString($error);
        self::assertStringContainsString('[REDACTED]', $error);
        self::assertStringNotContainsString('super-secret-value', $error);
    }

    // =========================================================================
    // Harness
    // =========================================================================

    private function config(): OAuthConfig
    {
        return OAuthConfig::clientCredentials(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: self::CLIENT_ID_SECRET,
            clientSecretSecret: self::CLIENT_SECRET_SECRET,
        );
    }

    private function programCredentialReads(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                self::CLIENT_ID_SECRET => 'my-client-id',
                self::CLIENT_SECRET_SECRET => 'my-client-secret',
                default => null,
            });
    }

    /**
     * A manager whose injected cancellable transport bottoms out in
     * `$transfer` and whose audit rows are captured into `$rows` as
     * `[identifier, action, success, error]`.
     *
     * @param list<array{0: string, 1: string, 2: bool, 3: ?string}> $rows
     *
     * @param-out list<array{0: string, 1: string, 2: bool, 3: ?string}> $rows
     */
    private function managerWith(
        TokenTransfer $transfer,
        TokenLoopTicker $ticker,
        array &$rows,
        float $wallClockBudgetSeconds = 45.0,
    ): OAuthTokenManager {
        $rows = [];
        $auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $auditLogService
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
                    $rows[] = [$identifier, $action, $success, $error];
                },
            );

        $transport = new CancellableTransport(
            new Client(['handler' => HandlerStack::create($transfer->handler())]),
            $ticker,
            $wallClockBudgetSeconds,
        );

        return new OAuthTokenManager(
            $this->vaultService,
            $this->blockingClient,
            new SecureHttpClientFactory(new AlwaysEmptyDnsResolver()),
            null,
            null,
            null,
            $auditLogService,
            $transport,
        );
    }

    private static function tokenResponse(string $accessToken): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ], JSON_THROW_ON_ERROR));
    }
}

/**
 * Deterministic stand-in for DNS during the host gate: every host resolves to
 * nothing, which the gate treats as "let the client surface the connection
 * error" — no network, no real resolver.
 */
final class AlwaysEmptyDnsResolver implements DnsResolverInterface
{
    public function resolve(string $host): array
    {
        return [];
    }
}

/**
 * The bottom handler of the token transport under test — the token-leg
 * sibling of `StubbedTransfer` in `VaultHttpClientCancellableTest`. Returns a
 * promise that never settles on its own; the ticker settles it, or the loop
 * cancels it.
 */
final class TokenTransfer
{
    private ?RequestInterface $request = null;

    private ?Promise $promise = null;

    private int $transferCount = 0;

    private int $cancelCalls = 0;

    private int $waitCalls = 0;

    /**
     * @return Closure(RequestInterface, array<int|string, mixed>): PromiseInterface
     */
    public function handler(): Closure
    {
        return function (RequestInterface $request, array $options): PromiseInterface {
            $this->request = $request;
            ++$this->transferCount;

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

    public function settleWith(Response $response): void
    {
        $this->promise?->resolve($response);
        PromiseUtils::queue()->run();
    }

    public function rejectWith(mixed $reason): void
    {
        $this->promise?->reject($reason);
        PromiseUtils::queue()->run();
    }

    public function request(): ?RequestInterface
    {
        return $this->request;
    }

    public function wasReached(): bool
    {
        return $this->transferCount > 0;
    }

    public function cancelCalls(): int
    {
        return $this->cancelCalls;
    }

    public function waitCalls(): int
    {
        return $this->waitCalls;
    }
}

/**
 * Drives the token-leg loop from a closure instead of a curl multi handle.
 */
final class TokenLoopTicker implements TransportTickerInterface
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
}

/**
 * False for the first `$falseAnswers` questions, true from then on.
 */
final class TokenCountdownSignal implements CancellationSignalInterface
{
    private int $asked = 0;

    public function __construct(private readonly int $falseAnswers) {}

    public function isCancelled(): bool
    {
        ++$this->asked;

        return $this->asked > $this->falseAnswers;
    }
}

final class TokenNeverCancelledSignal implements CancellationSignalInterface
{
    public function isCancelled(): bool
    {
        return false;
    }
}

final class TokenAlreadyCancelledSignal implements CancellationSignalInterface
{
    public function isCancelled(): bool
    {
        return true;
    }
}
