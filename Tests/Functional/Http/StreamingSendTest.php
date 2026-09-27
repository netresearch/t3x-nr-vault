<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Http;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Handler\CurlMultiHandler;
use GuzzleHttp\Psr7\Request;
use Netresearch\NrVault\Audit\AuditContextInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\RequestCancelledException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\CancellableTransport;
use Netresearch\NrVault\Http\CancellationSignalInterface;
use Netresearch\NrVault\Http\CurlMultiTicker;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\StreamingResponseBody;
use Netresearch\NrVault\Http\StreamingSink;
use Netresearch\NrVault\Http\StreamingTransfer;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\Http\Fixtures\PinnedDnsResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use ReflectionProperty;
use RuntimeException;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * `VaultHttpClient::sendStreaming()` against a real HTTP server.
 *
 * The server is PHP's built-in web server running
 * `Fixtures/streaming-router.php` on a free loopback port chosen at runtime,
 * started once per class. Its routes flush one line at a time and stamp each
 * line with the moment it was sent, so a test can compare when a byte left the
 * server with when the client could read it.
 *
 * Every request goes to a name under `.test`, which no resolver answers; the
 * `PinnedDnsResolver` hands the SSRF middleware the loopback address and the
 * middleware pins it with `CURLOPT_RESOLVE`. A transfer that reaches the server
 * therefore reached it through the pin.
 *
 * An unreachable server is a test failure, never a skip.
 */
#[CoversClass(VaultHttpClient::class)]
#[CoversClass(StreamingTransfer::class)]
#[CoversClass(StreamingResponseBody::class)]
#[Group('integration')]
final class StreamingSendTest extends FunctionalTestCase
{
    private const ROUTER_SCRIPT = __DIR__ . '/Fixtures/streaming-router.php';

    private const LOOPBACK_HOST = '127.0.0.1';

    /**
     * Loopback, but not the address the server is bound to: a pin to it must
     * fail to connect.
     */
    private const WRONG_LOOPBACK_ADDRESS = '127.0.0.2';

    private const PINNED_NAME = 'stream-pin.test';

    private const SERVER_START_ATTEMPTS = 3;

    private const SERVER_READY_TIMEOUT_SECONDS = 10;

    private const SECRET = 'streaming-test-token';

    private const TLS_ORIGIN_NAME = 'tls-origin.test';

    private const LINE_READ_TIMEOUT_SECONDS = 15.0;

    private const BUFFER_LIMIT_MESSAGE
        = 'Streaming transfer aborted: one step delivered more body than the 16 MiB streaming buffer holds';

    private const TUNNEL_SCRIPT = __DIR__ . '/Fixtures/tunnel-server.php';

    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    /** @var resource|null */
    private static $serverProcess;

    private static int $serverPort = 0;

    private static string $serverLogFile = '';

    private static string $hitsDirectory = '';

    private static string $tunnelDirectory = '';

    /** @var list<resource> */
    private array $tunnelProcesses = [];

    /** @var list<array{identifier: string, action: string, success: bool, status: mixed, error: string|null}> */
    private array $auditRows = [];

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        self::startServer();
    }

    public static function tearDownAfterClass(): void
    {
        self::stopServer();
        parent::tearDownAfterClass();
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->auditRows = [];

        // A fresh hits directory per test, so a route reached by an earlier
        // test cannot count as reached by this one.
        GeneralUtility::rmdir(self::$hitsDirectory, true);
        mkdir(self::$hitsDirectory, 0o700);

        // The SSRF guard refuses loopback unless the name is listed literally
        // in `allowed_hosts` — the documented opt-in for self-hosted endpoints.
        $this->setHttpConfiguration([
            'allowed_hosts' => [self::PINNED_NAME],
            'timeout' => 10,
            'connect_timeout' => 2,
        ]);
    }

    protected function tearDown(): void
    {
        foreach ($this->tunnelProcesses as $process) {
            proc_terminate($process);
            proc_close($process);
        }

        $this->tunnelProcesses = [];
        if (self::$tunnelDirectory !== '') {
            GeneralUtility::rmdir(self::$tunnelDirectory, true);
            self::$tunnelDirectory = '';
        }

        parent::tearDown();
    }

    #[Test]
    public function theFirstBytesAreReadableBeforeTheServerHasFinished(): void
    {
        $client = $this->client();
        self::assertTrue($client->supportsStreaming(), 'A degraded blocking send would pass every content assertion below.');

        $response = $client->sendStreaming(new Request('GET', $this->url('/chunks?count=3&delay_ms=600')));
        $returnedAt = $this->nowMicroseconds();

        $body = $response->getBody();
        $pending = '';
        $lines = $this->readCompleteLines($body, 3, $pending);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['chunk 1', 'chunk 2', 'chunk 3'], array_column($lines, 'text'));

        $lastSentAt = $lines[2]['sentAt'];
        self::assertLessThan(
            $lastSentAt,
            $returnedAt,
            'sendStreaming() must return before the server has sent its last line.',
        );
        self::assertLessThan(
            $lastSentAt,
            $lines[0]['readAt'],
            'The first line must be readable before the server has sent its last one.',
        );
        self::assertLessThan(
            $lines[2]['readAt'],
            $lines[1]['readAt'],
            'The second line must be readable before the third.',
        );

        self::assertSame('', $pending, 'Nothing may be left over after the last complete line.');
        self::assertSame('', $body->read(8192), 'A completed transfer ends with an empty read.');
        self::assertTrue($body->eof());
        self::assertSame(
            [['identifier' => 'none', 'action' => 'http_call', 'success' => true, 'status' => 200, 'error' => null]],
            $this->auditRows,
            'Exactly one row, written when the headers arrived.',
        );
    }

    #[Test]
    public function theCredentialIsInjectedExactlyAsOnSendRequest(): void
    {
        $client = $this->client()->withAuthentication('stream_token', SecretPlacement::Bearer);

        $streamed = (string) $client->sendStreaming(new Request('GET', $this->url('/echo-auth')))->getBody();
        $blocking = (string) $client->sendRequest(new Request('GET', $this->url('/echo-auth')))->getBody();

        self::assertStringStartsWith('authorization=Bearer ' . self::SECRET . ' ', $streamed);
        self::assertStringStartsWith('authorization=Bearer ' . self::SECRET . ' ', $blocking);
        self::assertSame(
            ['stream_token', 'stream_token'],
            array_column($this->auditRows, 'identifier'),
            'Both sends are audited under the secret they injected.',
        );
    }

    #[Test]
    public function theTransferReachesTheServerOnlyThroughTheDnsPin(): void
    {
        $resolver = new PinnedDnsResolver(self::LOOPBACK_HOST);

        $body = (string) $this->client($resolver)
            ->sendStreaming(new Request('GET', $this->url('/chunks?count=1')))
            ->getBody();

        self::assertStringStartsWith('chunk 1 ', $body, 'The .test name resolves nowhere; only the pin can have delivered this.');
        self::assertGreaterThan(0, $resolver->lookups(), 'The pin comes from the factory resolver.');
    }

    #[Test]
    public function aPinToAnotherAddressFailsInsteadOfFallingBackToDns(): void
    {
        $client = $this->client(new PinnedDnsResolver(self::WRONG_LOOPBACK_ADDRESS));

        try {
            $client->sendStreaming(new Request('GET', $this->url('/chunks?count=1')));
            self::fail('A pin to an address nothing listens on must not reach the server.');
        } catch (ClientExceptionInterface) {
            // expected
        }

        self::assertFileDoesNotExist(self::$hitsDirectory . '/chunks');
        self::assertCount(1, $this->auditRows);
        self::assertSame('http_call', $this->auditRows[0]['action']);
        self::assertFalse($this->auditRows[0]['success']);
    }

    #[Test]
    public function aRedirectIsReturnedAndNotFollowed(): void
    {
        $this->setHttpConfiguration(['allow_redirects' => true]);

        $response = $this->client()->sendStreaming(new Request('GET', $this->url('/redirect')));

        self::assertSame(302, $response->getStatusCode());
        self::assertSame('/redirect-target', $response->getHeaderLine('Location'));
        self::assertSame('redirecting', (string) $response->getBody());
        self::assertFileExists(self::$hitsDirectory . '/redirect');
        self::assertFileDoesNotExist(
            self::$hitsDirectory . '/redirect-target',
            'The redirect must not be followed, even when the platform enables redirects.',
        );
    }

    #[Test]
    public function aStalledStreamEndsAtTheTransferTimeout(): void
    {
        $response = $this->client()->withTimeout(2)->sendStreaming(new Request('GET', $this->url('/stall')));
        $body = $response->getBody();

        $pending = '';
        $firstLine = $this->readCompleteLines($body, 1, $pending);
        self::assertSame('before stall', $firstLine[0]['text'] ?? null);

        $start = microtime(true);

        try {
            $body->read(8192);
            self::fail('A stalled transfer must end with an exception, not wait for the server.');
        } catch (VaultException $e) {
            self::assertSame(1790475706, $e->getCode());
            self::assertInstanceOf(ClientExceptionInterface::class, $e->getPrevious());
        }

        self::assertLessThan(
            5.0,
            microtime(true) - $start,
            'The two-second transfer timeout must end the read long before the 30-second stall does.',
        );
    }

    #[Test]
    public function closingTheBodyRemovesTheTransferFromTheMultiHandle(): void
    {
        [$client, $multi] = $this->clientWithObservableTransport();

        $body = $client->sendStreaming(new Request('GET', $this->url('/chunks?count=50&delay_ms=100')))->getBody();
        $pending = '';
        $this->readCompleteLines($body, 1, $pending);
        self::assertSame(1, $this->activeTransfers($multi), 'The transfer is on the multi handle while it is read.');

        $body->close();

        self::assertSame(0, $this->activeTransfers($multi), 'close() before the end must remove and close the handle.');
    }

    #[Test]
    public function droppingTheBodyRemovesTheTransferFromTheMultiHandle(): void
    {
        [$client, $multi] = $this->clientWithObservableTransport();

        $response = $client->sendStreaming(new Request('GET', $this->url('/chunks?count=50&delay_ms=100')));
        $pending = '';
        $this->readCompleteLines($response->getBody(), 1, $pending);
        self::assertSame(1, $this->activeTransfers($multi));

        unset($response);

        self::assertSame(0, $this->activeTransfers($multi), 'A body nobody holds any more must not keep its transfer alive.');
    }

    #[Test]
    public function aSignalFiredWhileReadingAbortsTheTransfer(): void
    {
        [$client, $multi] = $this->clientWithObservableTransport();
        $signal = new SwitchableSignal();

        $body = $client->sendStreaming(new Request('GET', $this->url('/chunks?count=50&delay_ms=100')), $signal)->getBody();
        $pending = '';
        $this->readCompleteLines($body, 1, $pending);

        $signal->cancel();

        $caught = null;

        try {
            // Bounded: the route sends fifty lines, so a loop that never sees
            // the signal stops at the end of the stream and fails below.
            for ($read = 0; $read < 1000; ++$read) {
                if ($body->read(8192) === '') {
                    break;
                }
            }
        } catch (RequestCancelledException $e) {
            $caught = $e;
        }

        self::assertInstanceOf(RequestCancelledException::class, $caught, 'The signal must abort the read.');
        self::assertSame(1790475704, $caught->getCode());

        self::assertSame(0, $this->activeTransfers($multi));
    }

    #[Test]
    public function aTransferThatFailsMidStreamThrowsFromReadAfterTheBytesThatArrived(): void
    {
        $response = $this->client()->sendStreaming(new Request('GET', $this->url('/truncated')));
        $body = $response->getBody();

        self::assertSame(200, $response->getStatusCode());

        $received = '';
        $caught = null;

        try {
            // An empty read would be an end of stream the server never sent;
            // it ends the loop and fails the assertions below.
            for ($read = 0; $read < 1000 && ($chunk = $body->read(8192)) !== ''; ++$read) {
                $received .= $chunk;
            }
        } catch (VaultException $e) {
            $caught = $e;
        }

        self::assertInstanceOf(VaultException::class, $caught, 'A truncated transfer must throw from read().');
        self::assertSame(1790475706, $caught->getCode());
        self::assertInstanceOf(ClientExceptionInterface::class, $caught->getPrevious());

        self::assertSame('sixteen bytes!!!', $received, 'The bytes that arrived are handed out before the failure.');
        self::assertFalse($body->eof(), 'A failed transfer never reports end of stream.');
    }

    #[Test]
    public function throughATunnellingProxyTheOriginHeadIsReturnedNotTheProxyReply(): void
    {
        $origin = $this->startTunnelServer('origin');
        $proxy = $this->startTunnelServer('proxy', (string) $origin);
        $this->setHttpConfiguration([
            'allowed_hosts' => [self::TLS_ORIGIN_NAME],
            'proxy' => 'http://' . self::LOOPBACK_HOST . ':' . $proxy, // NOSONAR — test-only loopback proxy
            // The origin's certificate is a throwaway; this test is about which
            // head is returned, not about TLS.
            'verify' => false,
        ]);
        $url = 'https://' . self::TLS_ORIGIN_NAME . ':' . $origin . '/protected';

        $blocking = $this->client()->sendRequest(new Request('GET', $url));
        $streamed = $this->client()->sendStreaming(new Request('GET', $url));

        self::assertSame(401, $blocking->getStatusCode(), 'Control: the blocking send returns the origin head.');
        self::assertSame(401, $streamed->getStatusCode(), "The proxy's 200 Connection established is not the response.");
        self::assertSame('target', $streamed->getHeaderLine('X-Origin'));
        self::assertFalse($streamed->hasHeader('X-Proxy'));
        self::assertSame("target said: 401\n", (string) $streamed->getBody());
        self::assertSame([401, 401], array_column($this->auditRows, 'status'), 'Both rows carry the origin status.');
        self::assertStringContainsString(
            'CONNECT ' . self::TLS_ORIGIN_NAME . ':' . $origin,
            (string) file_get_contents(self::$tunnelDirectory . '/proxy.port.log'),
            'Both sends must have gone through the tunnel, or this test proves nothing about it.',
        );
    }

    #[Test]
    public function aLargePlainBodyStreamsToTheEndUnderTheBufferLimit(): void
    {
        $body = $this->client()->sendStreaming(new Request('GET', $this->url('/large?mb=64')))->getBody();

        $total = 0;
        $largestStep = 0;
        // Each read drains the whole buffer, so a chunk is what one step delivered.
        while (($chunk = $body->read(64 * 1024 * 1024)) !== '') {
            $total += \strlen($chunk);
            $largestStep = max($largestStep, \strlen($chunk));
        }

        self::assertSame(64 * 1024 * 1024, $total, 'A legitimate large body must not trip the limit.');
        self::assertLessThan(StreamingSink::DEFAULT_LIMIT_BYTES, $largestStep);
    }

    #[Test]
    public function aCompressionBombFailsClosedWithBoundedMemory(): void
    {
        gc_collect_cycles();
        memory_reset_peak_usage();
        $before = memory_get_usage(true);

        $caught = null;

        try {
            $response = $this->client()->sendStreaming(new Request('GET', $this->url('/bomb?mb=128')));
            $body = $response->getBody();
            for ($read = 0; $read < 100_000; ++$read) {
                if ($body->read(1024 * 1024) === '') {
                    break;
                }
            }
        } catch (VaultException $e) {
            $caught = $e;
        }

        $growth = memory_get_peak_usage(true) - $before;

        self::assertInstanceOf(VaultException::class, $caught, '128 MiB decoded from about 128 KiB must not be buffered or returned.');
        self::assertContains($caught->getCode(), [1790487102, 1790487103]);
        self::assertSame(self::BUFFER_LIMIT_MESSAGE, $caught->getMessage());
        self::assertLessThan(
            64 * 1024 * 1024,
            $growth,
            'Memory must stay near the 16 MiB bound, not follow the decoded size.',
        );
        self::assertCount(1, $this->auditRows);
        if ($caught->getCode() === 1790487102) {
            // The transport's exception keeps the response it built, whose body
            // is the sink: a caller holding the exception must not hold the
            // buffered bytes with it.
            // Guzzle 7 rejects with a RequestException, Guzzle 8 with a
            // ResponseException; both carry getResponse(), on different classes.
            $previous = $caught->getPrevious();
            self::assertIsObject($previous);
            self::assertTrue(method_exists($previous, 'getResponse'), 'The transport exception must carry its response.');
            $response = $previous->getResponse();
            self::assertInstanceOf(ResponseInterface::class, $response);
            $retained = $response->getBody();
            self::assertInstanceOf(StreamingSink::class, $retained);
            self::assertSame(0, $retained->getSize());

            // Overflowed before sendStreaming() returned: the call failed, and
            // the row names the bound rather than the cURL write error.
            self::assertFalse($this->auditRows[0]['success']);
            self::assertSame(self::BUFFER_LIMIT_MESSAGE, $this->auditRows[0]['error']);
        }
    }

    // =========================================================================
    // Harness
    // =========================================================================

    private function client(?PinnedDnsResolver $resolver = null): VaultHttpClient
    {
        return new VaultHttpClient(
            vaultService: $this->vaultService(),
            auditLogService: $this->auditLogService(),
            secureHttpClientFactory: new SecureHttpClientFactory($resolver ?? new PinnedDnsResolver(self::LOOPBACK_HOST)),
        );
    }

    /**
     * A client whose transport the test built, so the curl multi handle it
     * runs on can be inspected.
     *
     * @return array{0: VaultHttpClient, 1: CurlMultiHandler}
     */
    private function clientWithObservableTransport(): array
    {
        $factory = new SecureHttpClientFactory(new PinnedDnsResolver(self::LOOPBACK_HOST));
        $transport = $factory->createCancellable();
        self::assertInstanceOf(CancellableTransport::class, $transport);

        $ticker = $transport->ticker();
        self::assertInstanceOf(CurlMultiTicker::class, $ticker);
        $multi = (new ReflectionProperty(CurlMultiTicker::class, 'handler'))->getValue($ticker);
        self::assertInstanceOf(CurlMultiHandler::class, $multi);

        $client = new VaultHttpClient(
            vaultService: $this->vaultService(),
            auditLogService: $this->auditLogService(),
            secureHttpClientFactory: $factory,
            cancellableTransport: $transport,
        );

        return [$client, $multi];
    }

    /**
     * Transfers the multi handle still holds — Guzzle keeps them in a private
     * map until the transfer settles or is cancelled.
     */
    private function activeTransfers(CurlMultiHandler $multi): int
    {
        $handles = (new ReflectionProperty(CurlMultiHandler::class, 'handles'))->getValue($multi);
        self::assertIsArray($handles);

        return \count($handles);
    }

    private function vaultService(): VaultServiceInterface
    {
        $vaultService = self::createStub(VaultServiceInterface::class);
        $vaultService->method('retrieve')->willReturn(self::SECRET);

        return $vaultService;
    }

    private function auditLogService(): AuditLogServiceInterface
    {
        $auditLogService = self::createStub(AuditLogServiceInterface::class);
        $auditLogService->method('log')->willReturnCallback(
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
                    'identifier' => $identifier,
                    'action' => $action,
                    'success' => $success,
                    'status' => $context?->toArray()['status_code'] ?? null,
                    'error' => $error,
                ];
            },
        );

        return $auditLogService;
    }

    private function url(string $pathAndQuery): string
    {
        // Plain HTTP on loopback: the built-in server cannot terminate TLS. NOSONAR — test-only.
        return 'http://' . self::PINNED_NAME . ':' . self::$serverPort . $pathAndQuery; // NOSONAR
    }

    /**
     * Read until `$wanted` complete router lines have arrived.
     *
     * A read returns whatever bytes are there, and a line can end anywhere
     * between two reads — the router's lines left the server as several
     * `sendto()` calls, and a read on a busy CI runner landed between them. So
     * bytes after the last newline are kept in `$pending` for the next call,
     * and a line's `readAt` is the moment the read that completed it returned.
     * Bounded by end of stream and by a deadline, so a transfer that stops
     * delivering fails the test instead of hanging the suite.
     *
     * @param-out string $pending
     *
     * @return list<array{text: string, sentAt: int, readAt: int}>
     */
    private function readCompleteLines(StreamInterface $body, int $wanted, string &$pending): array
    {
        $lines = [];
        $deadline = microtime(true) + self::LINE_READ_TIMEOUT_SECONDS;

        while (\count($lines) < $wanted) {
            self::assertLessThan($deadline, microtime(true), \sprintf('Only %d of %d lines arrived in time.', \count($lines), $wanted));

            $chunk = $body->read(8192);
            $readAt = $this->nowMicroseconds();
            if ($chunk === '') {
                self::fail(\sprintf('The stream ended after %d of %d lines; left over: %s', \count($lines), $wanted, var_export($pending, true)));
            }

            $pending .= $chunk;
            while (($end = strpos($pending, "\n")) !== false) {
                $raw = substr($pending, 0, $end);
                $pending = substr($pending, $end + 1);
                self::assertSame(1, preg_match('/^(.*) sent_us=(\d+)$/', $raw, $matches), 'Not a router line: ' . var_export($raw, true));
                $lines[] = ['text' => $matches[1], 'sentAt' => (int) $matches[2], 'readAt' => $readAt];
            }
        }

        return $lines;
    }

    private function nowMicroseconds(): int
    {
        return (int) (microtime(true) * 1_000_000);
    }

    /**
     * Start PHP's built-in web server on a free loopback port. Throws (erroring
     * every test of the class) if it cannot.
     */
    private static function startServer(): void
    {
        $logFile = tempnam(sys_get_temp_dir(), 'nr-vault-stream-server-');
        if ($logFile === false) {
            throw new RuntimeException('Could not create a log file for the streaming test server', 1790475801);
        }

        $hitsDirectory = $logFile . '-hits';
        mkdir($hitsDirectory, 0o700);

        self::$serverLogFile = $logFile;
        self::$hitsDirectory = $hitsDirectory;

        $environment = getenv();
        $environment['NR_VAULT_STREAM_HITS'] = $hitsDirectory;
        // Several workers: an abandoned stream keeps its worker busy until the
        // route's own loop ends, and must not block the next test's request.
        $environment['PHP_CLI_SERVER_WORKERS'] = '4';

        for ($attempt = 1; $attempt <= self::SERVER_START_ATTEMPTS; ++$attempt) {
            $port = self::findFreePort();
            // nosemgrep: php.lang.security.exec-use.exec-use - fixed argv (PHP_BINARY + test router), no shell
            $process = proc_open(
                [PHP_BINARY, '-d', 'xdebug.mode=off', '-S', self::LOOPBACK_HOST . ':' . $port, self::ROUTER_SCRIPT],
                [
                    0 => ['file', '/dev/null', 'r'],
                    1 => ['file', $logFile, 'a'],
                    2 => ['file', $logFile, 'a'],
                ],
                $pipes,
                null,
                $environment,
            );
            if (!\is_resource($process)) {
                continue;
            }

            self::$serverProcess = $process;
            $deadline = microtime(true) + self::SERVER_READY_TIMEOUT_SECONDS;
            while (microtime(true) < $deadline && proc_get_status($process)['running']) {
                if (self::isServing($port)) {
                    self::$serverPort = $port;

                    return;
                }

                usleep(50_000);
            }

            self::stopServer(keepFiles: true);
        }

        throw new RuntimeException(
            'The streaming test server did not start after ' . self::SERVER_START_ATTEMPTS
            . ' attempts. Server output: ' . file_get_contents($logFile),
            1790475802,
        );
    }

    private static function stopServer(bool $keepFiles = false): void
    {
        if (\is_resource(self::$serverProcess)) {
            proc_terminate(self::$serverProcess);
            proc_close(self::$serverProcess);
        }

        self::$serverProcess = null;
        self::$serverPort = 0;

        if ($keepFiles) {
            return;
        }

        if (self::$serverLogFile !== '' && file_exists(self::$serverLogFile)) {
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned temp file
            unlink(self::$serverLogFile);
        }

        if (self::$hitsDirectory !== '') {
            GeneralUtility::rmdir(self::$hitsDirectory, true);
        }
    }

    /**
     * Start one `tunnel-server.php` process and return the port it listens on.
     */
    private function startTunnelServer(string $mode, string ...$arguments): int
    {
        if (self::$tunnelDirectory === '') {
            self::$tunnelDirectory = self::$serverLogFile . '-tunnel-' . bin2hex(random_bytes(4));
            mkdir(self::$tunnelDirectory, 0o700);
        }

        $portFile = self::$tunnelDirectory . '/' . $mode . '.port';
        $logFile = self::$tunnelDirectory . '/' . $mode . '.out';
        // nosemgrep: php.lang.security.exec-use.exec-use - fixed argv (PHP_BINARY + test fixture), no shell
        $command = array_merge([PHP_BINARY, '-d', 'xdebug.mode=off', self::TUNNEL_SCRIPT, $portFile, $mode], array_values($arguments));
        $process = proc_open(
            $command,
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', $logFile, 'a'], 2 => ['file', $logFile, 'a']],
            $pipes,
        );
        self::assertIsResource($process);
        $this->tunnelProcesses[] = $process;

        $deadline = microtime(true) + self::SERVER_READY_TIMEOUT_SECONDS;
        while (!is_file($portFile) && microtime(true) < $deadline) {
            usleep(20_000);
        }

        self::assertFileExists($portFile, 'The ' . $mode . ' server did not start: ' . (is_file($logFile) ? (string) file_get_contents($logFile) : ''));

        return (int) file_get_contents($portFile);
    }

    /**
     * Whether the router answers on `$port`. Any other answer — a foreign
     * service that took the port in the meantime — does not count.
     */
    private static function isServing(int $port): bool
    {
        try {
            // Plain HTTP on loopback, readiness probe only. NOSONAR — test-only.
            $response = (new GuzzleClient([
                'timeout' => 2,
                'connect_timeout' => 1,
                'http_errors' => false,
                'allow_redirects' => false,
            ]))->request('GET', 'http://' . self::LOOPBACK_HOST . ':' . $port . '/ready'); // NOSONAR
        } catch (GuzzleException) {
            return false;
        }

        return $response->getStatusCode() === 200 && (string) $response->getBody() === 'ready';
    }

    /**
     * Merge `$values` into `$GLOBALS['TYPO3_CONF_VARS']['HTTP']`;
     * `backupGlobals` restores the setting after the test.
     *
     * @param array<string, mixed> $values
     */
    private function setHttpConfiguration(array $values): void
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($confVars);
        $httpConfig = $confVars['HTTP'] ?? [];
        self::assertIsArray($httpConfig);

        $confVars['HTTP'] = array_replace($httpConfig, $values);
        $GLOBALS['TYPO3_CONF_VARS'] = $confVars;
    }

    /**
     * Ask the kernel for an unused loopback port.
     */
    private static function findFreePort(): int
    {
        $socket = stream_socket_server('tcp://' . self::LOOPBACK_HOST . ':0', $errorCode, $errorMessage);
        if ($socket === false) {
            throw new RuntimeException('Could not reserve a loopback port: ' . $errorMessage, 1790475803);
        }

        $name = (string) stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr($name, (int) strrpos($name, ':') + 1);
    }
}

/**
 * A signal the test sets by hand.
 */
final class SwitchableSignal implements CancellationSignalInterface
{
    private bool $cancelled = false;

    public function cancel(): void
    {
        $this->cancelled = true;
    }

    public function isCancelled(): bool
    {
        return $this->cancelled;
    }
}
