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
use Netresearch\NrVault\Http\StreamingTransfer;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\Http\Fixtures\PinnedDnsResolver;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientExceptionInterface;
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

    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    /** @var resource|null */
    private static $serverProcess;

    private static int $serverPort = 0;

    private static string $serverLogFile = '';

    private static string $hitsDirectory = '';

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

    #[Test]
    public function theFirstBytesAreReadableBeforeTheServerHasFinished(): void
    {
        $client = $this->client();
        self::assertTrue($client->supportsStreaming(), 'A degraded blocking send would pass every content assertion below.');

        $response = $client->sendStreaming(new Request('GET', $this->url('/chunks?count=3&delay_ms=600')));
        $returnedAt = $this->nowMicroseconds();

        $body = $response->getBody();
        $lines = [];
        while (\count($lines) < 3) {
            $lines = [...$lines, ...$this->readLines($body)];
        }

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['chunk 1', 'chunk 2', 'chunk 3'], array_column($lines, 'text'));

        $lastSentAt = $lines[2]['sentAt'];
        self::assertLessThan(
            $lastSentAt,
            $returnedAt,
            'sendStreaming() must return at the headers, before the server has sent its last line.',
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

        $firstLine = $this->readLines($body);
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
        $this->readLines($body);
        self::assertSame(1, $this->activeTransfers($multi), 'The transfer is on the multi handle while it is read.');

        $body->close();

        self::assertSame(0, $this->activeTransfers($multi), 'close() before the end must remove and close the handle.');
    }

    #[Test]
    public function droppingTheBodyRemovesTheTransferFromTheMultiHandle(): void
    {
        [$client, $multi] = $this->clientWithObservableTransport();

        $response = $client->sendStreaming(new Request('GET', $this->url('/chunks?count=50&delay_ms=100')));
        $this->readLines($response->getBody());
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
        $this->readLines($body);

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
     * Read once, then split what arrived into the router's lines.
     *
     * @return list<array{text: string, sentAt: int, readAt: int}>
     */
    private function readLines(StreamInterface $body): array
    {
        $chunk = $body->read(8192);
        $readAt = $this->nowMicroseconds();

        $lines = [];
        foreach (explode("\n", trim($chunk)) as $raw) {
            if (preg_match('/^(.*) sent_us=(\d+)$/', $raw, $matches) !== 1) {
                continue;
            }

            $lines[] = ['text' => $matches[1], 'sentAt' => (int) $matches[2], 'readAt' => $readAt];
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
