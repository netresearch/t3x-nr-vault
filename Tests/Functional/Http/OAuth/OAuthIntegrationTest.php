<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Http\OAuth;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use JsonException;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Domain\Dto\SecretDetails;
use Netresearch\NrVault\Exception\OAuthException;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Http\OAuth\OAuthTokenManager;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\VaultHttpClientInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use Throwable;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Integration tests for OAuth 2.0 functionality with real HTTP requests.
 *
 * The OAuth server is PHP's built-in web server running
 * `Fixtures/mock-oauth-router.php`, started once per class on a free loopback
 * port. Every request is a real HTTP round trip through Guzzle, so the tests
 * need no sidecar and run wherever PHP runs — including CI.
 *
 * Set MOCK_OAUTH_URL to aim the OAuth tests at another server instead, e.g. the
 * DDEV mock-oauth2-server (`http://mock-oauth:8080`). The embedded server still
 * starts: the bearer-token test needs its header echo endpoint.
 *
 * An unreachable server is a test failure, never a skip.
 */
#[CoversClass(OAuthTokenManager::class)]
#[Group('integration')]
#[Group('oauth')]
final class OAuthIntegrationTest extends FunctionalTestCase
{
    private const ROUTER_SCRIPT = __DIR__ . '/Fixtures/mock-oauth-router.php';

    private const LOOPBACK_HOST = '127.0.0.1';

    private const SERVER_START_ATTEMPTS = 3;

    private const SERVER_READY_TIMEOUT_SECONDS = 10;

    private const DEFAULT_TOKEN_PATH = '/default/token';

    private const CLIENT_CRED_TOKEN_URL = 'https://auth.example.com/token';

    private const DELETE_REASON_CLEANUP = 'test cleanup';

    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    protected array $coreExtensionsToLoad = [
        'backend',
    ];

    private ?VaultServiceInterface $vaultService = null;

    private ?string $masterKeyPath = null;

    private bool $setupCompleted = false;

    private string $mockOAuthUrl = '';

    /** @var resource|null */
    private static $serverProcess;

    private static string $embeddedServerUrl = '';

    private static string $serverLogFile = '';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();
        self::startEmbeddedServer();
    }

    public static function tearDownAfterClass(): void
    {
        self::stopEmbeddedServer();
        parent::tearDownAfterClass();
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->setupCompleted = true;

        $envUrl = getenv('MOCK_OAUTH_URL');
        $this->mockOAuthUrl = \is_string($envUrl) && $envUrl !== ''
            ? rtrim($envUrl, '/')
            : self::$embeddedServerUrl;

        // Create a temporary master key for testing
        $this->masterKeyPath = $this->instancePath . '/master.key';
        $masterKey = sodium_crypto_secretbox_keygen();
        file_put_contents($this->masterKeyPath, $masterKey);
        chmod($this->masterKeyPath, 0o600);

        // Configure extension to use file-based master key
        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault'] = [
            'masterKeySource' => $this->masterKeyPath,
            'autoKeyPath' => $this->masterKeyPath,
            'enableCache' => false,
            'auditHmacEpoch' => 1,
        ];

        // Import backend user for access control
        $this->importCSVDataSet(__DIR__ . '/Fixtures/be_users.csv');
        $this->setUpBackendUser(1);

        // Get properly wired service from container
        $service = $this->get(VaultServiceInterface::class);
        \assert($service instanceof VaultServiceInterface);
        $this->vaultService = $service;
    }

    protected function tearDown(): void
    {
        // Clean up master key
        if ($this->masterKeyPath !== null && file_exists($this->masterKeyPath)) {
            $content = file_get_contents($this->masterKeyPath);
            if ($content !== false) {
                sodium_memzero($content);
            }

            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
            unlink($this->masterKeyPath);
        }

        if ($this->setupCompleted) {
            parent::tearDown();
        }
    }

    #[Test]
    public function oauthTokenManagerAcquiresTokenWithClientCredentials(): void
    {
        $this->requireMockServer();

        // Store OAuth credentials in vault
        $vaultService = $this->getVaultService();
        $vaultService->store('test_oauth_client_id', 'test-client-id');
        $vaultService->store('test_oauth_client_secret', 'test-client-secret');

        // Create OAuth config
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: $this->mockOAuthUrl . self::DEFAULT_TOKEN_PATH,
            clientIdSecret: 'test_oauth_client_id',
            clientSecretSecret: 'test_oauth_client_secret',
            scopes: ['read', 'write'],
        );

        // Get token manager and acquire token
        $tokenManager = new OAuthTokenManager($vaultService, $this->buildTestClient(), new SecureHttpClientFactory());
        $accessToken = $tokenManager->getAccessToken($config);

        self::assertNotEmpty($accessToken);
    }

    #[Test]
    public function oauthTokenManagerCachesToken(): void
    {
        $this->requireMockServer();

        // Store OAuth credentials in vault
        $vaultService = $this->getVaultService();
        $vaultService->store('cache_oauth_client_id', 'test-client-id');
        $vaultService->store('cache_oauth_client_secret', 'test-client-secret');

        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: $this->mockOAuthUrl . self::DEFAULT_TOKEN_PATH,
            clientIdSecret: 'cache_oauth_client_id',
            clientSecretSecret: 'cache_oauth_client_secret',
        );

        $tokenManager = new OAuthTokenManager($vaultService, $this->buildTestClient(), new SecureHttpClientFactory());

        // First call - fetches from server
        $token1 = $tokenManager->getAccessToken($config);

        // Second call - should return cached token
        $token2 = $tokenManager->getAccessToken($config);

        self::assertSame($token1, $token2);
    }

    #[Test]
    public function oauthTokenManagerClearsCacheCorrectly(): void
    {
        $this->requireMockServer();

        // Store OAuth credentials in vault
        $vaultService = $this->getVaultService();
        $vaultService->store('clear_oauth_client_id', 'test-client-id');
        $vaultService->store('clear_oauth_client_secret', 'test-client-secret');

        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: $this->mockOAuthUrl . self::DEFAULT_TOKEN_PATH,
            clientIdSecret: 'clear_oauth_client_id',
            clientSecretSecret: 'clear_oauth_client_secret',
        );

        $tokenManager = new OAuthTokenManager($vaultService, $this->buildTestClient(), new SecureHttpClientFactory());

        // Get initial token
        $token1 = $tokenManager->getAccessToken($config);

        // Clear cache
        $tokenManager->clearCache($config);

        // Get new token - a new request to the server
        $token2 = $tokenManager->getAccessToken($config);

        // Both the embedded router and mock-oauth2-server (random `jti`) issue a
        // fresh token per request, so an unchanged token means the cache survived.
        self::assertNotEmpty($token1);
        self::assertNotSame($token1, $token2, 'clearCache() must force a new token request');
    }

    #[Test]
    public function vaultHttpClientWithOAuthMakesAuthenticatedRequest(): void
    {
        $this->requireMockServer();

        // Store OAuth credentials in vault
        $vaultService = $this->getVaultService();
        $vaultService->store('http_oauth_client_id', 'test-client-id');
        $vaultService->store('http_oauth_client_secret', 'test-client-secret');

        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: $this->mockOAuthUrl . self::DEFAULT_TOKEN_PATH,
            clientIdSecret: 'http_oauth_client_id',
            clientSecretSecret: 'http_oauth_client_secret',
        );

        // Get HTTP client with OAuth configured
        $httpClient = $vaultService->http()->withOAuth($config);

        self::assertInstanceOf(VaultHttpClientInterface::class, $httpClient);

        // Make a request to the mock server's userinfo endpoint
        // This verifies the OAuth token is properly injected
        $request = new Request('GET', $this->mockOAuthUrl . '/default/userinfo');
        $response = $httpClient->sendRequest($request);

        // Mock server should return 200 with valid token
        self::assertEquals(200, $response->getStatusCode());
    }

    #[Test]
    public function vaultHttpClientWithBearerTokenMakesAuthenticatedRequest(): void
    {
        $this->requireMockServer();

        // Store a static bearer token in vault
        $vaultService = $this->getVaultService();
        $vaultService->store('static_bearer_token', 'test-bearer-token-12345');

        // Get HTTP client with Bearer auth
        $httpClient = $vaultService->http()->withAuthentication(
            'static_bearer_token',
            SecretPlacement::Bearer,
        );

        self::assertInstanceOf(VaultHttpClientInterface::class, $httpClient);

        // The embedded server echoes the Authorization header it received, so the
        // assertion sees what actually went over the wire.
        $request = new Request('GET', self::$embeddedServerUrl . '/echo/authorization');
        $response = $httpClient->sendRequest($request);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(
            ['authorization' => 'Bearer test-bearer-token-12345'],
            json_decode((string) $response->getBody(), true, 4, JSON_THROW_ON_ERROR),
        );
    }

    #[Test]
    public function oauthConfigFactoryMethodsWork(): void
    {
        // Test client_credentials factory
        $clientCredConfig = OAuthConfig::clientCredentials(
            tokenEndpoint: self::CLIENT_CRED_TOKEN_URL,
            clientIdSecret: 'client_id_secret',
            clientSecretSecret: 'client_secret_secret',
            scopes: ['read', 'write'],
        );

        self::assertEquals('client_credentials', $clientCredConfig->grantType);
        self::assertEquals(self::CLIENT_CRED_TOKEN_URL, $clientCredConfig->tokenEndpoint);
        self::assertEquals('client_id_secret', $clientCredConfig->clientIdSecret);
        self::assertEquals('client_secret_secret', $clientCredConfig->clientSecretSecret);
        self::assertEquals(['read', 'write'], $clientCredConfig->scopes);
        self::assertEquals('read write', $clientCredConfig->getScopesString());

        // Test refresh_token factory
        $refreshConfig = OAuthConfig::refreshToken(
            tokenEndpoint: self::CLIENT_CRED_TOKEN_URL,
            clientIdSecret: 'client_id_secret',
            clientSecretSecret: 'client_secret_secret',
            refreshTokenSecret: 'refresh_token_secret',
            scopes: ['offline_access'],
        );

        self::assertEquals('refresh_token', $refreshConfig->grantType);
        self::assertEquals('refresh_token_secret', $refreshConfig->refreshTokenSecret);
    }

    #[Test]
    public function oauthSecretsAreNotLinkedInVault(): void
    {
        // This test documents the current limitation:
        // OAuth secrets are stored separately without semantic linking

        $vaultService = $this->getVaultService();
        $vaultService->store('my_app_oauth_client_id', 'client-123');
        $vaultService->store('my_app_oauth_client_secret', 'secret-456');
        $vaultService->store('my_app_oauth_refresh_token', 'refresh-789');

        // Each secret exists independently
        self::assertTrue($vaultService->exists('my_app_oauth_client_id'));
        self::assertTrue($vaultService->exists('my_app_oauth_client_secret'));
        self::assertTrue($vaultService->exists('my_app_oauth_refresh_token'));

        // Get metadata - SecretDetails DTO does not have 'type' or 'credentialSet' properties
        $clientIdMeta = $vaultService->getMetadata('my_app_oauth_client_id');
        $clientSecretMeta = $vaultService->getMetadata('my_app_oauth_client_secret');

        // SecretDetails DTO has no 'type' or 'credentialSet' property - they're not semantically linked
        // Verify we got valid metadata objects
        self::assertInstanceOf(SecretDetails::class, $clientIdMeta);
        self::assertInstanceOf(SecretDetails::class, $clientSecretMeta);
        self::assertSame('my_app_oauth_client_id', $clientIdMeta->identifier);
        self::assertSame('my_app_oauth_client_secret', $clientSecretMeta->identifier);

        // This is the documented limitation - see GitHub issue #15
    }

    /**
     * Regression test: when the OAuth server rejects the refresh_token with
     * HTTP 401, OAuthTokenManager must fall back to client_credentials rather
     * than propagating the failure to the caller. Both the failed refresh and
     * the subsequent fallback must be recorded in the audit log.
     *
     * The test drives OAuthTokenManager with a deterministic, in-process
     * PSR-18 client so it runs without the mock-oauth sidecar.
     */
    #[Test]
    public function oauthRefreshFailureFallsBackToClientCredentials(): void
    {
        $vaultService = $this->getVaultService();
        $auditService = $this->get(AuditLogServiceInterface::class);
        self::assertInstanceOf(AuditLogServiceInterface::class, $auditService);

        // Seed credentials in the vault.
        $vaultService->store('fallback_client_id', 'client-id-value');
        $vaultService->store('fallback_client_secret', 'client-secret-value');
        $vaultService->store('fallback_refresh_token', 'refresh-token-value');

        // A deterministic PSR-18 client that:
        //  - rejects the first request (refresh_token) with HTTP 401,
        //  - accepts the second request (client_credentials) with a valid token.
        //
        // We ALSO capture the grant_type sent in the body of each request so
        // we can assert the fallback grant switch actually happened.
        $capturedRequests = [];
        $call = 0;
        $httpClient = new class (
            $capturedRequests,
            $call,
        ) implements ClientInterface {
            /** @var list<array{grant_type: string, body: string}> */
            public array $capturedRequests;

            public int $call;

            /**
             * @param list<array{grant_type: string, body: string}> $capturedRequests
             */
            public function __construct(array &$capturedRequests, int &$call)
            {
                $this->capturedRequests = &$capturedRequests;
                $this->call = &$call;
            }

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $body = (string) $request->getBody();
                parse_str($body, $params);
                $grantType = \is_string($params['grant_type'] ?? null) ? $params['grant_type'] : '';

                $this->capturedRequests[] = [
                    'grant_type' => $grantType,
                    'body' => $body,
                ];
                $this->call++;

                if ($grantType === 'refresh_token') {
                    return new Response(
                        401,
                        ['Content-Type' => 'application/json'],
                        '{"error":"invalid_grant","error_description":"refresh token revoked"}',
                    );
                }

                // Successful client_credentials response.
                return new Response(
                    200,
                    ['Content-Type' => 'application/json'],
                    json_encode([
                        'access_token' => 'fallback-access-token',
                        'token_type' => 'Bearer',
                        'expires_in' => 3600,
                        'scope' => 'read',
                    ], JSON_THROW_ON_ERROR) ?: '',
                );
            }
        };

        $config = OAuthConfig::refreshToken(
            tokenEndpoint: 'https://auth.example.test/token',
            clientIdSecret: 'fallback_client_id',
            clientSecretSecret: 'fallback_client_secret',
            refreshTokenSecret: 'fallback_refresh_token',
            scopes: ['read'],
        );

        $tokenManager = new OAuthTokenManager(
            vaultService: $vaultService,
            httpClient: $httpClient,
            secureHttpClientFactory: new SecureHttpClientFactory(),
            auditLogService: $auditService,
        );

        $token = $tokenManager->getAccessToken($config);

        // Token came from the fallback client_credentials call.
        self::assertSame('fallback-access-token', $token);

        // Assert two HTTP calls happened: refresh first, then fallback.
        self::assertCount(
            2,
            $capturedRequests,
            'Manager must try refresh, then fall back to client_credentials',
        );
        self::assertSame('refresh_token', $capturedRequests[0]['grant_type']);
        self::assertSame('client_credentials', $capturedRequests[1]['grant_type']);

        // Audit log: both the failed refresh AND the fallback must be recorded.
        $refreshEntries = $auditService->query(
            AuditLogFilter::forAction('oauth_refresh_failed'),
        );
        $fallbackEntries = $auditService->query(
            AuditLogFilter::forAction('oauth_fallback_client_credentials'),
        );

        self::assertNotEmpty(
            $refreshEntries,
            'Failed refresh must be recorded in audit log',
        );
        self::assertNotEmpty(
            $fallbackEntries,
            'Fallback to client_credentials must be recorded in audit log',
        );

        $refreshForOurSecret = array_filter(
            $refreshEntries,
            static fn (AuditLogEntry $e): bool => $e->secretIdentifier === 'fallback_refresh_token',
        );
        self::assertNotEmpty(
            $refreshForOurSecret,
            'Failed refresh entry must reference the refresh-token identifier',
        );
        foreach ($refreshForOurSecret as $entry) {
            self::assertFalse(
                $entry->success,
                'Refresh failure entry must have success=false',
            );
        }

        $fallbackForOurSecret = array_filter(
            $fallbackEntries,
            static fn (AuditLogEntry $e): bool => $e->secretIdentifier === 'fallback_client_id',
        );
        self::assertNotEmpty(
            $fallbackForOurSecret,
            'Fallback entry must reference the client-id identifier',
        );
        foreach ($fallbackForOurSecret as $entry) {
            self::assertTrue(
                $entry->success,
                'Successful fallback must have success=true',
            );
        }

        // Cleanup
        $vaultService->delete('fallback_client_id', self::DELETE_REASON_CLEANUP);
        $vaultService->delete('fallback_client_secret', self::DELETE_REASON_CLEANUP);

        try {
            $vaultService->delete('fallback_refresh_token', self::DELETE_REASON_CLEANUP);
        } catch (Throwable) {
            // may have already been consumed
        }
    }

    /**
     * If the refresh fails AND the fallback client_credentials request ALSO
     * fails, the caller must see an OAuthException (no silent success).
     */
    #[Test]
    public function oauthRefreshFailureAndFallbackFailureBothPropagate(): void
    {
        $vaultService = $this->getVaultService();

        $vaultService->store('double_fail_client_id', 'id');
        $vaultService->store('double_fail_client_secret', 'secret');
        $vaultService->store('double_fail_refresh_token', 'refresh');

        $httpClient = new class () implements ClientInterface {
            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                // Both grant types fail.
                return new Response(
                    401,
                    ['Content-Type' => 'application/json'],
                    '{"error":"invalid_client"}',
                );
            }
        };

        $config = OAuthConfig::refreshToken(
            tokenEndpoint: 'https://auth.example.test/token',
            clientIdSecret: 'double_fail_client_id',
            clientSecretSecret: 'double_fail_client_secret',
            refreshTokenSecret: 'double_fail_refresh_token',
        );

        $tokenManager = new OAuthTokenManager(
            vaultService: $vaultService,
            httpClient: $httpClient,
            secureHttpClientFactory: new SecureHttpClientFactory(),
        );

        $this->expectException(OAuthException::class);

        try {
            $tokenManager->getAccessToken($config);
        } finally {
            // Cleanup even on failure
            $vaultService->delete('double_fail_client_id', self::DELETE_REASON_CLEANUP);
            $vaultService->delete('double_fail_client_secret', self::DELETE_REASON_CLEANUP);

            try {
                $vaultService->delete('double_fail_refresh_token', self::DELETE_REASON_CLEANUP);
            } catch (Throwable) {
                // ignore
            }
        }
    }

    /**
     * Get the vault service (asserts it's initialized).
     */
    private function getVaultService(): VaultServiceInterface
    {
        \assert($this->vaultService instanceof VaultServiceInterface);

        return $this->vaultService;
    }

    /**
     * Fail the test when the OAuth server does not answer. A skip here would
     * hide exactly the regression these tests exist to catch.
     */
    private function requireMockServer(): void
    {
        $discoveryUrl = $this->mockOAuthUrl . '/.well-known/openid-configuration';
        if (!self::isDiscoveryDocumentServed($discoveryUrl)) {
            self::fail('Mock OAuth server did not serve a discovery document at ' . $discoveryUrl);
        }

        $this->allowMockServerHosts();
    }

    /**
     * The SSRF guard refuses loopback and private addresses unless the operator
     * lists the host literally in `allowed_hosts` — the documented opt-in for
     * self-hosted endpoints. Opt the mock servers in for this test only;
     * backupGlobals restores the setting afterwards. Tests that do not talk to
     * a mock server keep the empty allowlist.
     */
    private function allowMockServerHosts(): void
    {
        $confVars = $GLOBALS['TYPO3_CONF_VARS'];
        self::assertIsArray($confVars);
        $httpConfig = $confVars['HTTP'] ?? [];
        self::assertIsArray($httpConfig);

        $httpConfig['allowed_hosts'] = array_values(array_unique([
            (string) parse_url($this->mockOAuthUrl, PHP_URL_HOST),
            self::LOOPBACK_HOST,
        ]));
        $confVars['HTTP'] = $httpConfig;
        $GLOBALS['TYPO3_CONF_VARS'] = $confVars;
    }

    /**
     * Start PHP's built-in web server with the mock OAuth router on a free
     * loopback port. Throws (erroring every test of the class) if it cannot.
     */
    private static function startEmbeddedServer(): void
    {
        $logFile = tempnam(sys_get_temp_dir(), 'nr-vault-mock-oauth-');
        if ($logFile === false) {
            throw new RuntimeException('Could not create a log file for the mock OAuth server', 1789000001);
        }

        self::$serverLogFile = $logFile;
        $environment = getenv();
        $environment['NR_VAULT_MOCK_OAUTH_SECRET'] = bin2hex(random_bytes(32));

        for ($attempt = 1; $attempt <= self::SERVER_START_ATTEMPTS; ++$attempt) {
            $address = self::LOOPBACK_HOST . ':' . self::findFreePort();
            // nosemgrep: php.lang.security.exec-use.exec-use - fixed argv (PHP_BINARY + test router), no shell
            $process = proc_open(
                [PHP_BINARY, '-d', 'xdebug.mode=off', '-S', $address, self::ROUTER_SCRIPT],
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
            // Plain HTTP on loopback: the built-in server cannot terminate TLS. NOSONAR — test-only.
            $url = 'http://' . $address; // NOSONAR
            $deadline = microtime(true) + self::SERVER_READY_TIMEOUT_SECONDS;
            while (microtime(true) < $deadline && proc_get_status($process)['running']) {
                if (self::isDiscoveryDocumentServed($url . '/.well-known/openid-configuration')) {
                    self::$embeddedServerUrl = $url;

                    return;
                }

                usleep(50_000);
            }

            // Port taken in the meantime, or the server died: try another port.
            self::stopEmbeddedServer(keepLog: true);
        }

        $log = (string) file_get_contents($logFile);

        throw new RuntimeException(
            'The embedded mock OAuth server did not start after ' . self::SERVER_START_ATTEMPTS
            . ' attempts. Server output: ' . $log,
            1789000002,
        );
    }

    private static function stopEmbeddedServer(bool $keepLog = false): void
    {
        if (\is_resource(self::$serverProcess)) {
            proc_terminate(self::$serverProcess);
            proc_close(self::$serverProcess);
        }

        self::$serverProcess = null;
        self::$embeddedServerUrl = '';

        if (!$keepLog && self::$serverLogFile !== '' && file_exists(self::$serverLogFile)) {
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned temp file
            unlink(self::$serverLogFile);
        }
    }

    /**
     * Ask the kernel for an unused loopback port.
     */
    private static function findFreePort(): int
    {
        $socket = stream_socket_server('tcp://' . self::LOOPBACK_HOST . ':0', $errorCode, $errorMessage);
        if ($socket === false) {
            throw new RuntimeException('Could not reserve a loopback port: ' . $errorMessage, 1789000003);
        }

        $name = (string) stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr($name, (int) strrpos($name, ':') + 1);
    }

    /**
     * Build a plain Guzzle Client for the token manager tests. The hardened
     * SecureHttpClientFactory transport is INTENTIONALLY bypassed here: the
     * SSRF middleware is not the assertion under test, and the token
     * manager still applies its own `isHostAllowed()` gate to the endpoint.
     *
     * Production OAuth flows always go through SecureHttpClientFactory
     * via VaultHttpClient::__construct (see PR #145). Do NOT copy this
     * pattern into unit tests or any production code path.
     */
    private function buildTestClient(): GuzzleClient
    {
        return new GuzzleClient([
            'timeout' => 10,         // hard cap so a stuck sidecar doesn't hang CI
            'connect_timeout' => 5,
            'http_errors' => false,  // OAuth manager handles non-2xx itself
        ]);
    }

    /**
     * Whether `$url` serves an OpenID Connect discovery document.
     *
     * Any answer is not enough: a foreign service squatting on the port (e.g. a
     * TYPO3 instance redirecting `/.well-known/...` to the install tool) must
     * not pass for the OAuth server. Only HTTP 200 with JSON exposing the
     * mandatory `token_endpoint` (RFC 8414 / OpenID Connect Discovery 1.0)
     * counts — what mock-oauth2-server and the embedded router both serve.
     */
    private static function isDiscoveryDocumentServed(string $url): bool
    {
        try {
            $response = (new GuzzleClient([
                'timeout' => 2,
                'connect_timeout' => 1,
                'http_errors' => false,
                'allow_redirects' => false,
            ]))->request('GET', $url);
        } catch (GuzzleException) {
            return false;
        }

        if ($response->getStatusCode() !== 200) {
            return false;
        }

        try {
            $decoded = json_decode((string) $response->getBody(), true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }

        return \is_array($decoded)
            && isset($decoded['token_endpoint'])
            && \is_string($decoded['token_endpoint']);
    }
}
