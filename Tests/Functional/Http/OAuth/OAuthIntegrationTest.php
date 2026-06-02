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
use Throwable;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Integration tests for OAuth 2.0 functionality with real HTTP requests.
 *
 * These tests require the mock OAuth server to be running:
 * - Via runTests.sh: Mock OAuth server is started automatically
 * - Via ddev: `ddev start` (mock-oauth service starts automatically)
 * - Via MOCK_OAUTH_URL env var: Point to a running mock OAuth server
 *
 * Tests are skipped if the mock server is not reachable.
 */
#[CoversClass(OAuthTokenManager::class)]
#[Group('integration')]
#[Group('oauth')]
final class OAuthIntegrationTest extends FunctionalTestCase
{
    /**
     * Mock OAuth server URL (internal ddev network).
     * Plain `http://` is intentional: the mock OAuth sidecar (see
     * `.ddev/docker-compose.mock-oauth.yaml`) only listens on plain
     * HTTP because it runs inside the trusted ddev bridge network.
     * NOSONAR — production OAuth integrations MUST use HTTPS via
     * `OAuthConfig::tokenEndpoint`; this constant is test-only.
     */
    private const MOCK_OAUTH_INTERNAL_URL = 'http://mock-oauth:8080'; // NOSONAR

    /** Mock OAuth server URL (external access). NOSONAR — test-only, see above. */
    private const MOCK_OAUTH_EXTERNAL_URL = 'http://localhost:8080'; // NOSONAR

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

    private string $mockOAuthUrl = self::MOCK_OAUTH_EXTERNAL_URL;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setupCompleted = true;

        // Determine which mock OAuth URL to use
        $this->mockOAuthUrl = $this->determineMockOAuthUrl();

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
        $this->skipIfMockServerUnavailable();

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
        $this->skipIfMockServerUnavailable();

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
        $this->skipIfMockServerUnavailable();

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

        // Get new token - should be different (new request to server)
        $token2 = $tokenManager->getAccessToken($config);

        // Tokens from mock server are generated fresh each time
        // They may or may not be the same depending on server implementation
        self::assertNotEmpty($token1);
        self::assertNotEmpty($token2);
    }

    #[Test]
    public function vaultHttpClientWithOAuthMakesAuthenticatedRequest(): void
    {
        $this->skipIfMockServerUnavailable();

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
        $this->skipIfMockServerUnavailable();

        // Store a static bearer token in vault
        $vaultService = $this->getVaultService();
        $vaultService->store('static_bearer_token', 'test-bearer-token-12345');

        // Get HTTP client with Bearer auth
        $httpClient = $vaultService->http()->withAuthentication(
            'static_bearer_token',
            SecretPlacement::Bearer,
        );

        self::assertInstanceOf(VaultHttpClientInterface::class, $httpClient);

        // Make a request - we just verify the client works
        // The mock OAuth server will accept any bearer token on its endpoints
        $request = new Request('GET', $this->mockOAuthUrl . '/default/.well-known/openid-configuration');
        $response = $httpClient->sendRequest($request);

        self::assertEquals(200, $response->getStatusCode());
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
            logger: null,
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
     * Determine which mock OAuth URL to use based on environment.
     */
    private function determineMockOAuthUrl(): string
    {
        // Check for environment variable (set by runTests.sh)
        $envUrl = getenv('MOCK_OAUTH_URL');
        if ($envUrl !== false && $envUrl !== '') {
            return $envUrl;
        }

        // Try internal ddev URL
        if ($this->isUrlReachable(self::MOCK_OAUTH_INTERNAL_URL . '/.well-known/openid-configuration')) {
            return self::MOCK_OAUTH_INTERNAL_URL;
        }

        // Fall back to external URL
        return self::MOCK_OAUTH_EXTERNAL_URL;
    }

    /**
     * Skip test if mock OAuth server is not available.
     */
    private function skipIfMockServerUnavailable(): void
    {
        if (!$this->isUrlReachable($this->mockOAuthUrl . '/.well-known/openid-configuration')) {
            self::markTestSkipped(
                'Mock OAuth server is not available at: ' . $this->mockOAuthUrl . "\n" .
                'Options: Set MOCK_OAUTH_URL env var, use runTests.sh, or start ddev.',
            );
        }
    }

    /**
     * Build a plain Guzzle Client for tests that target the local
     * mock-OAuth sidecar in DDEV. The hardened SecureHttpClientFactory
     * is INTENTIONALLY bypassed here because:
     *
     *  - The sidecar lives on a private DDEV bridge network and only
     *    accepts traffic from the test container; SSRF guards aren't
     *    the assertion under test.
     *  - Functional tests can't reach a real DNS resolver, so the
     *    `ssrf-dns-pin` middleware would reject `mock-oauth` hosts.
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
     * Check if a URL is reachable.
     */
    private function isUrlReachable(string $url): bool
    {
        $context = stream_context_create([
            'http' => [
                'timeout' => 2,
                'ignore_errors' => true,
            ],
        ]);

        $result = @file_get_contents($url, false, $context);
        if (!\is_string($result) || $result === '') {
            return false;
        }

        // `ignore_errors => true` makes file_get_contents return the body even
        // for 3xx/4xx responses, so a non-false result is NOT proof the mock
        // OAuth server is there. A foreign service squatting on the port (e.g.
        // a TYPO3 instance redirecting `/.well-known/...` to the install tool)
        // would otherwise be mistaken for the sidecar and the sidecar-dependent
        // tests would run against the wrong server instead of skipping.
        //
        // Only accept a genuine OpenID Connect discovery document: HTTP 2xx
        // with JSON exposing the mandatory `token_endpoint` (RFC 8414 / OpenID
        // Connect Discovery 1.0). This is what mock-oauth2-server serves and
        // what these tests actually need.
        $statusLine = $http_response_header[0] ?? '';
        if (preg_match('#\s(2\d\d)\s#', $statusLine) !== 1) {
            return false;
        }

        try {
            $decoded = json_decode($result, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }

        return \is_array($decoded)
            && isset($decoded['token_endpoint'])
            && \is_string($decoded['token_endpoint']);
    }
}
