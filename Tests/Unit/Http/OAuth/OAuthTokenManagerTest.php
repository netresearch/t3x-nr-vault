<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http\OAuth;

use ArgumentCountError;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\OAuthException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Http\OAuth\OAuthTokenManager;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;
use ReflectionClass;
use RuntimeException;

#[CoversClass(OAuthTokenManager::class)]
#[AllowMockObjectsWithoutExpectations]
final class OAuthTokenManagerTest extends TestCase
{
    private OAuthTokenManager $subject;

    private VaultServiceInterface&MockObject $vaultService;

    private ClientInterface&MockObject $httpClient;

    private RequestFactoryInterface&MockObject $requestFactory;

    private StreamFactoryInterface&MockObject $streamFactory;

    private LoggerInterface&MockObject $logger;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->httpClient = $this->createMock(ClientInterface::class);
        $this->requestFactory = $this->createMock(RequestFactoryInterface::class);
        $this->streamFactory = $this->createMock(StreamFactoryInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);

        // Configure request factory to return a mock request
        $this->setupRequestFactory();

        $this->subject = new OAuthTokenManager(
            $this->vaultService,
            $this->httpClient,
            new SecureHttpClientFactory(),
            $this->logger,
            $this->requestFactory,
            $this->streamFactory,
        );
    }

    #[Test]
    public function getAccessTokenFetchesNewToken(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        $response = $this->createSuccessfulTokenResponse([
            'access_token' => 'new-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);

        $this->httpClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn($response);

        $token = $this->subject->getAccessToken($config);

        self::assertSame('new-access-token', $token);
    }

    #[Test]
    public function getAccessTokenReturnsCachedToken(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        $response = $this->createSuccessfulTokenResponse([
            'access_token' => 'cached-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);

        $this->httpClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn($response);

        // First call fetches token
        $token1 = $this->subject->getAccessToken($config);
        // Second call returns cached token (no HTTP request)
        $token2 = $this->subject->getAccessToken($config);

        self::assertSame('cached-token', $token1);
        self::assertSame('cached-token', $token2);
    }

    #[Test]
    public function getAccessTokenRefreshesExpiredToken(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );
        $config = new OAuthConfig(
            tokenEndpoint: $config->tokenEndpoint,
            clientIdSecret: $config->clientIdSecret,
            clientSecretSecret: $config->clientSecretSecret,
            tokenExpiryBuffer: 120, // 2 minute buffer
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        // First response: token expires in 60 seconds (within 120 second buffer)
        $response1 = $this->createSuccessfulTokenResponse([
            'access_token' => 'expiring-token',
            'token_type' => 'Bearer',
            'expires_in' => 60,
        ]);

        // Second response: new token
        $response2 = $this->createSuccessfulTokenResponse([
            'access_token' => 'refreshed-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);

        $this->httpClient
            ->expects(self::exactly(2))
            ->method('sendRequest')
            ->willReturnOnConsecutiveCalls($response1, $response2);

        // First call: gets expiring token
        $token1 = $this->subject->getAccessToken($config);
        // Second call: token within buffer, fetches new one
        $token2 = $this->subject->getAccessToken($config);

        self::assertSame('expiring-token', $token1);
        self::assertSame('refreshed-token', $token2);
    }

    #[Test]
    public function getAccessTokenThrowsForMissingClientId(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->with('oauth/client-id')
            ->willReturn(null);

        $this->expectException(SecretNotFoundException::class);

        $this->subject->getAccessToken($config);
    }

    #[Test]
    public function getAccessTokenThrowsForMissingClientSecret(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                default => null,
            });

        $this->expectException(SecretNotFoundException::class);

        $this->subject->getAccessToken($config);
    }

    #[Test]
    public function getAccessTokenThrowsForFailedRequest(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(401);

        $this->httpClient
            ->method('sendRequest')
            ->willReturn($response);

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('OAuth token request failed with status 401');

        $this->subject->getAccessToken($config);
    }

    #[Test]
    public function getAccessTokenThrowsForMissingAccessToken(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        $response = $this->createSuccessfulTokenResponse([
            'token_type' => 'Bearer',
            // Missing access_token
        ]);

        $this->httpClient
            ->method('sendRequest')
            ->willReturn($response);

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('OAuth response missing access_token');

        $this->subject->getAccessToken($config);
    }

    #[Test]
    public function getAccessTokenHandlesHttpException(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        $exception = new class ('Connection timeout') extends RuntimeException implements ClientExceptionInterface {};

        $this->httpClient
            ->method('sendRequest')
            ->willThrowException($exception);

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('OAuth token request failed: Connection timeout');

        $this->subject->getAccessToken($config);
    }

    #[Test]
    public function getAccessTokenIncludesScopes(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
            scopes: ['read', 'write'],
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        $response = $this->createSuccessfulTokenResponse([
            'access_token' => 'token-with-scope',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => 'read write',
        ]);

        $this->httpClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn($response);

        $token = $this->subject->getAccessToken($config);

        self::assertSame('token-with-scope', $token);
    }

    #[Test]
    public function clearCacheClearsSpecificConfig(): void
    {
        $config1 = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth1.example.com/token',
            clientIdSecret: 'oauth1/client-id',
            clientSecretSecret: 'oauth1/client-secret',
        );

        $config2 = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth2.example.com/token',
            clientIdSecret: 'oauth2/client-id',
            clientSecretSecret: 'oauth2/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth1/client-id' => 'client-1',
                'oauth1/client-secret' => 'secret-1',
                'oauth2/client-id' => 'client-2',
                'oauth2/client-secret' => 'secret-2',
                default => null,
            });

        $this->httpClient
            ->method('sendRequest')
            ->willReturn($this->createSuccessfulTokenResponse([
                'access_token' => 'token',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
            ]));

        // Populate cache
        $this->subject->getAccessToken($config1);
        $this->subject->getAccessToken($config2);

        // Clear only config1
        $this->subject->clearCache($config1);

        // config2 should still be cached (only 3 requests total)
        $this->httpClient
            ->expects(self::exactly(1))
            ->method('sendRequest');

        $this->subject->getAccessToken($config1); // New request
    }

    #[Test]
    public function clearCacheClearsAllConfigs(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        $this->httpClient
            ->expects(self::exactly(2))
            ->method('sendRequest')
            ->willReturn($this->createSuccessfulTokenResponse([
                'access_token' => 'token',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
            ]));

        // First call: fetch
        $this->subject->getAccessToken($config);

        // Clear all
        $this->subject->clearCache();

        // Second call: fetch again (not from cache)
        $this->subject->getAccessToken($config);
    }

    #[Test]
    public function getAccessTokenThrowsForInvalidJsonResponse(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        // Create response with invalid JSON
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn('not valid json {');

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getBody')->willReturn($stream);

        $this->httpClient
            ->method('sendRequest')
            ->willReturn($response);

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('Invalid JSON response from OAuth server');

        $this->subject->getAccessToken($config);
    }

    #[Test]
    public function getAccessTokenUsesRefreshTokenGrant(): void
    {
        $config = new OAuthConfig(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
            grantType: 'refresh_token',
            refreshTokenSecret: 'oauth/refresh-token',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                'oauth/refresh-token' => 'my-refresh-token',
                default => null,
            });

        $response = $this->createSuccessfulTokenResponse([
            'access_token' => 'refreshed-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);

        $this->httpClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn($response);

        $token = $this->subject->getAccessToken($config);

        self::assertSame('refreshed-access-token', $token);
    }

    #[Test]
    public function getAccessTokenThrowsForMissingRefreshToken(): void
    {
        $config = new OAuthConfig(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
            grantType: 'refresh_token',
            refreshTokenSecret: 'oauth/refresh-token',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                // refresh token returns null
                default => null,
            });

        $this->expectException(SecretNotFoundException::class);

        $this->subject->getAccessToken($config);
    }

    #[Test]
    public function getAccessTokenStoresNewRefreshToken(): void
    {
        $config = new OAuthConfig(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
            refreshTokenSecret: 'oauth/refresh-token',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        // Expect store to be called with new refresh token
        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->with(
                'oauth/refresh-token',
                'new-refresh-token',
                self::callback(fn (array $meta): bool => $meta['source'] === 'oauth_refresh'),
            );

        $response = $this->createSuccessfulTokenResponse([
            'access_token' => 'new-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'new-refresh-token',
        ]);

        $this->httpClient
            ->method('sendRequest')
            ->willReturn($response);

        $token = $this->subject->getAccessToken($config);

        self::assertSame('new-access-token', $token);
    }

    #[Test]
    public function getAccessTokenUsesDefaultExpiresIn(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        // Response without expires_in - should default to 3600
        $response = $this->createSuccessfulTokenResponse([
            'access_token' => 'token-without-expiry',
            'token_type' => 'Bearer',
            // No expires_in
        ]);

        $this->httpClient
            ->method('sendRequest')
            ->willReturn($response);

        $token = $this->subject->getAccessToken($config);

        self::assertSame('token-without-expiry', $token);
    }

    #[Test]
    public function getAccessTokenUsesDefaultTokenType(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        // Response without token_type - should default to Bearer
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn(json_encode([
            'access_token' => 'token-without-type',
            // No token_type
        ]));

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getBody')->willReturn($stream);

        $this->httpClient
            ->method('sendRequest')
            ->willReturn($response);

        $token = $this->subject->getAccessToken($config);

        self::assertSame('token-without-type', $token);
    }

    #[Test]
    public function getAccessTokenIncludesAdditionalParams(): void
    {
        $config = new OAuthConfig(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
            additionalParams: ['audience' => 'https://api.example.com'],
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        $response = $this->createSuccessfulTokenResponse([
            'access_token' => 'token-with-audience',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);

        $this->httpClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn($response);

        $token = $this->subject->getAccessToken($config);

        self::assertSame('token-with-audience', $token);
    }

    #[Test]
    public function getAccessTokenWithExpiryAtNowIsConsideredExpired(): void
    {
        // Token expiry = now (or slightly in the past), buffer = 0 → should be refreshed
        $config = new OAuthConfig(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
            tokenExpiryBuffer: 0,
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        // First response: token expires in 0 seconds (already expired)
        $response1 = $this->createSuccessfulTokenResponse([
            'access_token' => 'first-token',
            'token_type' => 'Bearer',
            'expires_in' => 0,
        ]);
        // Second response: fresh token
        $response2 = $this->createSuccessfulTokenResponse([
            'access_token' => 'second-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
        ]);

        $this->httpClient
            ->expects(self::exactly(2))
            ->method('sendRequest')
            ->willReturnOnConsecutiveCalls($response1, $response2);

        $token1 = $this->subject->getAccessToken($config);
        $token2 = $this->subject->getAccessToken($config);

        self::assertSame('first-token', $token1);
        self::assertSame('second-token', $token2);
    }

    #[Test]
    public function clearTokenClearsAllCachedTokens(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        $this->httpClient
            ->expects(self::exactly(2))
            ->method('sendRequest')
            ->willReturn($this->createSuccessfulTokenResponse([
                'access_token' => 'some-token',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
            ]));

        // Populate cache
        $this->subject->getAccessToken($config);

        // Clear token (separate from clearCache)
        $this->subject->clearToken();

        // Should fetch again after clear
        $this->subject->getAccessToken($config);
    }

    #[Test]
    public function getAccessTokenWithRefreshTokenGrantStoresNewRefreshTokenWhenProvided(): void
    {
        $config = OAuthConfig::refreshToken(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
            refreshTokenSecret: 'oauth/refresh-token',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                'oauth/refresh-token' => 'old-refresh-token',
                default => null,
            });

        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->with(
                'oauth/refresh-token',
                'new-refresh-token',
                self::callback(fn (array $meta): bool => $meta['source'] === 'oauth_refresh'),
            );

        $response = $this->createSuccessfulTokenResponse([
            'access_token' => 'new-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'new-refresh-token',
        ]);

        $this->httpClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn($response);

        $token = $this->subject->getAccessToken($config);

        self::assertSame('new-access-token', $token);
    }

    #[Test]
    public function getAccessTokenReturnsAccessTokenEvenWhenRefreshTokenStorageFails(): void
    {
        // If the OAuth response includes a new refresh_token but `vaultService
        // ->store()` throws (DB down, audit lock failed, etc.), the manager
        // must NOT propagate. The OAuth server has already issued the new
        // tokens and (per RFC 6749 §6) typically invalidated the old refresh
        // token — propagating the throw would also lose the access_token we
        // just obtained. The caller's current request succeeds; the next
        // refresh attempt will fall back to client_credentials.
        $config = OAuthConfig::refreshToken(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
            refreshTokenSecret: 'oauth/refresh-token',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                'oauth/refresh-token' => 'old-refresh-token',
                default => null,
            });

        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->willThrowException(new RuntimeException('vault write failed mid-OAuth-refresh'));

        $response = $this->createSuccessfulTokenResponse([
            'access_token' => 'new-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'new-refresh-token',
        ]);

        $this->httpClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn($response);

        // The logger must report the storage failure at error level so ops
        // can notice and remediate.
        $this->logger
            ->expects(self::atLeastOnce())
            ->method('error')
            ->with(self::stringContains('vault store failed'));

        $token = $this->subject->getAccessToken($config);

        self::assertSame('new-access-token', $token, 'Access token must reach the caller even when vault store fails');
    }

    #[Test]
    public function getAccessTokenSurvivesAuditLogFailureDuringStorageFailure(): void
    {
        // Both `vaultService->store()` AND `auditLogService->log()` throw —
        // mimicking a full DB outage. The caller must still receive the
        // just-obtained access_token; neither secondary failure may
        // propagate.
        $auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $auditLogService
            ->expects(self::once())
            ->method('log')
            ->willThrowException(new RuntimeException('audit log also down'));

        $subject = new OAuthTokenManager(
            $this->vaultService,
            $this->httpClient,
            new SecureHttpClientFactory(),
            $this->logger,
            $this->requestFactory,
            $this->streamFactory,
            $auditLogService,
        );

        $config = OAuthConfig::refreshToken(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
            refreshTokenSecret: 'oauth/refresh-token',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                'oauth/refresh-token' => 'old-refresh-token',
                default => null,
            });
        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->willThrowException(new RuntimeException('vault write failed'));

        $this->httpClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn($this->createSuccessfulTokenResponse([
                'access_token' => 'new-access-token',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => 'new-refresh-token',
            ]));

        // No exception should reach the test — caller must get access_token.
        $token = $subject->getAccessToken($config);

        self::assertSame('new-access-token', $token);
    }

    #[Test]
    public function getAccessTokenHashesVaultIdentifierInLogContext(): void
    {
        // The refresh-token secret PATH (vault identifier) is semi-sensitive —
        // it reveals which secrets the system uses. Log it as a short hash, not
        // the raw path.
        $config = OAuthConfig::refreshToken(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
            refreshTokenSecret: 'oauth/refresh-token-sensitive-path',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                'oauth/refresh-token-sensitive-path' => 'old-refresh-token',
                default => null,
            });
        $this->vaultService
            ->expects(self::once())
            ->method('store')
            ->willThrowException(new RuntimeException('vault write failed'));

        $this->httpClient
            ->method('sendRequest')
            ->willReturn($this->createSuccessfulTokenResponse([
                'access_token' => 'new-access-token',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => 'new-refresh-token',
            ]));

        $loggedContext = null;
        $this->logger
            ->expects(self::atLeastOnce())
            ->method('error')
            ->willReturnCallback(function (string $message, array $context = []) use (&$loggedContext): void {
                $loggedContext = $context;
            });

        $this->subject->getAccessToken($config);

        self::assertIsArray($loggedContext);
        self::assertArrayHasKey('refresh_token_secret_hash', $loggedContext);
        self::assertArrayNotHasKey('refresh_token_secret', $loggedContext);
        // The hash must be 16 hex chars (16-char prefix of sha256).
        self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/', (string) $loggedContext['refresh_token_secret_hash']);
        // The full path must NOT appear anywhere in the context.
        $contextString = var_export($loggedContext, true);
        self::assertStringNotContainsString('sensitive-path', $contextString);
    }

    #[Test]
    public function getAccessTokenWithNoRefreshTokenSecretConfigDoesNotStoreRefreshToken(): void
    {
        // refreshTokenSecret = null → even if response contains refresh_token, do not store
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: 'https://auth.example.com/token',
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $this->vaultService
            ->method('retrieve')
            ->willReturnCallback(fn (string $id): ?string => match ($id) {
                'oauth/client-id' => 'my-client-id',
                'oauth/client-secret' => 'my-client-secret',
                default => null,
            });

        $this->vaultService->expects(self::never())->method('store');

        $response = $this->createSuccessfulTokenResponse([
            'access_token' => 'new-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'should-not-be-stored',
        ]);

        $this->httpClient
            ->method('sendRequest')
            ->willReturn($response);

        $token = $this->subject->getAccessToken($config);

        self::assertSame('new-access-token', $token);
    }

    /**
     * Regression guard: the `httpClient` constructor parameter MUST be
     * required (no default value). The previous default
     * `new GuzzleHttp\Client(['timeout' => 30, ...])` silently bypassed
     * `SecureHttpClientFactory`'s SSRF / DNS-rebinding / no-redirect
     * defences; callers could forget to inject and OAuth token endpoints
     * would reach internal IPs unchecked. See PR #145 / the OAuth client
     * unification follow-up to PR #144.
     *
     * Behavioural assertion (not `ReflectionParameter::isOptional()`):
     * a future refactor could declare `?ClientInterface $httpClient = null`
     * + a body `?? new Client()` — `isOptional()` would return true while
     * the security regression returns. Constructing without the argument
     * MUST throw `ArgumentCountError` instead.
     */
    #[Test]
    public function constructorRequiresHttpClient(): void
    {
        $this->expectException(ArgumentCountError::class);

        // assertInstanceOf is unreachable (ctor throws before returning) but
        // uses the constructed value so Sonar's S1848 ("useless object
        // instantiation") doesn't fire on this throws-from-ctor test.
        self::assertInstanceOf(
            OAuthTokenManager::class,
            /** @phpstan-ignore arguments.count (intentional — proves the parameter is required) */
            new OAuthTokenManager($this->vaultService),
        );
    }

    /**
     * Security gate: the `tokenEndpoint` host MUST pass
     * `SecureHttpClientFactory::isHostAllowed()` BEFORE the request body
     * (containing the bearer `client_secret`) is built. The request-time
     * middleware already rejects dangerous IPs, but the `allowed_hosts`
     * allowlist is per-host and must apply to OAuth too.
     */
    #[Test]
    public function dispatchTokenRequestRejectsHostNotInAllowedHostsList(): void
    {
        $originalGlobals = $GLOBALS['TYPO3_CONF_VARS'] ?? null;
        $GLOBALS['TYPO3_CONF_VARS'] = [
            'HTTP' => ['allowed_hosts' => ['only.this.example.com']],
        ];

        try {
            $config = OAuthConfig::clientCredentials(
                tokenEndpoint: 'https://elsewhere.example/token',
                clientIdSecret: 'oauth/client-id',
                clientSecretSecret: 'oauth/client-secret',
            );

            $this->vaultService
                ->method('retrieve')
                ->willReturnCallback(fn (string $id): string => match ($id) {
                    'oauth/client-id' => 'cid',
                    'oauth/client-secret' => 'csec',
                    default => '',
                });

            // The middleware on $httpClient would also block — but the gate
            // we're testing runs first, BEFORE the request is built and
            // sent, so sendRequest must NEVER be called.
            $this->httpClient
                ->expects(self::never())
                ->method('sendRequest');

            $this->expectException(OAuthException::class);
            $this->expectExceptionMessageMatches('/not in the allowed hosts list/i');

            $this->subject->getAccessToken($config);
        } finally {
            if ($originalGlobals !== null) {
                $GLOBALS['TYPO3_CONF_VARS'] = $originalGlobals;
            } else {
                unset($GLOBALS['TYPO3_CONF_VARS']);
            }
        }
    }

    /**
     * Security gate: `redactCredentials()` must scrub bearer / basic auth /
     * client_secret / refresh_token from upstream error messages before they
     * reach the logger, audit log, or OAuthException. Cheap defence against
     * a future OAuth server (or refactor) that echoes credentials back in
     * its error responses.
     */
    #[Test]
    #[DataProvider('credentialPatternsProvider')]
    public function redactCredentialsScrubsKnownPatterns(string $raw, string $expected): void
    {
        // `redactCredentials` is private; invoke via reflection. Handles
        // both static and instance method forms so cgl / rector can flip
        // it freely without breaking the regression guard.
        $method = (new ReflectionClass(OAuthTokenManager::class))->getMethod('redactCredentials');
        $target = $method->isStatic() ? null : $this->subject;
        self::assertSame($expected, $method->invoke($target, $raw));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function credentialPatternsProvider(): iterable
    {
        yield 'client_secret in form body' => [
            'POST /token grant_type=client_credentials&client_secret=topSecr3t&scope=read',
            'POST /token grant_type=client_credentials&client_secret=[REDACTED]&scope=read',
        ];
        yield 'refresh_token in form body' => [
            'grant_type=refresh_token&refresh_token=eyJabc.def.ghi&scope=read',
            'grant_type=refresh_token&refresh_token=[REDACTED]&scope=read',
        ];
        yield 'Bearer Authorization header' => [
            'response headers: Authorization: Bearer abc123def456 — rejected',
            'response headers: Authorization: Bearer [REDACTED] — rejected',
        ];
        yield 'Basic Authorization header' => [
            'sent: Authorization: Basic dXNlcjpwYXNz== to endpoint',
            'sent: Authorization: Basic [REDACTED] to endpoint',
        ];
        yield 'mixed multiple credentials' => [
            'client_secret=abc&refresh_token=def — Authorization: Bearer xyz',
            'client_secret=[REDACTED]&refresh_token=[REDACTED] — Authorization: Bearer [REDACTED]',
        ];
        yield 'case-insensitive Authorization header' => [
            'authorization: bearer ABC123',
            'authorization: bearer [REDACTED]',
        ];
        yield 'safe message passes through' => [
            'Connection refused (timeout after 10s)',
            'Connection refused (timeout after 10s)',
        ];
    }

    private function setupRequestFactory(): void
    {
        $mockStream = $this->createMock(StreamInterface::class);
        $this->streamFactory
            ->method('createStream')
            ->willReturn($mockStream);

        $mockRequest = $this->createMock(RequestInterface::class);
        $mockRequest->method('withHeader')->willReturnSelf();
        $mockRequest->method('withBody')->willReturnSelf();

        $this->requestFactory
            ->method('createRequest')
            ->willReturn($mockRequest);
    }

    private function createSuccessfulTokenResponse(array $data): ResponseInterface&MockObject
    {
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('__toString')->willReturn(json_encode($data));

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getBody')->willReturn($stream);

        return $response;
    }
}
