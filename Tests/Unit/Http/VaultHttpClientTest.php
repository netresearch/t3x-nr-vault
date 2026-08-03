<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use Exception;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Netresearch\NrVault\Audit\AuditContextInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HttpCallContext;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Http\OAuth\OAuthTokenManager;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use ReflectionClass;

#[CoversClass(VaultHttpClient::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultHttpClientTest extends TestCase
{
    use GuzzleClientConfigTrait;

    private const API_URL = 'https://api.example.com/data';

    private const TOKEN_ENDPOINT = 'https://auth.example.com/token';

    private const CONTENT_TYPE_JSON = 'application/json';

    private const NON_OBJECT_BODY_MESSAGE = 'request body must be a JSON object';

    /** @phpstan-ignore property.uninitialized */
    private VaultServiceInterface&MockObject $vaultService;

    /** @phpstan-ignore property.uninitialized */
    private AuditLogServiceInterface&MockObject $auditLogService;

    /** @phpstan-ignore property.uninitialized */
    private ClientInterface&MockObject $innerClient;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $this->innerClient = $this->createMock(ClientInterface::class);
    }

    #[Test]
    public function implementsClientInterface(): void
    {
        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        self::assertInstanceOf(ClientInterface::class, $client);
    }

    #[Test]
    public function sendRequestWithoutAuthPassesRequestUnmodified(): void
    {
        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                self::assertFalse($request->hasHeader('Authorization'));

                return new Response(200);
            });

        $this->auditLogService
            ->expects(self::once())
            ->method('log');

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $request = new Request('GET', self::API_URL);
        $response = $client->sendRequest($request);

        self::assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function withAuthenticationReturnNewInstance(): void
    {
        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::Bearer);

        self::assertNotSame($client, $authenticatedClient);
        self::assertInstanceOf(VaultHttpClient::class, $authenticatedClient);
    }

    #[Test]
    public function withAuthenticationInjectsBearerToken(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('secret-token-123');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                self::assertSame('Bearer secret-token-123', $request->getHeaderLine('Authorization'));

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::Bearer);

        $request = new Request('GET', self::API_URL);
        $response = $authenticatedClient->sendRequest($request);

        self::assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function withAuthenticationInjectsApiKeyHeader(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('key-abc-123');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                self::assertSame('key-abc-123', $request->getHeaderLine('X-API-Key'));

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::ApiKey);

        $request = new Request('GET', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationInjectsCustomHeader(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('custom-value');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                self::assertSame('custom-value', $request->getHeaderLine('X-Custom-Auth'));

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication(
            'my_api_key',
            SecretPlacement::Header,
            ['headerName' => 'X-Custom-Auth'],
        );

        $request = new Request('GET', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationAppliesSchemePrefixToHeader(): void
    {
        // FAL/DeepL-style "Authorization: <scheme> <secret>" schemes that Bearer can't express.
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('fal-secret');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                self::assertSame('Key fal-secret', $request->getHeaderLine('Authorization'));

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication(
            'my_api_key',
            SecretPlacement::Header,
            ['headerName' => 'Authorization', 'prefix' => 'Key '],
        );

        $request = new Request('GET', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationInjectsBasicAuthFromCombinedSecret(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_credentials')
            ->willReturn('user:pass123');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                $expected = 'Basic ' . base64_encode('user:pass123');
                self::assertSame($expected, $request->getHeaderLine('Authorization'));

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_credentials', SecretPlacement::BasicAuth);

        $request = new Request('GET', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationInjectsBasicAuthFromSeparateSecrets(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturnMap([
                ['my_username', 'john_doe'],
                ['my_password', 'secret123'],
            ]);

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                $expected = 'Basic ' . base64_encode('john_doe:secret123');
                self::assertSame($expected, $request->getHeaderLine('Authorization'));

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication(
            'my_password',
            SecretPlacement::BasicAuth,
            ['usernameSecret' => 'my_username'],
        );

        $request = new Request('GET', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationInjectsQueryParam(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('query-key-value');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                self::assertStringContainsString('api_key=query-key-value', $request->getUri()->getQuery());

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::QueryParam);

        $request = new Request('GET', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationInjectsCustomQueryParam(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('token123');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                self::assertStringContainsString('access_token=token123', $request->getUri()->getQuery());

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication(
            'my_api_key',
            SecretPlacement::QueryParam,
            ['queryParam' => 'access_token'],
        );

        $request = new Request('GET', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationAppendsToExistingQueryParams(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('key123');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                $query = $request->getUri()->getQuery();
                self::assertStringContainsString('existing=value', $query);
                self::assertStringContainsString('api_key=key123', $query);

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::QueryParam);

        $request = new Request('GET', 'https://api.example.com/data?existing=value');
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function sendRequestThrowsOnMissingSecret(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('nonexistent_key')
            ->willReturn(null);

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('nonexistent_key', SecretPlacement::Bearer);

        $request = new Request('GET', self::API_URL);

        $this->expectException(SecretNotFoundException::class);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withReasonSetsAuditReason(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('secret');

        $this->innerClient
            ->method('sendRequest')
            ->willReturn(new Response(200));

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->willReturnCallback(function (
                string $identifier,
                string $action,
                bool $success,
                ?string $error,
                string $reason,
            ): void {
                self::assertSame('Custom audit reason', $reason);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client
            ->withAuthentication('my_key', SecretPlacement::Bearer)
            ->withReason('Custom audit reason');

        $request = new Request('GET', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withTimeoutReturnsNewInstanceAndLeavesOriginalUntouched(): void
    {
        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturn(new Response(200));

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $timeoutClient = $client->withTimeout(300);

        self::assertNotSame($client, $timeoutClient);
        self::assertInstanceOf(VaultHttpClient::class, $timeoutClient);

        // The original instance still sends through the injected inner client.
        $response = $client->sendRequest(new Request('GET', self::API_URL));
        self::assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function withTimeoutAppliesOverrideToInnerClientOptions(): void
    {
        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $config = $this->getInnerGuzzleConfig($client->withTimeout(300));

        self::assertSame(300, $config['timeout']);
    }

    #[Test]
    #[DataProvider('nonPositiveTimeoutProvider')]
    public function withTimeoutNonPositiveFallsBackToPlatformDefault(int $seconds): void
    {
        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $platformConfig = $this->getGuzzleConfig((new SecureHttpClientFactory())->create());
        $config = $this->getInnerGuzzleConfig($client->withTimeout($seconds));

        self::assertSame($platformConfig['timeout'], $config['timeout']);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function nonPositiveTimeoutProvider(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-300];
    }

    #[Test]
    public function withTimeoutSurvivesSubsequentWitherCalls(): void
    {
        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $chained = $client
            ->withTimeout(300)
            ->withAuthentication('my_key', SecretPlacement::Bearer)
            ->withReason('Long-running generation');

        $config = $this->getInnerGuzzleConfig($chained);

        self::assertSame(300, $config['timeout']);
    }

    #[Test]
    public function withTimeoutPreservesAuthenticationConfiguration(): void
    {
        $client = (new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        ))
            ->withAuthentication('my_key', SecretPlacement::Bearer, ['reason' => 'API call'])
            ->withTimeout(300);

        $reflection = new ReflectionClass(VaultHttpClient::class);

        self::assertSame('my_key', $reflection->getProperty('secretIdentifier')->getValue($client));
        self::assertSame(SecretPlacement::Bearer, $reflection->getProperty('placement')->getValue($client));
        self::assertSame('API call', $reflection->getProperty('reason')->getValue($client));
    }

    #[Test]
    public function sendRequestPreservesOriginalRequestHeaders(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('token');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                // Original headers should be preserved
                self::assertSame(self::CONTENT_TYPE_JSON, $request->getHeaderLine('Content-Type'));
                self::assertSame('CustomAgent', $request->getHeaderLine('User-Agent'));
                // Auth header should be added
                self::assertSame('Bearer token', $request->getHeaderLine('Authorization'));

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_key', SecretPlacement::Bearer);

        $request = new Request('POST', self::API_URL, [
            'Content-Type' => self::CONTENT_TYPE_JSON,
            'User-Agent' => 'CustomAgent',
        ]);

        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function auditLogsSuccessfulRequest(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('secret');

        $this->innerClient
            ->method('sendRequest')
            ->willReturn(new Response(201));

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->willReturnCallback(function (
                string $identifier,
                string $action,
                bool $success,
                ?string $error,
                ?string $reason,
                ?string $hashBefore,
                ?string $hashAfter,
                ?AuditContextInterface $context,
            ): void {
                self::assertSame('my_key', $identifier);
                self::assertSame('http_call', $action);
                self::assertTrue($success);
                self::assertNull($error);
                self::assertInstanceOf(HttpCallContext::class, $context);
                self::assertSame('POST', $context->method);
                self::assertSame(201, $context->statusCode);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_key', SecretPlacement::Bearer);

        $request = new Request('POST', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function fluentChainingWorks(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('secret');

        $this->innerClient
            ->method('sendRequest')
            ->willReturn(new Response(200));

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        // Should be able to chain fluently
        $response = $client
            ->withAuthentication('my_key', SecretPlacement::Bearer)
            ->withReason('API call for order processing')
            ->sendRequest(new Request('GET', 'https://api.example.com'));

        self::assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function withAuthenticationInjectsBodyFieldJson(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('secret-value');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                $body = (string) $request->getBody();
                $decoded = json_decode($body, true);
                self::assertSame('secret-value', $decoded['api_key']);
                self::assertSame('existing', $decoded['field']);

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::BodyField);

        $request = new Request('POST', self::API_URL, [
            'Content-Type' => self::CONTENT_TYPE_JSON,
        ], json_encode(['field' => 'existing']));

        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationInjectsBodyFieldFormData(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_secret')
            ->willReturn('form-secret');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                $body = (string) $request->getBody();
                parse_str($body, $data);
                self::assertSame('form-secret', $data['api_key']);
                self::assertSame('existing_value', $data['other_field']);

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_secret', SecretPlacement::BodyField);

        $request = new Request('POST', self::API_URL, [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ], 'other_field=existing_value');

        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationInjectsCustomBodyField(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('secret-token');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                $body = (string) $request->getBody();
                $decoded = json_decode($body, true);
                self::assertSame('secret-token', $decoded['access_token']);

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication(
            'my_api_key',
            SecretPlacement::BodyField,
            ['bodyField' => 'access_token'],
        );

        $request = new Request('POST', self::API_URL, [
            'Content-Type' => self::CONTENT_TYPE_JSON,
        ], '{}');

        $authenticatedClient->sendRequest($request);
    }

    /**
     * A JSON request body that decodes to a list (not an object) cannot carry a
     * named secret field. The old code did `$data[$field] = ...` on the list,
     * silently reshaping it into a mixed-key structure. Reject it deterministically.
     */
    #[Test]
    public function injectBodyFieldRejectsJsonArrayBody(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('secret-value');

        // The malformed body must be rejected BEFORE any HTTP call is made.
        $this->innerClient
            ->expects(self::never())
            ->method('sendRequest');

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::BodyField);

        $request = new Request('POST', self::API_URL, [
            'Content-Type' => self::CONTENT_TYPE_JSON,
        ], json_encode([1, 2, 3]));

        $this->expectException(VaultException::class);
        $this->expectExceptionMessageToContain(self::NON_OBJECT_BODY_MESSAGE);

        $authenticatedClient->sendRequest($request);
    }

    /**
     * A scalar JSON body (`"value"`, `42`, `true`) is even worse — the old
     * `$data[$field] = ...` on a string/int would fatally error after the
     * secret was already retrieved. Reject it with a clear exception instead.
     */
    #[Test]
    public function injectBodyFieldRejectsJsonScalarBody(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('secret-value');

        $this->innerClient
            ->expects(self::never())
            ->method('sendRequest');

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::BodyField);

        $request = new Request('POST', self::API_URL, [
            'Content-Type' => self::CONTENT_TYPE_JSON,
        ], json_encode('just-a-string'));

        $this->expectException(VaultException::class);
        $this->expectExceptionMessageToContain(self::NON_OBJECT_BODY_MESSAGE);

        $authenticatedClient->sendRequest($request);
    }

    /**
     * An empty JSON array body (`[]`) decodes to the same PHP value as `{}`,
     * so it used to slip through the list guard and get silently reshaped
     * into an object once the secret field was assigned. The leading-token
     * check (`{`) must reject it deterministically before any HTTP call.
     */
    #[Test]
    public function injectBodyFieldRejectsEmptyJsonArrayBody(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('secret-value');

        $this->innerClient
            ->expects(self::never())
            ->method('sendRequest');

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::BodyField);

        $request = new Request('POST', self::API_URL, [
            'Content-Type' => self::CONTENT_TYPE_JSON,
        ], '[]');

        $this->expectException(VaultException::class);
        $this->expectExceptionMessageToContain(self::NON_OBJECT_BODY_MESSAGE);

        $authenticatedClient->sendRequest($request);
    }

    /**
     * Behavioural change guard: a syntactically INVALID JSON body used to be
     * silently coerced to `[]` (`json_decode(...) ?: []`), so the request went
     * out as `{"field":"secret"}` and the caller's original payload was
     * dropped. Now it must be rejected before any HTTP call — with the
     * explicit malformed-JSON message, not the generic non-object one.
     */
    #[Test]
    public function injectBodyFieldRejectsMalformedJsonBody(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('secret-value');

        $this->innerClient
            ->expects(self::never())
            ->method('sendRequest');

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::BodyField);

        $request = new Request('POST', self::API_URL, [
            'Content-Type' => self::CONTENT_TYPE_JSON,
        ], '{"broken": ');

        $this->expectException(VaultException::class);
        $this->expectExceptionMessageToContain('request body is not valid JSON');

        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function auditLogsFailedRequest(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('secret');

        $clientException = new class ('Connection failed') extends Exception implements ClientExceptionInterface {};

        $this->innerClient
            ->method('sendRequest')
            ->willThrowException($clientException);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->willReturnCallback(function (
                string $identifier,
                string $action,
                bool $success,
                ?string $error,
            ): void {
                self::assertSame('my_key', $identifier);
                self::assertSame('http_call', $action);
                self::assertFalse($success);
                self::assertSame('Connection failed', $error);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_key', SecretPlacement::Bearer);

        $request = new Request('GET', self::API_URL);

        $this->expectException(ClientExceptionInterface::class);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withOAuthReturnsNewInstance(): void
    {
        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $oauthConfig = OAuthConfig::clientCredentials(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $oauthClient = $client->withOAuth($oauthConfig);

        self::assertNotSame($client, $oauthClient);
        self::assertInstanceOf(VaultHttpClient::class, $oauthClient);
    }

    #[Test]
    public function withOAuthReasonCanBeCustomized(): void
    {
        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $oauthConfig = OAuthConfig::clientCredentials(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: 'oauth/client-id',
            clientSecretSecret: 'oauth/client-secret',
        );

        $oauthClient = $client->withOAuth($oauthConfig, 'Custom OAuth reason');

        self::assertInstanceOf(VaultHttpClient::class, $oauthClient);
    }

    #[Test]
    public function sendRequestWithoutAuthenticationPassesUnmodified(): void
    {
        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                // No Authorization header should be added
                self::assertFalse($request->hasHeader('Authorization'));
                self::assertFalse($request->hasHeader('X-API-Key'));

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $request = new Request('GET', self::API_URL);
        $response = $client->sendRequest($request);

        self::assertSame(200, $response->getStatusCode());
    }

    #[Test]
    public function auditLogShowsNoneWhenNoAuthentication(): void
    {
        $this->innerClient
            ->method('sendRequest')
            ->willReturn(new Response(200));

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->willReturnCallback(function (
                string $identifier,
                string $action,
            ): void {
                self::assertSame('none', $identifier);
                self::assertSame('http_call', $action);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $request = new Request('GET', self::API_URL);
        $client->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationDefaultHeaderNameForHeaderPlacement(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('header-secret');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                // Default header name should be X-API-Key
                self::assertSame('header-secret', $request->getHeaderLine('X-API-Key'));

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        // Header placement without custom headerName
        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::Header);

        $request = new Request('GET', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationInjectsBodyFieldWithEmptyBody(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('secret-value');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                $body = (string) $request->getBody();
                $decoded = json_decode($body, true);
                self::assertSame('secret-value', $decoded['api_key']);

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::BodyField);

        // JSON request with empty body
        $request = new Request('POST', self::API_URL, [
            'Content-Type' => self::CONTENT_TYPE_JSON,
        ], '');

        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function withAuthenticationInjectsBodyFieldWithEmptyFormData(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->with('my_api_key')
            ->willReturn('form-secret');

        $this->innerClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(function (RequestInterface $request): Response {
                $body = (string) $request->getBody();
                parse_str($body, $data);
                self::assertSame('form-secret', $data['api_key']);

                return new Response(200);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $authenticatedClient = $client->withAuthentication('my_api_key', SecretPlacement::BodyField);

        // Form request with empty body
        $request = new Request('POST', self::API_URL, [
            'Content-Type' => 'application/x-www-form-urlencoded',
        ], '');

        $authenticatedClient->sendRequest($request);
    }

    #[Test]
    public function sendRequestThrowsForUnsupportedUriScheme(): void
    {
        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $request = new Request('GET', 'ftp://files.example.com/data');

        $this->expectException(VaultException::class);
        $this->expectExceptionMessageMatches('/Unsupported URI scheme/');

        $client->sendRequest($request);
    }

    #[Test]
    public function sendRequestThrowsForFileScheme(): void
    {
        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $request = new Request('GET', 'file:///etc/passwd');

        $this->expectException(VaultException::class);

        $client->sendRequest($request);
    }

    #[Test]
    public function sendRequestThrowsWhenHostNotInAllowList(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = ['trusted.example.com'];

        try {
            $client = new VaultHttpClient(
                $this->vaultService,
                $this->auditLogService,
                $this->innerClient,
            );

            $request = new Request('GET', 'https://untrusted.other.com/data');

            $this->expectException(VaultException::class);
            $this->expectExceptionMessageMatches('/not in the allowed hosts list/');

            $client->sendRequest($request);
        } finally {
            unset($GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']);
        }
    }

    #[Test]
    public function sendRequestAllowsWildcardHostMatch(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = ['*.example.com'];

        try {
            $this->innerClient
                ->expects(self::once())
                ->method('sendRequest')
                ->willReturn(new Response(200));

            $client = new VaultHttpClient(
                $this->vaultService,
                $this->auditLogService,
                $this->innerClient,
            );

            $request = new Request('GET', self::API_URL);
            $response = $client->sendRequest($request);

            self::assertSame(200, $response->getStatusCode());
        } finally {
            unset($GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts']);
        }
    }

    #[Test]
    public function withReasonPreservesOtherConfiguration(): void
    {
        $this->vaultService
            ->method('retrieve')
            ->willReturn('secret');

        $this->innerClient
            ->method('sendRequest')
            ->willReturn(new Response(200));

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->willReturnCallback(function (
                string $identifier,
                string $action,
                bool $success,
                ?string $error,
                string $reason,
            ): void {
                self::assertSame('my_key', $identifier);
                self::assertSame('Updated reason', $reason);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        // Chain withAuthentication and withReason
        $authenticatedClient = $client
            ->withAuthentication('my_key', SecretPlacement::Bearer)
            ->withReason('Updated reason');

        $request = new Request('GET', self::API_URL);
        $authenticatedClient->sendRequest($request);
    }

    /**
     * Regression guard: the OAuth token manager (and therefore its token
     * cache) MUST survive `withAuthentication()` / `withOAuth()` /
     * `withReason()` clones.
     *
     * Before the fix, every clone built a fresh `OAuthTokenManager` via
     * `new self(...)` in the constructor — meaning each fluent chain
     * re-hit the IdP for a new token, plus extra audit-log writes and
     * `client_secret` decryptions. Reflection-based identity check is
     * the most robust assertion: even if a future caching change moves
     * tokens elsewhere, the manager instance equality still proves the
     * with-clones share state.
     */
    #[Test]
    public function oauthManagerSurvivesWithAuthenticationWithOAuthAndWithReasonClones(): void
    {
        $client = new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
        );

        $originalManager = $this->extractOAuthManager($client);

        $afterAuth = $client->withAuthentication('my_key', SecretPlacement::Bearer);
        $afterOAuth = $client->withOAuth(OAuthConfig::clientCredentials(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: 'cid',
            clientSecretSecret: 'csec',
        ));
        $afterReason = $afterAuth->withReason('updated');
        $afterChain = $afterOAuth->withReason('chained');

        self::assertSame(
            $originalManager,
            $this->extractOAuthManager($afterAuth),
            'withAuthentication() must forward the same OAuthTokenManager',
        );
        self::assertSame(
            $originalManager,
            $this->extractOAuthManager($afterOAuth),
            'withOAuth() must forward the same OAuthTokenManager',
        );
        self::assertSame(
            $originalManager,
            $this->extractOAuthManager($afterReason),
            'withReason() (after withAuthentication) must forward the same OAuthTokenManager',
        );
        self::assertSame(
            $originalManager,
            $this->extractOAuthManager($afterChain),
            'withReason() (after withOAuth) must forward the same OAuthTokenManager — token cache is dead if this fails',
        );
    }

    /**
     * Read the request-option configuration of the inner Guzzle client that
     * withTimeout() bakes into a VaultHttpClient instance.
     *
     * @return array<string, mixed>
     */
    private function getInnerGuzzleConfig(VaultHttpClient $client): array
    {
        $inner = (new ReflectionClass(VaultHttpClient::class))
            ->getProperty('innerClient')
            ->getValue($client);

        self::assertInstanceOf(ClientInterface::class, $inner);

        return $this->getGuzzleConfig($inner);
    }

    private function extractOAuthManager(VaultHttpClient $client): OAuthTokenManager
    {
        $property = (new ReflectionClass(VaultHttpClient::class))->getProperty('oauthManager');
        $value = $property->getValue($client);
        self::assertInstanceOf(OAuthTokenManager::class, $value);

        return $value;
    }
}
