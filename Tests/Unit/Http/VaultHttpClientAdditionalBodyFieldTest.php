<?php

/* Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\FulfilledPromise;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use Netresearch\NrVault\Audit\AuditContextInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\RequestCancelledException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\AdditionalSecretHttpClientInterface;
use Netresearch\NrVault\Http\CancellationSignalInterface;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Http\OAuth\OAuthTokenManager;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\Fixtures\AlwaysPublicDnsResolver;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use ReflectionProperty;

#[CoversClass(VaultHttpClient::class)]
final class VaultHttpClientAdditionalBodyFieldTest extends TestCase
{
    use GuzzleClientConfigTrait;

    #[Test]
    public function basicAndSubjectCredentialsShareOneRequestForBothBodyFormats(): void
    {
        foreach (['application/x-www-form-urlencoded', 'application/json'] as $contentType) {
            $vault = $this->createMock(VaultServiceInterface::class);
            $vault
                ->expects(self::exactly(2))
                ->method('retrieve')
                ->willReturnCallback(
                    static fn (
                        string $id,
                    ): string => $id === 'client' ? 'client-id:client-password' : 'subject-value',
                );
            $transport = $this->createMock(ClientInterface::class);
            $transport
                ->expects(self::once())
                ->method('sendRequest')
                ->willReturnCallback(
                    static function (
                        RequestInterface $request,
                    ) use ($contentType): Response {
                        self::assertSame(
                            'Basic ' . base64_encode('client-id:client-password'),
                            $request->getHeaderLine('Authorization'),
                        );
                        if ($contentType === 'application/json') {
                            $data = json_decode(
                                (string) $request->getBody(),
                                true,
                                512,
                                JSON_THROW_ON_ERROR,
                            );
                        } else {
                            parse_str((string) $request->getBody(), $data);
                        }

                        self::assertSame(
                            [
                                'grant_type' => 'token-exchange',
                                'subject_token' => 'subject-value',
                            ],
                            $data,
                        );

                        return new Response(200, [], '{}');
                    },
                );
            $client = new VaultHttpClient(
                $vault,
                self::createStub(AuditLogServiceInterface::class),
                $transport,
                secureHttpClientFactory: new SecureHttpClientFactory(new AlwaysPublicDnsResolver()),
            );
            self::assertContains(
                AdditionalSecretHttpClientInterface::class,
                class_implements($client),
            );
            $configured = $client
                ->withAuthentication('client', SecretPlacement::BasicAuth)
                ->withAdditionalBodyField('subject', 'subject_token')
                ->withReason('exchange');
            $body = $contentType === 'application/json' ? ' {"grant_type":"token-exchange"} ' : 'grant_type=token-exchange';
            $configured->sendRequest(
                new Request(
                    'POST',
                    'https://idp.example.com/token',
                    ['Content-Type' => $contentType],
                    $body,
                ),
            );
        }
    }

    #[Test]
    public function originalClientHasNoAdditionalCredentialAndBuilderOrderPreservesIt(): void
    {
        $vault = $this->createMock(VaultServiceInterface::class);
        $vault
            ->expects(self::once())
            ->method('retrieve')
            ->with('subject')
            ->willReturn('subject-value');
        $requests = [];
        $transport = $this->createMock(ClientInterface::class);
        $transport
            ->expects(self::exactly(2))
            ->method('sendRequest')
            ->willReturnCallback(
                static function (
                    RequestInterface $request,
                ) use (&$requests): Response {
                    $requests[] = (string) $request->getBody();

                    return new Response(200);
                },
            );
        $client = new VaultHttpClient(
            $vault,
            self::createStub(AuditLogServiceInterface::class),
            $transport,
            secureHttpClientFactory: new SecureHttpClientFactory(new AlwaysPublicDnsResolver()),
        );
        $configured = $client
            ->withAdditionalBodyField('subject', 'subject_token')
            ->withReason('kept');
        $request = new Request(
            'POST',
            'https://idp.example.com/token',
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            'client_id=public',
        );
        $configured->sendRequest($request);
        $client->sendRequest($request);
        self::assertSame(
            ['client_id=public&subject_token=subject-value', 'client_id=public'],
            $requests,
        );
    }

    #[Test]
    public function missingAdditionalCredentialPreventsTransportContact(): void
    {
        $vault = $this->createMock(VaultServiceInterface::class);
        $vault
            ->expects(self::once())
            ->method('retrieve')
            ->willThrowException(new SecretNotFoundException('missing'));
        $transport = $this->createMock(ClientInterface::class);
        $transport->expects(self::never())->method('sendRequest');
        $client = new VaultHttpClient(
            $vault,
            self::createStub(AuditLogServiceInterface::class),
            $transport,
            secureHttpClientFactory: new SecureHttpClientFactory(new AlwaysPublicDnsResolver()),
        );
        $this->expectException(SecretNotFoundException::class);
        $client
            ->withAdditionalBodyField('missing', 'subject_token')
            ->sendRequest(new Request('POST', 'https://idp.example.com/token'));
    }

    #[Test]
    public function rejectsCollisionsAndBoundsInBothBuilderOrders(): void
    {
        $client = new VaultHttpClient(
            self::createStub(VaultServiceInterface::class),
            self::createStub(AuditLogServiceInterface::class),
            self::createStub(ClientInterface::class),
            secureHttpClientFactory: new SecureHttpClientFactory(new AlwaysPublicDnsResolver()),
        );
        foreach ([
            static fn (): VaultHttpClient => $client->withAdditionalBodyField('a', 'invalid[]'),
            static fn (): VaultHttpClient => $client
                ->withAdditionalBodyField('a', 'subject_token')
                ->withAdditionalBodyField('b', 'subject_token'),
            static fn (): VaultHttpClient => $client
                ->withAuthentication(
                    'a',
                    SecretPlacement::BodyField,
                    ['bodyField' => 'subject_token'],
                )
                ->withAdditionalBodyField('b', 'subject_token'),
            static fn (): VaultHttpClient => $client
                ->withAdditionalBodyField('b', 'subject_token')
                ->withAuthentication(
                    'a',
                    SecretPlacement::BodyField,
                    ['bodyField' => 'subject_token'],
                ),
        ] as $builder) {
            try {
                $builder();
                self::fail('Ambiguous body binding was accepted.');
            } catch (InvalidArgumentException $exception) {
                self::assertNotSame('', $exception->getMessage());
            }
        }

        $bounded = $client;
        for ($index = 0; $index < 8; ++$index) {
            $bounded = $bounded->withAdditionalBodyField('id-' . $index, 'field_' . $index);
        }

        $this->expectException(InvalidArgumentException::class);
        $bounded->withAdditionalBodyField('last', 'field_8');
    }

    #[Test]
    public function timeoutAuthenticationAndReasonClonesPreserveActualInjection(): void
    {
        $vault = $this->createMock(VaultServiceInterface::class);
        $vault
            ->expects(self::exactly(2))
            ->method('retrieve')
            ->willReturnCallback(
                static fn (
                    string $id,
                ): string => $id === 'primary' ? 'client:password' : 'subject-value',
            );
        $audit = $this->createMock(AuditLogServiceInterface::class);
        $audit
            ->expects(self::once())
            ->method('log')
            ->with('primary', 'http_call', true, null, 'cloned-exchange');
        $client = (new VaultHttpClient(
            $vault,
            $audit,
            secureHttpClientFactory: new SecureHttpClientFactory(new AlwaysPublicDnsResolver()),
        ))
            ->withAdditionalBodyField('subject', 'subject_token')
            ->withAuthentication('primary', SecretPlacement::BasicAuth)
            ->withTimeout(3)
            ->withReason('cloned-exchange');
        $inner = (new ReflectionProperty(VaultHttpClient::class, 'innerClient'))->getValue(
            $client,
        );
        self::assertInstanceOf(Client::class, $inner);
        $handler = $this->getGuzzleConfig($inner)['handler'];
        self::assertInstanceOf(HandlerStack::class, $handler);
        $handler->setHandler(
            static function (
                RequestInterface $request,
                array $options,
            ): FulfilledPromise {
                self::assertSame(
                    'Basic ' . base64_encode('client:password'),
                    $request->getHeaderLine('Authorization'),
                );
                parse_str((string) $request->getBody(), $fields);
                self::assertSame(
                    [
                        'grant_type' => 'exchange',
                        'subject_token' => 'subject-value',
                    ],
                    $fields,
                );
                self::assertSame(3, $options['timeout']);
                self::assertFalse($options['debug']);
                self::assertFalse($options['allow_redirects']);
                self::assertArrayHasKey(CURLOPT_RESOLVE, $options['curl']);

                return new FulfilledPromise(new Response(204));
            },
        );
        $original = new Request(
            'POST',
            'https://idp.example.com/token',
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            'grant_type=exchange',
        );
        self::assertSame(204, $client->sendRequest($original)->getStatusCode());
        self::assertSame('grant_type=exchange', (string) $original->getBody());
    }

    #[Test]
    public function oauthCloneKeepsAdditionalFieldsOutOfTheTokenLeg(): void
    {
        $vault = $this->createMock(VaultServiceInterface::class);
        $vault
            ->expects(self::exactly(3))
            ->method('retrieve')
            ->willReturnCallback(
                static fn (string $id): string => match ($id) {
                    'oauth-id' => 'client-id',
                    'oauth-password' => 'client-password',
                    default => 'subject-value',
                },
            );
        $tokenClient = $this->createMock(ClientInterface::class);
        $tokenClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(
                static function (RequestInterface $request): Response {
                    self::assertStringNotContainsString(
                        'subject_token',
                        (string) $request->getBody(),
                    );

                    return new Response(
                        200,
                        [],
                        '{"access_token":"issued-token","expires_in":3600,"token_type":"Bearer"}',
                    );
                },
            );
        $resourceClient = $this->createMock(ClientInterface::class);
        $resourceClient
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(
                static function (RequestInterface $request): Response {
                    self::assertSame(
                        'Bearer issued-token',
                        $request->getHeaderLine('Authorization'),
                    );
                    self::assertSame(
                        ['public' => 'kept', 'subject_token' => 'subject-value'],
                        json_decode(
                            (string) $request->getBody(),
                            true,
                            512,
                            JSON_THROW_ON_ERROR,
                        ),
                    );

                    return new Response(204);
                },
            );
        $factory = new SecureHttpClientFactory(new AlwaysPublicDnsResolver());
        $client = new VaultHttpClient(
            $vault,
            self::createStub(AuditLogServiceInterface::class),
            $resourceClient,
            oauthManager: new OAuthTokenManager($vault, $tokenClient, $factory),
            secureHttpClientFactory: $factory,
        );
        self::assertSame(
            204,
            $client
                ->withAdditionalBodyField('subject', 'subject_token')
                ->withOAuth(
                    OAuthConfig::clientCredentials(
                        'https://idp.example.com/token',
                        'oauth-id',
                        'oauth-password',
                    ),
                )
                ->withReason('oauth-exchange')
                ->sendRequest(
                    new Request(
                        'POST',
                        'https://api.example.com/resource',
                        ['Content-Type' => 'application/json'],
                        '{"public":"kept"}',
                    ),
                )
                ->getStatusCode(),
        );
    }

    #[Test]
    public function bothAsyncSendsInjectBothCredentialsOnTheSecuredTransport(): void
    {
        foreach (['sendCancellable', 'sendStreaming'] as $method) {
            $vault = $this->createMock(VaultServiceInterface::class);
            $vault
                ->expects(self::exactly(2))
                ->method('retrieve')
                ->willReturnCallback(
                    static fn (
                        string $id,
                    ): string => $id === 'primary' ? 'client:password' : 'subject-value',
                );
            $audit = $this->createMock(AuditLogServiceInterface::class);
            $audit
                ->expects(self::once())
                ->method('log')
                ->willReturnCallback(
                    static function (
                        string $id,
                        string $action,
                        bool $success,
                        ?string $error = null,
                        ?string $reason = null,
                        ?string $before = null,
                        ?string $after = null,
                        ?AuditContextInterface $context = null,
                    ): void {
                        self::assertSame('primary', $id);
                        self::assertSame('http_call', $action);
                        self::assertTrue($success);
                        self::assertNull($error);
                        $metadata = json_encode($context?->toArray(), JSON_THROW_ON_ERROR);
                        self::assertStringNotContainsString(
                            'subject-value',
                            $metadata,
                        );
                        self::assertStringNotContainsString(
                            'client:password',
                            $metadata,
                        );
                        self::assertSame(
                            204,
                            $context?->toArray()['status_code'],
                        );
                    },
                );
            $factory = new SecureHttpClientFactory(new AlwaysPublicDnsResolver());
            $transport = $factory->createCancellable();
            self::assertNotNull($transport);
            $inner = $transport->client();
            self::assertInstanceOf(Client::class, $inner);
            $handler = $this->getGuzzleConfig($inner)['handler'];
            self::assertInstanceOf(HandlerStack::class, $handler);
            $calls = 0;
            $handler->setHandler(
                static function (
                    RequestInterface $request,
                    array $options,
                ) use (&$calls): FulfilledPromise {
                    ++$calls;
                    self::assertSame(
                        'Basic ' . base64_encode('client:password'),
                        $request->getHeaderLine('Authorization'),
                    );
                    self::assertSame(
                        ['public' => 'kept', 'subject_token' => 'subject-value'],
                        json_decode(
                            (string) $request->getBody(),
                            true,
                            512,
                            JSON_THROW_ON_ERROR,
                        ),
                    );
                    self::assertArrayHasKey(CURLOPT_RESOLVE, $options['curl']);
                    self::assertFalse($options['allow_redirects']);

                    return new FulfilledPromise(new Response(204));
                },
            );
            $client = (new VaultHttpClient(
                $vault,
                $audit,
                secureHttpClientFactory: $factory,
                cancellableTransport: $transport,
            ))
                ->withAuthentication('primary', SecretPlacement::BasicAuth)
                ->withAdditionalBodyField('subject', 'subject_token')
                ->withReason('async-exchange');
            self::assertTrue($client->supportsCancellation());
            self::assertTrue($client->supportsStreaming());
            $response = $method === 'sendCancellable' ? $client->sendCancellable(
                new Request(
                    'POST',
                    'https://idp.example.com/token',
                    ['Content-Type' => 'application/json'],
                    '{"public":"kept"}',
                ),
                self::createStub(CancellationSignalInterface::class),
            ) : $client->sendStreaming(
                new Request(
                    'POST',
                    'https://idp.example.com/token',
                    ['Content-Type' => 'application/json'],
                    '{"public":"kept"}',
                ),
            );
            self::assertSame(204, $response->getStatusCode());
            $response->getBody()->close();
            self::assertSame(1, $calls);
        }
    }

    #[Test]
    public function preCancelledAsyncCallsReadNeitherPrimaryNorAdditionalSecrets(): void
    {
        $signal = new class () implements CancellationSignalInterface {
            public function isCancelled(): bool
            {
                return true;
            }
        };
        foreach (['sendCancellable', 'sendStreaming'] as $method) {
            $vault = $this->createMock(VaultServiceInterface::class);
            $vault->expects(self::never())->method('retrieve');
            $transport = $this->createMock(ClientInterface::class);
            $transport->expects(self::never())->method('sendRequest');
            $audit = $this->createMock(AuditLogServiceInterface::class);
            $audit
                ->expects(self::once())
                ->method('log')
                ->with('primary', 'http_call_cancelled_before_send', false);
            $client = (new VaultHttpClient(
                $vault,
                $audit,
                $transport,
                secureHttpClientFactory: new SecureHttpClientFactory(new AlwaysPublicDnsResolver()),
            ))
                ->withAuthentication('primary', SecretPlacement::BasicAuth)
                ->withAdditionalBodyField('subject', 'subject_token');

            try {
                $request = new Request('POST', 'https://idp.example.com/token');
                if ($method === 'sendCancellable') {
                    $client->sendCancellable($request, $signal);
                } else {
                    $client->sendStreaming($request, $signal);
                }

                self::fail('A cancelled call was accepted.');
            } catch (RequestCancelledException $exception) {
                self::assertStringContainsString(
                    'no secret was retrieved',
                    $exception->getMessage(),
                );
            }
        }
    }

    #[Test]
    public function deniedAdditionalReadIsAuditedWithoutEgressOrSecretValues(): void
    {
        foreach (['sendRequest', 'sendCancellable', 'sendStreaming'] as $method) {
            $vault = $this->createMock(VaultServiceInterface::class);
            $vault
                ->expects(self::exactly(2))
                ->method('retrieve')
                ->willReturnCallback(
                    static function (string $id): string {
                        if ($id === 'primary') {
                            return 'client:password';
                        }

                        throw AccessDeniedException::forIdentifier($id);
                    },
                );
            $transport = $this->createMock(ClientInterface::class);
            $transport->expects(self::never())->method('sendRequest');
            $audit = $this->createMock(AuditLogServiceInterface::class);
            $audit
                ->expects(self::once())
                ->method('log')
                ->willReturnCallback(
                    static function (
                        string $id,
                        string $action,
                        bool $success,
                        ?string $error = null,
                        ?string $reason = null,
                        ?string $before = null,
                        ?string $after = null,
                        ?AuditContextInterface $context = null,
                    ): void {
                        self::assertSame('primary', $id);
                        self::assertSame('http_call', $action);
                        self::assertFalse($success);
                        self::assertStringContainsString(
                            'nothing was sent',
                            $error ?? '',
                        );
                        self::assertStringNotContainsString(
                            'client:password',
                            json_encode(
                                [$error, $context?->toArray()],
                                JSON_THROW_ON_ERROR,
                            ),
                        );
                    },
                );
            $client = (new VaultHttpClient(
                $vault,
                $audit,
                $transport,
                secureHttpClientFactory: new SecureHttpClientFactory(new AlwaysPublicDnsResolver()),
            ))
                ->withAuthentication('primary', SecretPlacement::BasicAuth)
                ->withAdditionalBodyField('denied', 'subject_token');

            try {
                $request = new Request('POST', 'https://idp.example.com/token');
                match ($method) {
                    'sendRequest' => $client->sendRequest($request),
                    'sendCancellable' => $client->sendCancellable(
                        $request,
                        self::createStub(CancellationSignalInterface::class),
                    ),
                    default => $client->sendStreaming($request),
                };
                self::fail('A denied secret was sent.');
            } catch (AccessDeniedException $exception) {
                self::assertStringContainsString(
                    'denied',
                    $exception->getMessage(),
                );
            }
        }
    }

    #[Test]
    public function malformedJsonWithAdditionalCredentialsNeverContactsTheTransport(): void
    {
        foreach (['[]', '42', '{broken'] as $body) {
            $vault = $this->createMock(VaultServiceInterface::class);
            $vault
                ->expects(self::once())
                ->method('retrieve')
                ->with('subject')
                ->willReturn('subject-value');
            $transport = $this->createMock(ClientInterface::class);
            $transport->expects(self::never())->method('sendRequest');
            $client = new VaultHttpClient(
                $vault,
                self::createStub(AuditLogServiceInterface::class),
                $transport,
                secureHttpClientFactory: new SecureHttpClientFactory(new AlwaysPublicDnsResolver()),
            );

            try {
                $client
                    ->withAdditionalBodyField('subject', 'subject_token')
                    ->sendRequest(
                        new Request(
                            'POST',
                            'https://idp.example.com/token',
                            ['Content-Type' => 'application/json'],
                            $body,
                        ),
                    );
                self::fail('A malformed body was sent.');
            } catch (VaultException $exception) {
                self::assertStringNotContainsString(
                    'subject-value',
                    $exception->getMessage(),
                );
            }
        }
    }
}
