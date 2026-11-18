<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Http\AuthScheme;
use Netresearch\NrVault\Http\AuthSchemeHttpClientInterface;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\Fixtures\AlwaysPublicDnsResolver;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use ReflectionProperty;

/**
 * withAuthScheme() must send exactly what the deprecated withAuthentication()
 * sends for the same placement and options (ADR-056).
 */
#[CoversClass(VaultHttpClient::class)]
final class VaultHttpClientAuthSchemeTest extends TestCase
{
    /**
     * @return iterable<string, array{SecretPlacement, array{headerName?: string, prefix?: string, queryParam?: string, bodyField?: string, usernameSecret?: string}, AuthScheme, array<string, string>}>
     */
    public static function placementProvider(): iterable
    {
        yield 'bearer' => [SecretPlacement::Bearer, [], AuthScheme::bearer(), ['Authorization' => 'Bearer primary-value']];
        yield 'basic, combined secret' => [SecretPlacement::BasicAuth, [], AuthScheme::basicAuth(), ['Authorization' => 'Basic ' . base64_encode('primary-value')]];
        yield 'basic, username secret' => [SecretPlacement::BasicAuth, ['usernameSecret' => 'api_user'], AuthScheme::basicAuth('api_user'), ['Authorization' => 'Basic ' . base64_encode('user-value:primary-value')]];
        yield 'header, default name' => [SecretPlacement::Header, [], AuthScheme::header(), ['X-API-Key' => 'primary-value']];
        yield 'header, name and prefix' => [SecretPlacement::Header, ['headerName' => 'Authorization', 'prefix' => 'DeepL-Auth-Key '], AuthScheme::header('Authorization', 'DeepL-Auth-Key '), ['Authorization' => 'DeepL-Auth-Key primary-value']];
        yield 'api key' => [SecretPlacement::ApiKey, [], AuthScheme::apiKey(), ['X-API-Key' => 'primary-value']];
        yield 'query, default name' => [SecretPlacement::QueryParam, [], AuthScheme::queryParam(), ['uri' => 'https://api.example.com/v1?page=2&api_key=primary-value']];
        yield 'query, custom name' => [SecretPlacement::QueryParam, ['queryParam' => 'key'], AuthScheme::queryParam('key'), ['uri' => 'https://api.example.com/v1?page=2&key=primary-value']];
        yield 'body, default field' => [SecretPlacement::BodyField, [], AuthScheme::bodyField(), ['body' => 'model=small&api_key=primary-value']];
        yield 'body, hyphenated field' => [SecretPlacement::BodyField, ['bodyField' => 'api-key'], AuthScheme::bodyField('api-key'), ['body' => 'model=small&api-key=primary-value']];
        yield 'header, empty prefix' => [SecretPlacement::Header, ['headerName' => 'Authorization', 'prefix' => ''], AuthScheme::header('Authorization', ''), ['Authorization' => 'primary-value']];
        yield 'body, custom field' => [SecretPlacement::BodyField, ['bodyField' => 'client_secret'], AuthScheme::bodyField('client_secret'), ['body' => 'model=small&client_secret=primary-value']];
    }

    /**
     * @param array{headerName?: string, prefix?: string, queryParam?: string, bodyField?: string, usernameSecret?: string} $options
     * @param array<string, string>                                                                                         $expected
     */
    #[Test]
    #[DataProvider('placementProvider')]
    public function schemeSendsWhatTheLegacyOptionsSend(
        SecretPlacement $placement,
        array $options,
        AuthScheme $scheme,
        array $expected,
    ): void {
        $legacy = $this->sendThrough(
            static fn (VaultHttpClient $client): VaultHttpClient => $client->withAuthentication('primary', $placement, $options),
        );
        $current = $this->sendThrough(
            static fn (VaultHttpClient $client): VaultHttpClient => $client->withAuthScheme('primary', $scheme),
        );

        self::assertSame($legacy, $current);
        foreach ($expected as $key => $value) {
            self::assertSame($value, $current[$key] ?? $current['headers'][$key][0] ?? null, $key);
        }
    }

    #[Test]
    public function clientAdvertisesTheCapability(): void
    {
        self::assertContains(AuthSchemeHttpClientInterface::class, class_implements(VaultHttpClient::class));
    }

    #[Test]
    public function schemeKeepsTheReasonAndLeavesTheOriginalUnauthenticated(): void
    {
        $original   = $this->client(self::createStub(ClientInterface::class))->withReason('Translate request');
        $configured = $original->withAuthScheme('primary', AuthScheme::bearer());

        $reason     = new ReflectionProperty(VaultHttpClient::class, 'reason');
        $identifier = new ReflectionProperty(VaultHttpClient::class, 'secretIdentifier');
        self::assertSame('Translate request', $reason->getValue($configured));
        self::assertSame('primary', $identifier->getValue($configured));
        self::assertNull($identifier->getValue($original));
    }

    #[Test]
    public function bodySchemeCollidingWithAnAdditionalBodyFieldIsRefused(): void
    {
        $client = $this->client(self::createStub(ClientInterface::class))
            ->withAdditionalBodyField('subject', 'subject_token');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode(7902701577);

        $client->withAuthScheme('primary', AuthScheme::bodyField('subject_token'));
    }

    /**
     * @param callable(VaultHttpClient): VaultHttpClient $configure
     *
     * @return array{method: string, uri: string, headers: array<string, list<string>>, body: string}
     */
    private function sendThrough(callable $configure): array
    {
        $sent      = null;
        $transport = $this->createMock(ClientInterface::class);
        $transport
            ->expects(self::once())
            ->method('sendRequest')
            ->willReturnCallback(static function (RequestInterface $request) use (&$sent): Response {
                $sent = [
                    'method'  => $request->getMethod(),
                    'uri'     => (string) $request->getUri(),
                    'headers' => $request->getHeaders(),
                    'body'    => (string) $request->getBody(),
                ];

                return new Response(200);
            });

        $configure($this->client($transport))->sendRequest(new Request(
            'POST',
            'https://api.example.com/v1?page=2',
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            'model=small',
        ));
        self::assertIsArray($sent);

        /** @var array{method: string, uri: string, headers: array<string, list<string>>, body: string} $sent */
        return $sent;
    }

    private function client(ClientInterface $transport): VaultHttpClient
    {
        $vault = self::createStub(VaultServiceInterface::class);
        $vault
            ->method('retrieve')
            ->willReturnCallback(static fn (string $identifier): string => $identifier === 'api_user' ? 'user-value' : 'primary-value');

        return new VaultHttpClient(
            $vault,
            self::createStub(AuditLogServiceInterface::class),
            $transport,
            secureHttpClientFactory: new SecureHttpClientFactory(new AlwaysPublicDnsResolver()),
        );
    }
}
