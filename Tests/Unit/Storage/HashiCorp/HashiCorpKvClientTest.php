<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage\HashiCorp;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Netresearch\NrVault\Configuration\Dto\VaultServerConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\HashiCorpException;
use Netresearch\NrVault\Storage\HashiCorp\HashiCorpAuthenticator;
use Netresearch\NrVault\Storage\HashiCorp\HashiCorpHttp;
use Netresearch\NrVault\Storage\HashiCorp\HashiCorpKvClient;
use Netresearch\NrVault\Tests\Unit\Fixtures\RecordingHttpClient;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(HashiCorpKvClient::class)]
#[CoversClass(HashiCorpHttp::class)]
#[AllowMockObjectsWithoutExpectations]
final class HashiCorpKvClientTest extends TestCase
{
    private const ADDRESS = 'https://vault.example.com:8200';

    private const SECRET_ID_ENV = 'NR_VAULT_TEST_KV_SECRET_ID';

    protected function tearDown(): void
    {
        putenv(self::SECRET_ID_ENV);

        parent::tearDown();
    }

    #[Test]
    public function readReturnsTheStoredDataAndSendsTheToken(): void
    {
        $http = new RecordingHttpClient(RecordingHttpClient::json(200, [
            'data' => ['data' => ['k' => 'v'], 'metadata' => ['version' => 3]],
        ]));

        $data = $this->client($http)->read('api_key');

        self::assertSame(['k' => 'v'], $data);
        self::assertSame('GET', $http->requests[0]->getMethod());
        self::assertSame(self::ADDRESS . '/v1/secret/data/typo3/api_key', (string) $http->requests[0]->getUri());
        self::assertSame('static-token', $http->requests[0]->getHeaderLine('X-Vault-Token'));
    }

    #[Test]
    public function readReturnsNullForAMissingKey(): void
    {
        $http = new RecordingHttpClient(new Response(404, [], '{"errors":[]}'));

        self::assertNull($this->client($http)->read('api_key'));
    }

    #[Test]
    public function readRefusesAResponseWithoutData(): void
    {
        $http = new RecordingHttpClient(RecordingHttpClient::json(200, ['data' => ['metadata' => []]]));

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400008);

        $this->client($http)->read('api_key');
    }

    #[Test]
    public function readRefusesABodyThatIsNotJson(): void
    {
        $http = new RecordingHttpClient(new Response(200, [], '<html>proxy error</html>'));

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400008);

        $this->client($http)->read('api_key');
    }

    #[Test]
    public function writeSendsTheDataUnderTheDataKey(): void
    {
        $http = new RecordingHttpClient(RecordingHttpClient::json(200, ['data' => ['version' => 4]]));

        $this->client($http)->write('api_key', ['k' => 'v']);

        self::assertSame('POST', $http->requests[0]->getMethod());
        self::assertSame(self::ADDRESS . '/v1/secret/data/typo3/api_key', (string) $http->requests[0]->getUri());
        self::assertSame(['data' => ['k' => 'v']], $http->bodyOf(0));
    }

    #[Test]
    public function writeRefusesARejection(): void
    {
        $http = new RecordingHttpClient(new Response(500, [], '{"errors":["leaked internals"]}'));

        try {
            $this->client($http)->write('api_key', ['k' => 'v']);
            self::fail('A rejected write must throw.');
        } catch (HashiCorpException $e) {
            self::assertSame(1794400006, $e->getCode());
            self::assertStringContainsString('HTTP 500', $e->getMessage());
            self::assertStringNotContainsString('leaked internals', $e->getMessage());
        }
    }

    #[Test]
    public function destroyDeletesTheMetadataPathSoEveryVersionGoes(): void
    {
        $http = new RecordingHttpClient(new Response(204));

        $this->client($http)->destroy('api_key');

        self::assertSame('DELETE', $http->requests[0]->getMethod());
        self::assertSame(self::ADDRESS . '/v1/secret/metadata/typo3/api_key', (string) $http->requests[0]->getUri());
    }

    #[Test]
    public function destroyOfAMissingKeyIsNotAnError(): void
    {
        $http = new RecordingHttpClient(new Response(404));

        $this->client($http)->destroy('api_key');

        self::assertCount(1, $http->requests);
    }

    #[Test]
    public function aForbiddenRequestUnderTokenAuthIsFinal(): void
    {
        $http = new RecordingHttpClient(new Response(403));

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400006);

        try {
            $this->client($http)->read('api_key');
        } finally {
            self::assertCount(1, $http->requests, 'a static token has nothing to refresh');
        }
    }

    #[Test]
    public function aForbiddenRequestUnderAppRoleLogsInAgainOnce(): void
    {
        putenv(self::SECRET_ID_ENV . '=the-secret-id');
        $http = new RecordingHttpClient(
            RecordingHttpClient::json(200, ['auth' => ['client_token' => 'hvs.old', 'lease_duration' => 3600]]),
            new Response(403),
            RecordingHttpClient::json(200, ['auth' => ['client_token' => 'hvs.new', 'lease_duration' => 3600]]),
            RecordingHttpClient::json(200, ['data' => ['data' => ['k' => 'v']]]),
        );

        $data = $this->client($http, authMethod: 'approle')->read('api_key');

        self::assertSame(['k' => 'v'], $data);
        self::assertCount(4, $http->requests);
        self::assertSame('hvs.old', $http->requests[1]->getHeaderLine('X-Vault-Token'));
        self::assertSame('hvs.new', $http->requests[3]->getHeaderLine('X-Vault-Token'));
    }

    #[Test]
    public function aSecondForbiddenAnswerAfterRelogginIsFinal(): void
    {
        putenv(self::SECRET_ID_ENV . '=the-secret-id');
        $http = new RecordingHttpClient(
            RecordingHttpClient::json(200, ['auth' => ['client_token' => 'hvs.old', 'lease_duration' => 3600]]),
            new Response(403),
            RecordingHttpClient::json(200, ['auth' => ['client_token' => 'hvs.new', 'lease_duration' => 3600]]),
            new Response(403),
        );

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400006);

        $this->client($http, authMethod: 'approle')->read('api_key');
    }

    #[Test]
    public function aTransportFailureIsRedactedAndNamesTheCause(): void
    {
        $failure = new ConnectException(
            'cURL error 7 for X-Vault-Token: hvs.super-secret-token',
            new Request('GET', self::ADDRESS),
        );
        $http = new RecordingHttpClient($failure);

        try {
            $this->client($http)->read('api_key');
            self::fail('A transport failure must throw.');
        } catch (HashiCorpException $e) {
            self::assertSame(1794400007, $e->getCode());
            self::assertStringNotContainsString('hvs.super-secret-token', $e->getMessage());
            self::assertStringContainsString('[REDACTED]', $e->getMessage());
            self::assertStringContainsString(ConnectException::class, $e->getMessage());
        }
    }

    #[Test]
    public function aMisconfiguredAddressFailsBeforeAnyRequest(): void
    {
        $http = new RecordingHttpClient();

        try {
            $this->client($http, address: 'http://vault.example.com')->read('api_key');
            self::fail('Plain http must be refused.');
        } catch (HashiCorpException $e) {
            self::assertSame(1794400002, $e->getCode());
            self::assertSame([], $http->requests);
        }
    }

    #[Test]
    public function referenceNamesTheObjectPath(): void
    {
        self::assertSame('secret/data/typo3/api_key', $this->client(new RecordingHttpClient())->reference('api_key'));
    }

    private function client(
        RecordingHttpClient $http,
        string $authMethod = 'token',
        string $address = self::ADDRESS,
    ): HashiCorpKvClient {
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('getHashiCorpConfig')->willReturn(new VaultServerConfig(
            address: $address,
            path: 'secret/data/typo3',
            authMethod: $authMethod,
            token: 'static-token',
            tokenEnvVar: 'NR_VAULT_TEST_KV_UNSET_TOKEN',
            roleId: 'role-1',
            secretIdEnvVar: self::SECRET_ID_ENV,
        ));

        $factory = new HttpFactory();
        $wire    = new HashiCorpHttp($http, $factory, $factory);

        return new HashiCorpKvClient($configuration, $wire, new HashiCorpAuthenticator($configuration, $wire));
    }
}
