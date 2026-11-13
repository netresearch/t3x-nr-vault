<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage\HashiCorp;

use GuzzleHttp\Psr7\HttpFactory;
use Netresearch\NrVault\Configuration\Dto\VaultServerConfig;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\HashiCorpException;
use Netresearch\NrVault\Storage\HashiCorp\HashiCorpAuthenticator;
use Netresearch\NrVault\Storage\HashiCorp\HashiCorpHttp;
use Netresearch\NrVault\Tests\Unit\Fixtures\RecordingHttpClient;
use Netresearch\NrVault\Tests\Unit\TestCase;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(HashiCorpAuthenticator::class)]
#[AllowMockObjectsWithoutExpectations]
final class HashiCorpAuthenticatorTest extends TestCase
{
    private const ADDRESS = 'https://vault.example.com:8200';

    private const TOKEN_ENV = 'NR_VAULT_TEST_HC_TOKEN';

    private const SECRET_ID_ENV = 'NR_VAULT_TEST_HC_SECRET_ID';

    protected function tearDown(): void
    {
        putenv(self::TOKEN_ENV);
        putenv(self::SECRET_ID_ENV);

        parent::tearDown();
    }

    #[Test]
    public function tokenMethodPrefersTheEnvironmentOverTheStoredToken(): void
    {
        putenv(self::TOKEN_ENV . '=env-token');
        $http = new RecordingHttpClient();

        $token = $this->authenticator($http, authMethod: 'token', token: 'stored-token')->token();

        self::assertSame('env-token', $token);
        self::assertSame([], $http->requests, 'the token method never calls Vault to log in');
    }

    #[Test]
    public function tokenMethodFallsBackToTheStoredToken(): void
    {
        $token = $this->authenticator(new RecordingHttpClient(), authMethod: 'token', token: 'stored-token')->token();

        self::assertSame('stored-token', $token);
    }

    #[Test]
    public function tokenMethodFailsClosedWithoutAnyToken(): void
    {
        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400004);

        $this->authenticator(new RecordingHttpClient(), authMethod: 'token')->token();
    }

    #[Test]
    public function appRoleLogsInWithRoleIdAndTheSecretIdFromTheEnvironment(): void
    {
        putenv(self::SECRET_ID_ENV . '=the-secret-id');
        $http = new RecordingHttpClient(RecordingHttpClient::json(200, [
            'auth' => ['client_token' => 'hvs.login-token', 'lease_duration' => 3600],
        ]));

        $token = $this->authenticator($http, authMethod: 'approle', roleId: 'role-1')->token();

        self::assertSame('hvs.login-token', $token);
        self::assertCount(1, $http->requests);
        self::assertSame('POST', $http->requests[0]->getMethod());
        self::assertSame(self::ADDRESS . '/v1/auth/approle/login', (string) $http->requests[0]->getUri());
        self::assertSame(['role_id' => 'role-1', 'secret_id' => 'the-secret-id'], $http->bodyOf(0));
        self::assertFalse($http->requests[0]->hasHeader('X-Vault-Token'), 'a login carries no token');
    }

    #[Test]
    public function appRoleRefusesToLogInWithoutASecretId(): void
    {
        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400004);

        $this->authenticator(new RecordingHttpClient(), authMethod: 'approle', roleId: 'role-1')->token();
    }

    #[Test]
    public function appRoleRefusesToLogInWithoutARoleId(): void
    {
        putenv(self::SECRET_ID_ENV . '=the-secret-id');

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400004);

        $this->authenticator(new RecordingHttpClient(), authMethod: 'approle')->token();
    }

    #[Test]
    public function kubernetesLogsInWithTheServiceAccountJwt(): void
    {
        $root = vfsStream::setup('sa', null, ['token' => "header.payload.signature\n"]);
        $http = new RecordingHttpClient(RecordingHttpClient::json(200, [
            'auth' => ['client_token' => 'hvs.k8s-token', 'lease_duration' => 600],
        ]));

        $token = $this->authenticator(
            $http,
            authMethod: 'kubernetes',
            kubernetesRole: 'typo3',
            kubernetesJwtPath: $root->url() . '/token',
        )->token();

        self::assertSame('hvs.k8s-token', $token);
        self::assertSame(self::ADDRESS . '/v1/auth/kubernetes/login', (string) $http->requests[0]->getUri());
        self::assertSame(['role' => 'typo3', 'jwt' => 'header.payload.signature'], $http->bodyOf(0));
    }

    #[Test]
    public function kubernetesRefusesToLogInWithoutTheTokenFile(): void
    {
        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400004);

        $this->authenticator(
            new RecordingHttpClient(),
            authMethod: 'kubernetes',
            kubernetesRole: 'typo3',
            kubernetesJwtPath: '/nonexistent/token',
        )->token();
    }

    #[Test]
    public function kubernetesRefusesToLogInWithoutARole(): void
    {
        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400004);

        $this->authenticator(new RecordingHttpClient(), authMethod: 'kubernetes')->token();
    }

    #[Test]
    public function aLoginTokenIsMemoisedWithinItsLease(): void
    {
        putenv(self::SECRET_ID_ENV . '=the-secret-id');
        $http = new RecordingHttpClient(RecordingHttpClient::json(200, [
            'auth' => ['client_token' => 'hvs.once', 'lease_duration' => 3600],
        ]));
        $authenticator = $this->authenticator($http, authMethod: 'approle', roleId: 'role-1');

        $authenticator->token();
        $authenticator->token();
        $authenticator->token();

        self::assertCount(1, $http->requests);
    }

    #[Test]
    public function aLoginTokenIsRefreshedAfterInvalidate(): void
    {
        putenv(self::SECRET_ID_ENV . '=the-secret-id');
        $http = new RecordingHttpClient(
            RecordingHttpClient::json(200, ['auth' => ['client_token' => 'hvs.first', 'lease_duration' => 3600]]),
            RecordingHttpClient::json(200, ['auth' => ['client_token' => 'hvs.second', 'lease_duration' => 3600]]),
        );
        $authenticator = $this->authenticator($http, authMethod: 'approle', roleId: 'role-1');

        self::assertSame('hvs.first', $authenticator->token());
        $authenticator->invalidate();

        self::assertSame('hvs.second', $authenticator->token());
    }

    #[Test]
    public function aRejectedLoginNamesTheStatusAndNothingElse(): void
    {
        putenv(self::SECRET_ID_ENV . '=the-secret-id');
        $http = new RecordingHttpClient(RecordingHttpClient::json(400, ['errors' => ['invalid secret id the-secret-id']]));

        try {
            $this->authenticator($http, authMethod: 'approle', roleId: 'role-1')->token();
            self::fail('A rejected login must throw.');
        } catch (HashiCorpException $e) {
            self::assertSame(1794400005, $e->getCode());
            self::assertStringContainsString('HTTP 400', $e->getMessage());
            self::assertStringNotContainsString('the-secret-id', $e->getMessage());
        }
    }

    #[Test]
    public function aLoginResponseWithoutAClientTokenIsRefused(): void
    {
        putenv(self::SECRET_ID_ENV . '=the-secret-id');
        $http = new RecordingHttpClient(RecordingHttpClient::json(200, ['auth' => ['lease_duration' => 10]]));

        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400008);

        $this->authenticator($http, authMethod: 'approle', roleId: 'role-1')->token();
    }

    #[Test]
    public function anUnknownAuthMethodIsRefused(): void
    {
        $this->expectException(HashiCorpException::class);
        $this->expectExceptionCode(1794400001);

        $this->authenticator(new RecordingHttpClient(), authMethod: 'ldap')->token();
    }

    #[Test]
    public function onlyLoginBasedMethodsCanRefresh(): void
    {
        $http = new RecordingHttpClient();

        self::assertFalse($this->authenticator($http, authMethod: 'token')->canRefresh());
        self::assertTrue($this->authenticator($http, authMethod: 'approle')->canRefresh());
        self::assertTrue($this->authenticator($http, authMethod: 'kubernetes')->canRefresh());
    }

    private function authenticator(
        RecordingHttpClient $http,
        string $authMethod,
        string $token = '',
        string $roleId = '',
        string $kubernetesRole = '',
        string $kubernetesJwtPath = '/var/run/secrets/kubernetes.io/serviceaccount/token',
    ): HashiCorpAuthenticator {
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('getHashiCorpConfig')->willReturn(new VaultServerConfig(
            address: self::ADDRESS,
            path: 'secret/data/typo3',
            authMethod: $authMethod,
            token: $token,
            tokenEnvVar: self::TOKEN_ENV,
            roleId: $roleId,
            secretIdEnvVar: self::SECRET_ID_ENV,
            kubernetesRole: $kubernetesRole,
            kubernetesJwtPath: $kubernetesJwtPath,
        ));

        $factory = new HttpFactory();

        return new HashiCorpAuthenticator($configuration, new HashiCorpHttp($http, $factory, $factory));
    }
}
