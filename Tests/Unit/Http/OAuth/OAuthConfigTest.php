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

use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

#[CoversClass(OAuthConfig::class)]
final class OAuthConfigTest extends TestCase
{
    private const TOKEN_ENDPOINT = 'https://auth.example.com/token';

    private const CLIENT_ID_SECRET = 'oauth/client-id';

    private const CLIENT_SECRET_SECRET = 'oauth/client-secret';

    private const REFRESH_TOKEN_SECRET = 'oauth/refresh-token';

    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $config = new OAuthConfig(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: self::CLIENT_ID_SECRET,
            clientSecretSecret: self::CLIENT_SECRET_SECRET,
            grantType: 'client_credentials',
            refreshTokenSecret: self::REFRESH_TOKEN_SECRET,
            scopes: ['read', 'write'],
            tokenExpiryBuffer: 120,
            additionalParams: ['audience' => 'https://api.example.com'],
        );

        self::assertSame(self::TOKEN_ENDPOINT, $config->tokenEndpoint);
        self::assertSame(self::CLIENT_ID_SECRET, $config->clientIdSecret);
        self::assertSame(self::CLIENT_SECRET_SECRET, $config->clientSecretSecret);
        self::assertSame('client_credentials', $config->grantType);
        self::assertSame(self::REFRESH_TOKEN_SECRET, $config->refreshTokenSecret);
        self::assertSame(['read', 'write'], $config->scopes);
        self::assertSame(120, $config->tokenExpiryBuffer);
        self::assertSame(['audience' => 'https://api.example.com'], $config->additionalParams);
    }

    #[Test]
    public function constructorHasCorrectDefaults(): void
    {
        $config = new OAuthConfig(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: self::CLIENT_ID_SECRET,
            clientSecretSecret: self::CLIENT_SECRET_SECRET,
        );

        self::assertSame('client_credentials', $config->grantType);
        self::assertNull($config->refreshTokenSecret);
        self::assertSame([], $config->scopes);
        self::assertSame(60, $config->tokenExpiryBuffer);
        self::assertSame([], $config->additionalParams);
    }

    #[Test]
    public function clientCredentialsCreatesCorrectConfig(): void
    {
        $config = OAuthConfig::clientCredentials(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: self::CLIENT_ID_SECRET,
            clientSecretSecret: self::CLIENT_SECRET_SECRET,
            scopes: ['api.read'],
        );

        self::assertSame(self::TOKEN_ENDPOINT, $config->tokenEndpoint);
        self::assertSame(self::CLIENT_ID_SECRET, $config->clientIdSecret);
        self::assertSame(self::CLIENT_SECRET_SECRET, $config->clientSecretSecret);
        self::assertSame('client_credentials', $config->grantType);
        self::assertNull($config->refreshTokenSecret);
        self::assertSame(['api.read'], $config->scopes);
    }

    #[Test]
    public function refreshTokenCreatesCorrectConfig(): void
    {
        $config = OAuthConfig::refreshToken(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: self::CLIENT_ID_SECRET,
            clientSecretSecret: self::CLIENT_SECRET_SECRET,
            refreshTokenSecret: self::REFRESH_TOKEN_SECRET,
            scopes: ['offline_access'],
        );

        self::assertSame(self::TOKEN_ENDPOINT, $config->tokenEndpoint);
        self::assertSame(self::CLIENT_ID_SECRET, $config->clientIdSecret);
        self::assertSame(self::CLIENT_SECRET_SECRET, $config->clientSecretSecret);
        self::assertSame('refresh_token', $config->grantType);
        self::assertSame(self::REFRESH_TOKEN_SECRET, $config->refreshTokenSecret);
        self::assertSame(['offline_access'], $config->scopes);
    }

    /**
     * Illegal-state guard: a `refresh_token` grant with no refresh-token secret
     * identifier must be rejected at construction time. Otherwise the token
     * manager silently downgrades to client_credentials, hiding a config error.
     */
    #[Test]
    public function constructorRejectsRefreshTokenGrantWithNullSecret(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageMatches('/refreshTokenSecret.*required for the refresh_token grant/i');

        new OAuthConfig(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: self::CLIENT_ID_SECRET,
            clientSecretSecret: self::CLIENT_SECRET_SECRET,
            grantType: 'refresh_token',
            // refreshTokenSecret omitted → null
        );
    }

    #[Test]
    public function constructorRejectsRefreshTokenGrantWithEmptySecret(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageMatches('/refreshTokenSecret.*required for the refresh_token grant/i');

        new OAuthConfig(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: self::CLIENT_ID_SECRET,
            clientSecretSecret: self::CLIENT_SECRET_SECRET,
            grantType: 'refresh_token',
            refreshTokenSecret: '',
        );
    }

    /**
     * Unknown grant types must fail fast rather than reaching the token manager
     * (which only branches on `client_credentials` / `refresh_token`).
     */
    #[Test]
    public function constructorRejectsUnsupportedGrantType(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessageMatches('/grantType.*must be one of/i');

        new OAuthConfig(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: self::CLIENT_ID_SECRET,
            clientSecretSecret: self::CLIENT_SECRET_SECRET,
            grantType: 'password',
        );
    }

    #[Test]
    public function getScopesStringReturnsSpaceSeparatedScopes(): void
    {
        $config = new OAuthConfig(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: self::CLIENT_ID_SECRET,
            clientSecretSecret: self::CLIENT_SECRET_SECRET,
            scopes: ['read', 'write', 'admin'],
        );

        self::assertSame('read write admin', $config->getScopesString());
    }

    #[Test]
    public function getScopesStringReturnsEmptyForNoScopes(): void
    {
        $config = new OAuthConfig(
            tokenEndpoint: self::TOKEN_ENDPOINT,
            clientIdSecret: self::CLIENT_ID_SECRET,
            clientSecretSecret: self::CLIENT_SECRET_SECRET,
            scopes: [],
        );

        self::assertSame('', $config->getScopesString());
    }

    #[Test]
    public function configIsReadonly(): void
    {
        $reflection = new ReflectionClass(OAuthConfig::class);

        self::assertTrue($reflection->isReadOnly());
    }
}
