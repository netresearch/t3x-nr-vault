<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http\OAuth;

use Netresearch\NrVault\Http\OAuth\OAuthTokenRequestParams;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * This value object holds OAuth client credentials in plaintext between the
 * vault read and the token POST. Two properties matter beyond the encoding:
 * every field that reaches the wire must be exactly the one that was set (the
 * per-deployment escape hatch can silently shadow a credential), and
 * `wipeCredentials()` must leave nothing behind for a stack trace to dump.
 */
#[CoversClass(OAuthTokenRequestParams::class)]
final class OAuthTokenRequestParamsTest extends TestCase
{
    #[Test]
    public function requiredFieldsAreAlwaysPresentInTheBody(): void
    {
        $clientId = $this->fakeCredential('client-id');
        $clientSecret = $this->fakeCredential('client-secret');

        $params = new OAuthTokenRequestParams('client_credentials', $clientId, $clientSecret);

        self::assertSame(
            [
                'grant_type' => 'client_credentials',
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
            ],
            $this->decode($params->toHttpQuery()),
        );
    }

    /**
     * Sending `scope=` or `refresh_token=` when neither was configured makes
     * strict token endpoints reject the request, so absent must stay absent
     * rather than becoming an empty field.
     */
    #[Test]
    public function optionalFieldsAreOmittedWhenNotConfigured(): void
    {
        $params = new OAuthTokenRequestParams(
            'client_credentials',
            $this->fakeCredential('client-id'),
            $this->fakeCredential('client-secret'),
        );

        $decoded = $this->decode($params->toHttpQuery());

        self::assertArrayNotHasKey('scope', $decoded);
        self::assertArrayNotHasKey('refresh_token', $decoded);
    }

    #[Test]
    public function scopeIsIncludedWhenConfigured(): void
    {
        $params = new OAuthTokenRequestParams(
            'client_credentials',
            $this->fakeCredential('client-id'),
            $this->fakeCredential('client-secret'),
            'read:secrets write:secrets',
        );

        self::assertSame('read:secrets write:secrets', $this->decode($params->toHttpQuery())['scope'] ?? null);
    }

    /**
     * An explicitly configured empty scope is a deliberate "ask for the default
     * scope set" and is distinct from "no scope configured".
     */
    #[Test]
    public function explicitlyEmptyScopeIsStillSent(): void
    {
        $params = new OAuthTokenRequestParams(
            'client_credentials',
            $this->fakeCredential('client-id'),
            $this->fakeCredential('client-secret'),
            '',
        );

        $decoded = $this->decode($params->toHttpQuery());

        self::assertArrayHasKey('scope', $decoded);
        self::assertSame('', $decoded['scope']);
    }

    #[Test]
    public function refreshTokenIsIncludedForTheRefreshGrant(): void
    {
        $refreshToken = $this->fakeCredential('refresh-token');

        $params = new OAuthTokenRequestParams(
            'refresh_token',
            $this->fakeCredential('client-id'),
            $this->fakeCredential('client-secret'),
            null,
            $refreshToken,
        );

        $decoded = $this->decode($params->toHttpQuery());

        self::assertSame('refresh_token', $decoded['grant_type']);
        self::assertSame($refreshToken, $decoded['refresh_token'] ?? null);
    }

    #[Test]
    public function additionalParamsAreAppendedToTheBody(): void
    {
        $params = new OAuthTokenRequestParams(
            'client_credentials',
            $this->fakeCredential('client-id'),
            $this->fakeCredential('client-secret'),
            null,
            null,
            ['audience' => 'https://api.example.com', 'resource' => 'urn:example:api'],
        );

        $decoded = $this->decode($params->toHttpQuery());

        self::assertSame('https://api.example.com', $decoded['audience'] ?? null);
        self::assertSame('urn:example:api', $decoded['resource'] ?? null);
    }

    /**
     * `array_merge()` puts the escape hatch last, so a deployment-supplied key
     * shadows the credential composed from the vault. Whoever configures
     * `additionalParams` can therefore replace what is authenticated with —
     * pinned here so the precedence cannot flip unnoticed.
     */
    #[Test]
    public function additionalParamsOverrideTheComposedCredentials(): void
    {
        $vaultSecret = $this->fakeCredential('vault-client-secret');
        $overrideSecret = $this->fakeCredential('override-client-secret');

        $params = new OAuthTokenRequestParams(
            'client_credentials',
            $this->fakeCredential('client-id'),
            $vaultSecret,
            null,
            null,
            ['client_secret' => $overrideSecret],
        );

        $decoded = $this->decode($params->toHttpQuery());

        self::assertSame($overrideSecret, $decoded['client_secret']);
        self::assertNotSame($vaultSecret, $decoded['client_secret']);
    }

    /**
     * Credentials routinely contain `&`, `=`, `+` and `%`. Unencoded, those
     * would split the body and truncate or corrupt the secret in transit.
     */
    #[Test]
    public function reservedCharactersInCredentialsSurviveTheEncoding(): void
    {
        $awkwardSecret = 'fake+secret&with=reserved%chars and spaces/ü';

        $params = new OAuthTokenRequestParams(
            'client_credentials',
            $this->fakeCredential('client-id'),
            $awkwardSecret,
        );

        $query = $params->toHttpQuery();

        self::assertStringNotContainsString('&with=', $query, 'A raw & would split the body into extra fields');
        self::assertSame($awkwardSecret, $this->decode($query)['client_secret']);
    }

    #[Test]
    public function wipeCredentialsClearsEveryCredentialField(): void
    {
        $params = new OAuthTokenRequestParams(
            'refresh_token',
            $this->fakeCredential('client-id'),
            $this->fakeCredential('client-secret'),
            'read:secrets',
            $this->fakeCredential('refresh-token'),
        );

        $params->wipeCredentials();

        $this->assertZeroized($params->clientId);
        $this->assertZeroized($params->clientSecret);
        self::assertNull($params->refreshToken);
    }

    /**
     * The non-credential fields describe the request, not the caller's
     * identity — wiping must not damage them, or a retry would build a
     * different request than the one that failed.
     */
    #[Test]
    public function wipeCredentialsLeavesTheNonSecretFieldsIntact(): void
    {
        $params = new OAuthTokenRequestParams(
            'client_credentials',
            $this->fakeCredential('client-id'),
            $this->fakeCredential('client-secret'),
            'read:secrets',
            null,
            ['audience' => 'https://api.example.com'],
        );

        $params->wipeCredentials();

        self::assertSame('client_credentials', $params->grantType);
        self::assertSame('read:secrets', $params->scope);
        self::assertSame(['audience' => 'https://api.example.com'], $params->additionalParams);
    }

    /**
     * Pins the documented idempotency contract: PHP's `sodium_memzero()`
     * converts the zval to NULL after zeroing it, so without the guard flag a
     * second wipe on a failure path would raise a SodiumException and replace
     * the real error. The guard makes repeat calls no-ops.
     */
    #[Test]
    public function aSecondWipeIsANoOpInsteadOfRaising(): void
    {
        $params = new OAuthTokenRequestParams(
            'refresh_token',
            $this->fakeCredential('client-id'),
            $this->fakeCredential('client-secret'),
            null,
            $this->fakeCredential('refresh-token'),
        );

        $params->wipeCredentials();
        $params->wipeCredentials();

        $this->assertZeroized($params->clientId);
        $this->assertZeroized($params->clientSecret);
        self::assertNull($params->refreshToken);
    }

    #[Test]
    public function wipeCredentialsWithoutARefreshTokenDoesNotFail(): void
    {
        $params = new OAuthTokenRequestParams(
            'client_credentials',
            $this->fakeCredential('client-id'),
            $this->fakeCredential('client-secret'),
        );

        $params->wipeCredentials();

        self::assertNull($params->refreshToken);
    }

    /**
     * The point of the wipe: after it, nothing that re-reads the object — a
     * retry, a dump, a serialiser — can recover the credential material. The
     * zeroed fields drop out of the body entirely, because `http_build_query()`
     * skips the nulls `sodium_memzero()` leaves behind.
     */
    #[Test]
    public function bodyBuiltAfterTheWipeCarriesNoCredentialMaterial(): void
    {
        $clientSecret = $this->fakeCredential('client-secret');
        $refreshToken = $this->fakeCredential('refresh-token');
        // urlencode() returns fresh strings, so these needles survive the
        // in-place zeroing that wipeCredentials() performs on the properties.
        $secretNeedle = urlencode($clientSecret);
        $refreshNeedle = urlencode($refreshToken);

        $params = new OAuthTokenRequestParams(
            'refresh_token',
            $this->fakeCredential('client-id'),
            $clientSecret,
            null,
            $refreshToken,
        );

        $params->wipeCredentials();

        $query = $params->toHttpQuery();

        $decoded = $this->decode($query);

        self::assertStringNotContainsString($secretNeedle, $query);
        self::assertStringNotContainsString($refreshNeedle, $query);
        self::assertArrayNotHasKey('client_id', $decoded);
        self::assertArrayNotHasKey('client_secret', $decoded);
        self::assertArrayNotHasKey('refresh_token', $decoded);
    }

    /**
     * `sodium_memzero()` overwrites the string buffer and then converts the
     * zval to NULL, so a wiped credential reads back as null on every
     * supported PHP version — not as the empty string the class docblock
     * describes. Accept either so the assertion tracks "unreadable", not the
     * ext-sodium implementation detail.
     */
    private function assertZeroized(mixed $value): void
    {
        self::assertContains($value, [null, ''], 'Credential was not zeroized');
    }

    /**
     * @return array<string, string>
     */
    private function decode(string $query): array
    {
        parse_str($query, $decoded);

        /** @var array<string, string> $decoded */
        return $decoded;
    }

    /**
     * A clearly synthetic, runtime-generated stand-in for credential material.
     */
    private function fakeCredential(string $label): string
    {
        return 'FAKE-TEST-' . $label . '-' . bin2hex(random_bytes(8));
    }
}
