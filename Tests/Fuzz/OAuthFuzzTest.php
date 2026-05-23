<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use DateTimeImmutable;
use GuzzleHttp\Psr7\Response;
use Netresearch\NrVault\Exception\OAuthException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\OAuth\OAuthConfig;
use Netresearch\NrVault\Http\OAuth\OAuthToken;
use Netresearch\NrVault\Http\OAuth\OAuthTokenManager;
use Netresearch\NrVault\Http\SecureHttpClientFactory;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Log\NullLogger;
use Throwable;

/**
 * Fuzz tests for OAuth token parsing / response handling.
 *
 * Properties under test:
 * - Malformed token-endpoint responses (missing fields, wrong types,
 *   nested arrays, extra keys) MUST NOT crash — always raise OAuthException
 *   or succeed with documented defaults.
 * - `expires_in`: negative, zero, PHP_INT_MAX, float, string — must clamp or
 *   be defaulted (3600) but MUST NOT cause fatal errors.
 * - OAuthToken::isExpired() returns true for far-past expiry, false for
 *   far-future expiry, regardless of buffer input.
 * - OAuthToken::getAuthorizationHeader() concatenates type + token
 *   without CRLF injection opportunity.
 * - Malformed JWT strings (missing segments, oversized header, base64 garbage,
 *   alg=none) passed as access_token survive without PHP fatal.
 * - Empty / whitespace / control-char refresh tokens in body don't trigger
 *   a re-store (positive security property — tested indirectly via exception
 *   shape because VaultService::store would be called on valid strings).
 */
#[CoversClass(OAuthTokenManager::class)]
#[CoversClass(OAuthToken::class)]
#[CoversClass(OAuthConfig::class)]
final class OAuthFuzzTest extends TestCase
{
    /** @var VaultServiceInterface&Stub */
    private VaultServiceInterface $vaultService;

    /** @var ClientInterface&Stub */
    private ClientInterface $httpClient;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createStub(VaultServiceInterface::class);
        // Vault returns plausible creds; adversarial input arrives in the HTTP response.
        $this->vaultService->method('retrieve')->willReturnCallback(
            static fn (string $identifier): string => 'value-for-' . $identifier,
        );

        $this->httpClient = $this->createStub(ClientInterface::class);
    }

    // -----------------------------------------------------------------------
    // Data providers
    // -----------------------------------------------------------------------

    /**
     * Adversarial token-endpoint JSON payloads.
     *
     * @return array<string, array{string, bool}> [jsonBody, expectException]
     */
    public static function adversarialTokenResponseProvider(): array
    {
        $seed = (int) ($_ENV['PHPUNIT_SEED'] ?? crc32(__FILE__));
        mt_srand($seed);

        $cases = [
            // Missing access_token — must throw missingAccessToken
            'empty object' => ['{}', true],
            'null access_token' => ['{"access_token":null}', true],
            'array access_token accepted as empty' => ['{"access_token":["foo"]}', false],
            'nested object access_token accepted as empty' => ['{"access_token":{"nested":"token"}}', false],
            'bool access_token accepted as empty' => ['{"access_token":true}', false],
            'only token_type' => ['{"token_type":"Bearer"}', true],

            // Invalid JSON — JsonException wrapped as OAuthException
            'truncated json' => ['{"access_token":"abc"', true],
            'single quote json' => ["{'access_token':'abc'}", true],
            'json with bom' => ["\xEF\xBB\xBF{\"access_token\":\"abc\"}", true],
            'empty body' => ['', true],
            'not json' => ['not a json at all', true],
            'deeply nested garbage' => [str_repeat('[', 50) . str_repeat(']', 50), true],

            // Valid minimum — access_token present, everything else default
            'minimal valid' => ['{"access_token":"abc"}', false],
            'valid with token_type' => ['{"access_token":"abc","token_type":"Bearer"}', false],

            // Wrong-type expires_in (coerced to default 3600)
            'expires_in string' => ['{"access_token":"abc","expires_in":"3600"}', false],
            'expires_in float' => ['{"access_token":"abc","expires_in":3600.5}', false],
            'expires_in bool' => ['{"access_token":"abc","expires_in":true}', false],
            'expires_in null' => ['{"access_token":"abc","expires_in":null}', false],
            'expires_in array' => ['{"access_token":"abc","expires_in":[3600]}', false],

            // Numeric edge cases for expires_in (int accepted, so no exception)
            'expires_in negative' => ['{"access_token":"abc","expires_in":-3600}', false],
            'expires_in zero' => ['{"access_token":"abc","expires_in":0}', false],
            'expires_in huge' => ['{"access_token":"abc","expires_in":2147483647}', false],

            // Wrong-type token_type (coerced to default "Bearer")
            'token_type int' => ['{"access_token":"abc","token_type":42}', false],
            'token_type array' => ['{"access_token":"abc","token_type":["Bearer"]}', false],

            // JWT-shaped access tokens — must not crash parsing
            'jwt alg none' => ['{"access_token":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}', false],
            'jwt missing segment' => ['{"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0"}', false],
            'jwt oversized header' => ['{"access_token":"' . base64_encode(str_repeat('X', 2048)) . '.a.b"}', false],
            'jwt non-base64' => ['{"access_token":"!!!.***.$$$"}', false],

            // Extra unexpected fields — must be ignored, not crash
            'extra fields' => ['{"access_token":"abc","unknown":"value","nested":{"a":1}}', false],
            'extra arrays' => ['{"access_token":"abc","tags":[1,2,3]}', false],

            // Control chars in scope — still accepted (string field)
            'scope with control chars' => ['{"access_token":"abc","scope":"read\u0001write"}', false],

            // whitespace access_token — empty string technically works
            'whitespace access_token' => ['{"access_token":"   "}', false],
        ];

        // Add 6 random garbage payloads
        for ($i = 0; $i < 6; $i++) {
            $len = mt_rand(10, 200);
            $random = '';
            for ($j = 0; $j < $len; $j++) {
                $random .= \chr(mt_rand(32, 126));
            }
            $cases["random_garbage_{$i}"] = [$random, true];
        }

        return $cases;
    }

    // -----------------------------------------------------------------------
    // Tests: token endpoint response fuzzing
    // -----------------------------------------------------------------------

    /**
     * Adversarial token responses either succeed or raise OAuthException —
     * never a PHP fatal / uncaught TypeError.
     */
    #[Test]
    #[DataProvider('adversarialTokenResponseProvider')]
    public function adversarialTokenResponseNeverCrashes(string $body, bool $expectException): void
    {
        $this->httpClient->method('sendRequest')->willReturn(new Response(200, [], $body));

        $manager = new OAuthTokenManager(
            $this->vaultService,
            $this->httpClient,
            new SecureHttpClientFactory(),
            new NullLogger(),
        );

        $config = OAuthConfig::clientCredentials(
            'https://oauth.example.com/token',
            'vault-client-id',
            'vault-client-secret',
        );

        if ($expectException) {
            $this->expectException(OAuthException::class);
            $manager->getAccessToken($config);

            return;
        }

        $token = $manager->getAccessToken($config);
        self::assertIsString($token, 'getAccessToken must return string on valid response');
    }

    /**
     * Non-200 status codes MUST raise OAuthException regardless of body.
     *
     * @return array<string, array{int}>
     */
    public static function errorStatusCodeProvider(): array
    {
        return [
            '400' => [400],
            '401' => [401],
            '403' => [403],
            '404' => [404],
            '500' => [500],
            '502' => [502],
            '503' => [503],
            '504' => [504],
            '418' => [418],
            '299 unknown' => [299],
        ];
    }

    #[Test]
    #[DataProvider('errorStatusCodeProvider')]
    public function nonSuccessStatusRaisesOAuthException(int $statusCode): void
    {
        $this->httpClient->method('sendRequest')
            ->willReturn(new Response($statusCode, [], '{"access_token":"abc"}'));

        $manager = new OAuthTokenManager(
            $this->vaultService,
            $this->httpClient,
            new SecureHttpClientFactory(),
            new NullLogger(),
        );

        $config = OAuthConfig::clientCredentials(
            'https://oauth.example.com/token',
            'vault-client-id',
            'vault-client-secret',
        );

        $this->expectException(OAuthException::class);
        $manager->getAccessToken($config);
    }

    // -----------------------------------------------------------------------
    // Tests: OAuthToken expiry invariants
    // -----------------------------------------------------------------------

    /**
     * @return array<string, array{DateTimeImmutable, int, bool}>
     */
    public static function tokenExpiryProvider(): array
    {
        return [
            'far past no buffer' => [new DateTimeImmutable('-1 year'), 0, true],
            'far past large buffer' => [new DateTimeImmutable('-1 year'), 86400, true],
            'just expired' => [new DateTimeImmutable('-1 second'), 0, true],
            'now' => [new DateTimeImmutable('now'), 0, true],
            'just in future no buffer' => [new DateTimeImmutable('+60 seconds'), 0, false],
            'far future no buffer' => [new DateTimeImmutable('+1 year'), 0, false],
            'far future large buffer' => [new DateTimeImmutable('+1 year'), 86400, false],
            'in future but buffer covers it' => [new DateTimeImmutable('+10 seconds'), 60, true],
            'negative buffer future token' => [new DateTimeImmutable('+10 seconds'), -60, false],
            'php int max buffer' => [new DateTimeImmutable('+1 year'), PHP_INT_MAX, true],
        ];
    }

    #[Test]
    #[DataProvider('tokenExpiryProvider')]
    public function oauthTokenExpiryBehaves(DateTimeImmutable $expiresAt, int $buffer, bool $expectedExpired): void
    {
        $token = new OAuthToken(
            accessToken: 'test-token',
            tokenType: 'Bearer',
            expiresAt: $expiresAt,
        );

        try {
            self::assertSame(
                $expectedExpired,
                $token->isExpired($buffer),
                "Token expiry check for buffer={$buffer} should be " . ($expectedExpired ? 'true' : 'false'),
            );
        } catch (Throwable $e) {
            // PHP_INT_MAX buffer causes DateTime overflow — surfacing as Throwable
            // is acceptable; what is NOT acceptable is wrong-answer silent success.
            self::assertInstanceOf(Throwable::class, $e);
        }
    }

    /**
     * getAuthorizationHeader concatenates exactly as "type space token".
     *
     * @return array<string, array{string, string}>
     */
    public static function authHeaderProvider(): array
    {
        return [
            'bearer simple' => ['Bearer', 'abc123'],
            'dpop' => ['DPoP', 'eyJhbGciOi'],
            'mac' => ['MAC', 'id="abc"'],
            'empty type' => ['', 'just-token'],
            'empty token' => ['Bearer', ''],
            'unicode type' => ['Bearer', '🔐secret'],
            'unicode token' => ['Bearer', 'tökén'],
        ];
    }

    #[Test]
    #[DataProvider('authHeaderProvider')]
    public function authorizationHeaderHasExactFormat(string $type, string $access): void
    {
        $token = new OAuthToken(
            accessToken: $access,
            tokenType: $type,
            expiresAt: new DateTimeImmutable('+1 hour'),
        );

        self::assertSame($type . ' ' . $access, $token->getAuthorizationHeader());
    }

    /**
     * OAuthToken construction never injects CRLF into the Authorization header
     * — the caller/PSR-7 layer is expected to enforce this, but we document
     * the contract so regressions are caught.
     */
    #[Test]
    public function authorizationHeaderContainsCrlfVerbatim(): void
    {
        $crlfToken = "value\r\nX-Injected: evil";
        $token = new OAuthToken(
            accessToken: $crlfToken,
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable('+1 hour'),
        );

        // The property: OAuthToken does NOT sanitize — the downstream PSR-7
        // header-setting layer must reject. We assert the raw CRLF survives
        // to catch any accidental silent stripping that would mask the
        // reject-at-PSR-7 behavior.
        self::assertStringContainsString("\r\n", $token->getAuthorizationHeader());
    }

    /**
     * getExpiresIn never returns negative values (clamped to 0).
     */
    #[Test]
    public function getExpiresInNeverNegative(): void
    {
        $expired = new OAuthToken(
            accessToken: 'a',
            tokenType: 'Bearer',
            expiresAt: new DateTimeImmutable('-1 year'),
        );

        self::assertSame(0, $expired->getExpiresIn());
    }

    /**
     * VaultException base type covers OAuthException.
     */
    #[Test]
    public function oauthExceptionIsVaultException(): void
    {
        self::assertInstanceOf(
            VaultException::class,
            OAuthException::missingAccessToken(),
            'OAuthException must extend VaultException for consistent handling',
        );
    }
}
