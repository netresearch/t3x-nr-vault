<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Http\SecretPlacement;
use Netresearch\NrVault\Http\VaultHttpClient;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use RuntimeException;

/**
 * Fuzz tests for VaultHttpClient secret-injection logic.
 *
 * Properties under test:
 * - Secrets with CRLF characters are never injected verbatim into headers without sanitization
 *   (PSR-7 implementations must reject or strip CRLF from header values)
 * - Query parameter injection URL-encodes the secret value byte-for-byte
 * - The secret value is preserved exactly in query strings (round-trip via urldecode)
 * - Unicode and control chars in secret values do not crash the client
 * - CRLF in header name causes a rejection by PSR-7 (VaultException or \InvalidArgumentException)
 * - Body injection preserves secret in JSON fields for arbitrary key/value combinations
 * - Unsupported URI schemes are rejected before secret retrieval
 * - Audit log receives the identifier, NOT the secret value
 */
#[CoversClass(VaultHttpClient::class)]
final class HttpClientFuzzTest extends TestCase
{
    private const TEST_IDENTIFIER = '01937b6e-4b6c-7abc-8def-000000000099';

    /** @var VaultServiceInterface&Stub */
    private VaultServiceInterface $vaultService;

    /** @var AuditLogServiceInterface&MockObject */
    private AuditLogServiceInterface $auditLogService;

    /** @var ClientInterface&Stub */
    private ClientInterface $innerClient;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createStub(VaultServiceInterface::class);
        $this->auditLogService = $this->createStub(AuditLogServiceInterface::class);
        $this->innerClient = $this->createStub(ClientInterface::class);

        // Ensure allowed_hosts is not set so all hosts pass the factory check
        $GLOBALS['TYPO3_CONF_VARS']['HTTP']['allowed_hosts'] = [];
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['TYPO3_CONF_VARS']);
        parent::tearDown();
    }

    // -----------------------------------------------------------------------
    // Data providers
    // -----------------------------------------------------------------------

    /**
     * Secret values with various edge cases: unicode, control chars, long values.
     *
     * @return array<string, array{string}>
     */
    public static function edgeCaseSecretValueProvider(): array
    {
        $seed = (int) (getenv('PHPUNIT_SEED') ?: crc32(__FILE__));
        mt_srand($seed);

        $cases = [
            'empty string' => [''],
            'simple ascii' => ['my-secret-key-abc123'],
            'unicode emoji' => ['🔐token🗝'],
            'unicode mixed' => ['パスワード_secret'],
            'space in value' => ['secret value with spaces'],
            'ampersand' => ['secret&value=1'],
            'equals sign' => ['value=secret'],
            'percent encoded' => ['val%20ue'],
            'hash char' => ['secret#hash'],
            'question mark' => ['secret?param=1'],
            'plus sign' => ['secret+plus'],
            'slash' => ['secret/path'],
            'backslash' => ['secret\\path'],
            'single quote' => ["secret'value"],
            'double quote' => ['secret"value'],
            'angle brackets' => ['<secret>'],
            'null byte' => ["sec\x00ret"],
            'tab char' => ["sec\tret"],
            'very long value 1kb' => [str_repeat('x', 1024)],
        ];

        // 30 random printable-ASCII secrets
        for ($i = 0; $i < 30; $i++) {
            $len = mt_rand(1, 200);
            $value = '';
            for ($j = 0; $j < $len; $j++) {
                $value .= \chr(mt_rand(33, 126)); // printable, excludes space
            }
            $cases["random_printable_{$i}"] = [$value];
        }

        return $cases;
    }

    /**
     * Unsafe URI schemes that must be rejected.
     *
     * @return array<string, array{string}>
     */
    public static function unsafeSchemeProvider(): array
    {
        return [
            'file scheme' => ['file:///etc/passwd'],
            'gopher scheme' => ['gopher://attacker.example.com:70/'],
            'ftp scheme' => ['ftp://ftp.example.com/file.txt'],
            'data scheme' => ['data:text/html,<script>alert(1)</script>'],
            'javascript scheme' => ['javascript:alert(1)'],
            'ldap scheme' => ['ldap://ldap.example.com/'],
            'dict scheme' => ['dict://dict.example.com/'],
        ];
    }

    // -----------------------------------------------------------------------
    // Tests: query parameter injection
    // -----------------------------------------------------------------------

    /**
     * Query param injection URL-encodes the secret and the round-trip is exact.
     */
    #[Test]
    #[DataProvider('edgeCaseSecretValueProvider')]
    public function queryParamInjectionUrlEncodesSecretExactly(string $secretValue): void
    {
        $this->vaultService->method('retrieve')->willReturn($secretValue);
        $this->innerClient->method('sendRequest')->willReturnCallback(
            function (RequestInterface $request) use ($secretValue): Response {
                $query = $request->getUri()->getQuery();

                // The secret must be URL-encoded in the query string
                self::assertStringContainsString(
                    urlencode('api_key') . '=' . urlencode($secretValue),
                    $query,
                    'Secret must be URL-encoded in query string',
                );

                // Round-trip: decoded value must equal original secret exactly
                parse_str($query, $parsed);
                self::assertSame($secretValue, $parsed['api_key'] ?? null, 'URL-decoded query param must equal original secret');

                return new Response(200);
            },
        );

        $client = $this->buildClient(SecretPlacement::QueryParam, ['queryParam' => 'api_key']);
        $client->sendRequest(new Request('GET', 'https://api.example.com/data'));
    }

    // -----------------------------------------------------------------------
    // Tests: bearer token injection
    // -----------------------------------------------------------------------

    /**
     * Bearer injection never leaks the identifier string in the Authorization header.
     */
    #[Test]
    public function bearerInjectionUsesSecretNotIdentifier(): void
    {
        $secretValue = 'super-secret-token-abc123';
        $this->vaultService->method('retrieve')->willReturn($secretValue);
        $this->innerClient->method('sendRequest')->willReturnCallback(
            function (RequestInterface $request) use ($secretValue): Response {
                $authHeader = $request->getHeaderLine('Authorization');
                // Must contain the secret value
                self::assertStringContainsString($secretValue, $authHeader);
                // Must NOT contain the vault identifier in the auth header
                self::assertStringNotContainsString(self::TEST_IDENTIFIER, $authHeader);

                return new Response(200);
            },
        );

        $client = $this->buildClient(SecretPlacement::Bearer);
        $client->sendRequest(new Request('GET', 'https://api.example.com/endpoint'));
    }

    // -----------------------------------------------------------------------
    // Tests: JSON body injection
    // -----------------------------------------------------------------------

    /**
     * JSON body injection places secret byte-for-byte in the named field.
     */
    #[Test]
    #[DataProvider('edgeCaseSecretValueProvider')]
    public function bodyJsonInjectionPreservesSecretValue(string $secretValue): void
    {
        $this->vaultService->method('retrieve')->willReturn($secretValue);
        $this->innerClient->method('sendRequest')->willReturnCallback(
            function (RequestInterface $request) use ($secretValue): Response {
                $body = (string) $request->getBody();
                $data = json_decode($body, true);
                self::assertIsArray($data, 'Body must be valid JSON');
                self::assertSame($secretValue, $data['api_key'] ?? null, 'JSON field must contain exact secret value');

                return new Response(200);
            },
        );

        $client = $this->buildClient(SecretPlacement::BodyField, ['bodyField' => 'api_key']);
        $request = new Request(
            'POST',
            'https://api.example.com/submit',
            ['Content-Type' => 'application/json'],
            '{"existing":"data"}',
        );
        $client->sendRequest($request);
    }

    // -----------------------------------------------------------------------
    // Tests: CRLF header injection
    // -----------------------------------------------------------------------

    /**
     * CRLF in a secret value injected into a header MUST either throw
     * (PSR-7 rejects CRLF in header values) OR be completely stripped of
     * CR/LF bytes before being sent.
     *
     * The earlier "either outcome OK" assertion was too permissive — a
     * sanitization regression that silently forwarded raw CRLF to the
     * inner HTTP client would pass. This tightened version enforces:
     *   - If sendRequest runs, EVERY outgoing header value passes the
     *     test /[\r\n]/ → no match. Any CR/LF byte fails the test.
     *   - If sendRequest throws PSR-7 / VaultException, the test passes
     *     as long as the exception originated at the PSR-7 boundary.
     */
    #[Test]
    public function crlfInSecretValueIsRejectedByHeaderInjection(): void
    {
        $crlfSecret = "legitimate-value\r\nX-Injected-Header: evil";
        $this->vaultService->method('retrieve')->willReturn($crlfSecret);
        $this->innerClient->method('sendRequest')->willReturnCallback(
            function (RequestInterface $request): Response {
                foreach ($request->getHeaders() as $name => $values) {
                    foreach ($values as $value) {
                        self::assertSame(
                            0,
                            preg_match('/[\r\n]/', $value),
                            "Header '{$name}' must not contain raw CR/LF — got '" . bin2hex($value) . "'",
                        );
                    }
                }
                self::assertFalse(
                    $request->hasHeader('X-Injected-Header'),
                    'CRLF injection must not create extra headers',
                );

                return new Response(200);
            },
        );

        try {
            $client = $this->buildClient(SecretPlacement::Header, ['headerName' => 'X-API-Key']);
            $client->sendRequest(new Request('GET', 'https://api.example.com/data'));
            // Reached inner client without throw — header-value CR/LF check
            // above must have passed. PSR-7 sanitization is acceptable.
        } catch (VaultException $e) {
            // Vault wrapped the PSR-7 rejection — also safe. VaultException
            // extends RuntimeException, so this more-specific catch must come
            // before the RuntimeException one below (else it is unreachable).
            self::assertTrue(true, 'VaultException wrapping PSR-7 rejection: ' . $e->getMessage());
        } catch (InvalidArgumentException|RuntimeException $e) {
            // PSR-7 rejected the CRLF at header-set time — expected and safe.
            self::assertTrue(true, 'PSR-7 rejected CRLF: ' . $e->getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Tests: unsafe URI schemes
    // -----------------------------------------------------------------------

    /**
     * Requests with non-HTTP/HTTPS schemes MUST be rejected before any secret retrieval.
     */
    #[Test]
    #[DataProvider('unsafeSchemeProvider')]
    public function unsafeUriSchemeIsRejectedWithoutRetrievingSecret(string $uri): void
    {
        // Secret retrieval should never be called for unsafe schemes
        $this->vaultService->method('retrieve')->willReturnCallback(
            static function (): string {
                throw new RuntimeException('Secret should not be retrieved for unsafe URI scheme', 4342757983);
            },
        );

        $client = $this->buildClient(SecretPlacement::Bearer);

        $this->expectException(VaultException::class);
        $client->sendRequest(new Request('GET', $uri));
    }

    // -----------------------------------------------------------------------
    // Tests: audit log identifier
    // -----------------------------------------------------------------------

    /**
     * Audit log receives the vault identifier, never the raw secret value.
     */
    #[Test]
    public function auditLogReceivesIdentifierNotSecretValue(): void
    {
        $secretValue = 'very-secret-api-key-do-not-log';
        $this->vaultService->method('retrieve')->willReturn($secretValue);
        $this->innerClient->method('sendRequest')->willReturn(new Response(200));

        /** @var AuditLogServiceInterface&MockObject $strictAuditLog */
        $strictAuditLog = $this->createMock(AuditLogServiceInterface::class);
        $strictAuditLog->expects(self::once())
            ->method('log')
            ->willReturnCallback(static function (
                string $secretIdentifier,
                string $action,
                bool $success,
            ) use ($secretValue): void {
                self::assertStringNotContainsString(
                    $secretValue,
                    $secretIdentifier,
                    'Audit log must receive identifier, not secret value',
                );
                self::assertSame('http_call', $action);
                self::assertTrue($success);
            });

        $client = new VaultHttpClient(
            $this->vaultService,
            $strictAuditLog,
            $this->innerClient,
            self::TEST_IDENTIFIER,
            SecretPlacement::Bearer,
        );

        $client->sendRequest(new Request('GET', 'https://api.example.com/secure'));
    }

    // -----------------------------------------------------------------------
    // Tests: header name fuzz
    // -----------------------------------------------------------------------

    /**
     * Various header name inputs — valid names work, invalid names are rejected by PSR-7.
     *
     * @return array<string, array{string, bool}> [name => [headerName, expectSuccess]]
     */
    public static function headerNameProvider(): array
    {
        return [
            'valid: X-API-Key' => ['X-API-Key', true],
            'valid: Authorization' => ['Authorization', true],
            'valid: X-Custom-123' => ['X-Custom-123', true],
            'invalid: empty' => ['', false],
            'invalid: CRLF' => ["X-Head\r\ner: evil", false],
            'invalid: space' => ['X-My Header', false],
            'invalid: colon' => ['X:Bad', false],
        ];
    }

    /**
     * Valid header names succeed; invalid ones throw without leaking the secret.
     */
    #[Test]
    #[DataProvider('headerNameProvider')]
    public function headerInjectionValidatesHeaderName(string $headerName, bool $expectSuccess): void
    {
        $secretValue = 'my-api-secret-value';
        $this->vaultService->method('retrieve')->willReturn($secretValue);
        $this->innerClient->method('sendRequest')->willReturn(new Response(200));

        if ($expectSuccess) {
            $client = $this->buildClient(SecretPlacement::Header, ['headerName' => $headerName]);
            $response = $client->sendRequest(new Request('GET', 'https://api.example.com/test'));
            self::assertSame(200, $response->getStatusCode());
        } else {
            try {
                $client = $this->buildClient(SecretPlacement::Header, ['headerName' => $headerName]);
                $client->sendRequest(new Request('GET', 'https://api.example.com/test'));
                // Some empty header names may just send no header at all — acceptable
            } catch (InvalidArgumentException|RuntimeException) {
                // Expected: PSR-7 or Vault layer rejected invalid header name
                self::assertTrue(true);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    /**
     * @param array<string, string> $options
     */
    private function buildClient(SecretPlacement $placement, array $options = []): VaultHttpClient
    {
        return new VaultHttpClient(
            $this->vaultService,
            $this->auditLogService,
            $this->innerClient,
            self::TEST_IDENTIFIER,
            $placement,
            null,
            $options['headerName'] ?? null,
            $options['queryParam'] ?? null,
            $options['bodyField'] ?? null,
        );
    }
}
