<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\FlexFormVaultResolver;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Netresearch\NrVault\Utility\VaultFieldResolver;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use stdClass;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

/**
 * Fuzz tests for identifier validation and parsing.
 *
 * These tests ensure that malicious, malformed, or edge case inputs
 * are handled gracefully without crashes or security vulnerabilities.
 *
 * Both VaultFieldResolver and FlexFormVaultResolver now use UUID v7 format.
 */
#[CoversClass(VaultFieldResolver::class)]
#[CoversClass(FlexFormVaultResolver::class)]
#[CoversClass(IdentifierValidator::class)]
#[AllowMockObjectsWithoutExpectations]
final class IdentifierFuzzTest extends TestCase
{
    private VaultFieldResolver $vaultFieldResolver;

    private FlexFormVaultResolver $flexFormVaultResolver;

    protected function setUp(): void
    {
        parent::setUp();

        // Create resolvers with mock dependencies
        // isVaultIdentifier() is a pure function that doesn't use dependencies
        /** @var VaultServiceInterface&MockObject $vaultService */
        $vaultService = $this->createMock(VaultServiceInterface::class);
        /** @var TcaSchemaFactory&MockObject $tcaSchemaFactory */
        $tcaSchemaFactory = $this->createMock(TcaSchemaFactory::class);
        /** @var LoggerInterface&MockObject $logger */
        $logger = $this->createMock(LoggerInterface::class);

        $this->vaultFieldResolver = new VaultFieldResolver(
            $vaultService,
            $tcaSchemaFactory,
            $logger,
        );

        $this->flexFormVaultResolver = new FlexFormVaultResolver(
            $vaultService,
            $logger,
            $tcaSchemaFactory,
        );
    }

    /**
     * Test VaultFieldResolver with fuzzed inputs.
     *
     * Validates that isVaultIdentifier never throws and returns boolean.
     */
    #[Test]
    #[DataProvider('fuzzedIdentifierProvider')]
    public function vaultFieldResolverHandlesFuzzedInput(mixed $input): void
    {
        // Should not throw exceptions
        $result = $this->vaultFieldResolver->isVaultIdentifier($input);
        self::assertIsBool($result);
    }

    /**
     * Test FlexFormVaultResolver with fuzzed inputs.
     *
     * Validates that isVaultIdentifier never throws and returns boolean.
     */
    #[Test]
    #[DataProvider('fuzzedIdentifierProvider')]
    public function flexFormVaultResolverHandlesFuzzedInput(mixed $input): void
    {
        $result = $this->flexFormVaultResolver->isVaultIdentifier($input);
        self::assertIsBool($result);
    }

    /**
     * Test IdentifierValidator with fuzzed inputs.
     *
     * For non-string inputs, we verify the method handles them gracefully.
     */
    #[Test]
    #[DataProvider('fuzzedIdentifierProvider')]
    public function identifierValidatorHandlesFuzzedInput(mixed $input): void
    {
        // Should not throw exceptions for any input
        if (\is_string($input)) {
            $result = IdentifierValidator::isValid($input);
            self::assertIsBool($result);
        } else {
            // Non-string inputs: verify no exception is thrown by other methods
            self::assertFalse($this->vaultFieldResolver->isVaultIdentifier($input));
        }
    }

    /**
     * Provide fuzzed identifier values for testing.
     */
    public static function fuzzedIdentifierProvider(): array
    {
        return [
            // Null and empty
            'null' => [null],
            'empty string' => [''],
            'whitespace only' => ['   '],
            'tab and newline' => ["\t\n\r"],

            // Type confusion
            'integer zero' => [0],
            'integer positive' => [12345],
            'integer negative' => [-1],
            'float' => [3.14159],
            'boolean true' => [true],
            'boolean false' => [false],
            'empty array' => [[]],
            'array with values' => [['a', 'b', 'c']],
            'nested array' => [['a' => ['b' => 'c']]],
            'object' => [new stdClass()],

            // Injection attempts
            'sql injection single quote' => ["01937b6e-4b6c-7abc-8def-'; DROP TABLE users; --"],
            'sql injection double quote' => ['01937b6e-4b6c-7abc-8def-" OR "1"="1'],
            'sql injection union' => ['01937b6e-4b6c-7abc-8def-0123456789ab UNION SELECT'],

            // XSS attempts
            'xss script tag' => ['<script>alert("xss")</script>'],
            'xss img onerror' => ['<img src=x onerror=alert(1)>'],
            'xss event handler' => ['onload=alert(1)'],

            // Path traversal
            'path traversal dots' => ['../../../etc/passwd'],
            'path traversal encoded' => ['..%2F..%2F..%2Fetc%2Fpasswd'],

            // Unicode and encoding
            'unicode null' => ["01937b6e-4b6c-7abc-8def-\u0000"],
            'unicode bom' => ["\xEF\xBB\xBF01937b6e-4b6c-7abc-8def-0123456789ab"],
            'unicode rtl override' => ["01937b6e-4b6c-7abc-8def-\u202E"],
            'unicode emoji' => ['01937b6e-4b6c-7abc-8def-0123456789ab🔥'],

            // UUID edge cases
            'uuid v1' => ['01937b6e-4b6c-1abc-8def-0123456789ab'],
            'uuid v2' => ['01937b6e-4b6c-2abc-8def-0123456789ab'],
            'uuid v3' => ['01937b6e-4b6c-3abc-8def-0123456789ab'],
            'uuid v4' => ['01937b6e-4b6c-4abc-8def-0123456789ab'],
            'uuid v5' => ['01937b6e-4b6c-5abc-8def-0123456789ab'],
            'uuid wrong variant' => ['01937b6e-4b6c-7abc-cdef-0123456789ab'],
            'uuid too short' => ['01937b6e-4b6c-7abc-8def'],
            'uuid too long' => ['01937b6e-4b6c-7abc-8def-0123456789ab1'],
            'uuid missing hyphens' => ['01937b6e4b6c7abc8def0123456789ab'],
            'uuid extra hyphens' => ['0193-7b6e-4b6c-7abc-8def-0123456789ab'],

            // Old format (should be rejected)
            'old format table__field__uid' => ['tx_test__api_key__42'],
            'old format flexform' => ['tt_content__pi_flexform__settings__apiKey__123'],

            // Long strings. The identifier validator clamps on MAX_LENGTH long
            // before these; we only need to prove handlers never crash on
            // oversized input. 8 KB is 200x the realistic UUID length — enough
            // to exercise any length-guard regressions without ballooning
            // PHPUnit memory usage when the provider runs under mutation
            // testing (each case is re-serialised per mutant).
            'very long random' => [str_repeat('a', 1000)],
            'eight kilobytes' => [str_repeat('y', 8 * 1024)],

            // Special characters
            'newline in middle' => ["01937b6e-4b6c\n-7abc-8def-0123456789ab"],
            'carriage return' => ["01937b6e-4b6c\r-7abc-8def-0123456789ab"],
            'null byte' => ["01937b6e-4b6c\x00-7abc-8def-0123456789ab"],
            'backslash' => ['01937b6e\\-4b6c-7abc-8def-0123456789ab'],

            // Unicode abuse: RTL override and zero-width characters
            'rtl override char' => ["\u{202E}01937b6e-4b6c-7abc-8def-0123456789ab"],
            'rtl override mid-uuid' => ["01937b6e-4b6c-\u{202E}7abc-8def-0123456789ab"],
            'zero-width joiner' => ["01937b6e\u{200D}-4b6c-7abc-8def-0123456789ab"],
            'zero-width non-joiner' => ["01937b6e\u{200C}-4b6c-7abc-8def-0123456789ab"],
            'zero-width no-break space' => ["\u{FEFF}01937b6e-4b6c-7abc-8def-0123456789ab"],
            'left-to-right mark' => ["\u{200E}01937b6e-4b6c-7abc-8def-0123456789ab"],
            'homoglyph: cyrillic a' => ['01937b6е-4b6c-7abc-8def-0123456789ab'], // е is U+0435

            // Path traversal variants
            'path traversal unix' => ['../../../etc/passwd'],
            'path traversal windows' => ['..\\..\\windows\\system32'],
            'path traversal encoded forward slash' => ['..%2F..%2Fetc%2Fpasswd'],
            'path traversal double encoded' => ['..%252F..%252Fetc%252Fpasswd'],
            'path traversal null byte' => ["../etc/passwd\x00.jpg"],
            'path traversal url encoded dot' => ['%2e%2e%2fetc%2fpasswd'],

            // Null bytes and CR/LF injection
            'null byte only' => ["\x00"],
            'crlf injection' => ["valid-prefix\r\nX-Injected: evil"],
            'cr only injection' => ["valid-prefix\rX-Injected: evil"],
            'lf only injection' => ["valid-prefix\nX-Injected: evil"],
            'null byte mid string' => ["abc\x00def"],

            // Non-UTF-8 binary data
            'invalid utf8 continuation' => ["\x80\x81\x82"],
            'overlong utf8 encoding' => ["\xC0\xAF"],
            'lone surrogate' => ["\xED\xA0\x80"],
            'raw binary 16 bytes' => ["\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"],

            // Valid UUIDs
            'valid uuid lowercase' => ['01937b6e-4b6c-7abc-8def-0123456789ab'],
            'valid uuid uppercase' => ['01937B6E-4B6C-7ABC-8DEF-0123456789AB'],
            'valid uuid mixed' => ['01937b6e-4B6C-7abc-8DEF-0123456789ab'],
        ];
    }

    /**
     * Test that identifier parsing never accepts injection patterns.
     */
    #[Test]
    #[DataProvider('injectionPatternProvider')]
    public function parsingRejectsInjectionPatterns(string $input): void
    {
        // These should all be rejected
        self::assertFalse($this->vaultFieldResolver->isVaultIdentifier($input));
        self::assertFalse($this->flexFormVaultResolver->isVaultIdentifier($input));
    }

    public static function injectionPatternProvider(): array
    {
        return [
            'sql comment' => ['01937b6e-4b6c-7abc-8def-0123456789ab--'],
            'sql semicolon' => ['01937b6e-4b6c-7abc-8def-0123456789ab;'],
            'sql or' => ['01937b6e-4b6c-7abc-8def-0123456789ab OR 1=1'],
            'shell command' => ['01937b6e-4b6c-7abc-8def-0123456789ab; rm -rf /'],
            'shell backtick' => ['01937b6e-4b6c-7abc-`whoami`'],
            'shell dollar' => ['01937b6e-4b6c-7abc-$(whoami)'],
            'ldap injection' => ['01937b6e-4b6c-7abc-8def-0123456789ab)(cn=*)'],
            'xpath injection' => ['01937b6e-4b6c-7abc-8def-0123456789ab\' or \'1\'=\'1'],
            'template injection' => ['01937b6e-4b6c-7abc-{{7*7}}'],
            'ssti jinja' => ['01937b6e-4b6c-7abc-{{ config }}'],
        ];
    }

    /**
     * Test resilience to resource exhaustion attempts.
     */
    #[Test]
    public function handlesExtremelyLongInputWithoutMemoryExhaustion(): void
    {
        // 10MB string - should not cause memory issues
        $longString = str_repeat('a', 10 * 1024 * 1024);

        $startMemory = memory_get_usage();

        $this->vaultFieldResolver->isVaultIdentifier($longString);
        $this->flexFormVaultResolver->isVaultIdentifier($longString);

        $endMemory = memory_get_usage();

        // Memory increase should be reasonable (less than 50MB additional)
        self::assertLessThan(50 * 1024 * 1024, $endMemory - $startMemory);
    }

    /**
     * Test that the same input always produces the same result (determinism).
     */
    #[Test]
    public function validationIsDeterministic(): void
    {
        $inputs = [
            '01937b6e-4b6c-7abc-8def-0123456789ab',
            'invalid',
            '',
            'tx_ext__field__1', // Old format
        ];

        foreach ($inputs as $input) {
            $results = [];
            for ($i = 0; $i < 100; $i++) {
                $results[] = [
                    $this->vaultFieldResolver->isVaultIdentifier($input),
                    $this->flexFormVaultResolver->isVaultIdentifier($input),
                ];
            }

            // All results should be identical
            self::assertCount(1, array_unique($results, SORT_REGULAR));
        }
    }

    /**
     * Test that both resolvers accept the same UUID format.
     */
    #[Test]
    public function bothResolversAcceptSameUuidFormat(): void
    {
        $validUuids = [
            '01937b6e-4b6c-7abc-8def-0123456789ab',
            '01937b6f-0000-7000-8000-000000000000',
            '01937b6f-ffff-7fff-bfff-ffffffffffff',
        ];

        foreach ($validUuids as $uuid) {
            self::assertTrue($this->vaultFieldResolver->isVaultIdentifier($uuid), "VaultFieldResolver should accept: {$uuid}");
            self::assertTrue($this->flexFormVaultResolver->isVaultIdentifier($uuid), "FlexFormVaultResolver should accept: {$uuid}");
        }
    }

    /**
     * Test that old formats are rejected.
     */
    #[Test]
    public function oldFormatsAreRejected(): void
    {
        $oldFormats = [
            'tx_test__api_key__42',
            'pages__secret__1',
            'tt_content__pi_flexform__settings__apiKey__123',
        ];

        foreach ($oldFormats as $old) {
            self::assertFalse($this->vaultFieldResolver->isVaultIdentifier($old), "Should reject old format: {$old}");
            self::assertFalse($this->flexFormVaultResolver->isVaultIdentifier($old), "Should reject old format: {$old}");
        }
    }
}
