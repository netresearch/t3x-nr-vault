<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Utility;

use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\IdentifierValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(IdentifierValidator::class)]
final class IdentifierValidatorTest extends TestCase
{
    private const TEST_UUID = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const EXPECTED_VALIDATION_EXCEPTION = 'Expected ValidationException';

    #[Test]
    public function validateAcceptsValidIdentifier(): void
    {
        $this->expectNotToPerformAssertions();

        IdentifierValidator::validate('myApiKey');
    }

    #[Test]
    public function validateAcceptsIdentifierWithUnderscores(): void
    {
        $this->expectNotToPerformAssertions();

        IdentifierValidator::validate('my_api_key');
    }

    #[Test]
    public function validateAcceptsIdentifierWithNumbers(): void
    {
        $this->expectNotToPerformAssertions();

        IdentifierValidator::validate('apiKey123');
    }

    #[Test]
    public function validateRejectsEmptyIdentifier(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('empty');

        IdentifierValidator::validate('');
    }

    #[Test]
    public function validateRejectsTooShortIdentifier(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('at least');

        IdentifierValidator::validate('ab');
    }

    #[Test]
    public function validateRejectsTooLongIdentifier(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('exceed');

        IdentifierValidator::validate(str_repeat('a', 256));
    }

    #[Test]
    public function validateRejectsIdentifierStartingWithNumber(): void
    {
        $this->expectException(ValidationException::class);

        IdentifierValidator::validate('123apiKey');
    }

    #[Test]
    #[DataProvider('invalidCharactersProvider')]
    public function validateRejectsInvalidCharacters(string $identifier): void
    {
        $this->expectException(ValidationException::class);

        IdentifierValidator::validate($identifier);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidCharactersProvider(): array
    {
        return [
            'hyphen' => ['api-key'],
            'space' => ['api key'],
            'dot' => ['api.key'],
            'special chars' => ['api@key'],
            'unicode' => ['apiKeyäöü'],
            'slash' => ['api/key'],
        ];
    }

    #[Test]
    public function isValidReturnsTrueForValidIdentifier(): void
    {
        self::assertTrue(IdentifierValidator::isValid('myValidKey'));
    }

    #[Test]
    public function isValidReturnsFalseForInvalidIdentifier(): void
    {
        self::assertFalse(IdentifierValidator::isValid(''));
        self::assertFalse(IdentifierValidator::isValid('ab'));
        self::assertFalse(IdentifierValidator::isValid('123key'));
        self::assertFalse(IdentifierValidator::isValid('key-with-dashes'));
    }

    #[Test]
    public function sanitizeRemovesInvalidCharacters(): void
    {
        $result = IdentifierValidator::sanitize('api-key.test@123');

        self::assertEquals('api_key_test_123', $result);
    }

    #[Test]
    public function sanitizePrependsPrefixIfStartsWithNumber(): void
    {
        $result = IdentifierValidator::sanitize('123apiKey');

        // Implementation converts to lowercase and prepends 'secret_' for numbers
        self::assertEquals('secret_123apikey', $result);
    }

    #[Test]
    public function sanitizeTruncatesToMaxLength(): void
    {
        $longIdentifier = str_repeat('a', 300);
        $result = IdentifierValidator::sanitize($longIdentifier);

        self::assertEquals(255, \strlen($result));
    }

    #[Test]
    public function validateAcceptsMinimumLengthIdentifier(): void
    {
        $this->expectNotToPerformAssertions();

        IdentifierValidator::validate('abc'); // Exactly 3 characters
    }

    #[Test]
    public function validateAcceptsMaximumLengthIdentifier(): void
    {
        $this->expectNotToPerformAssertions();

        IdentifierValidator::validate('a' . str_repeat('b', 254)); // Exactly 255 characters
    }

    #[Test]
    public function generateUuidReturnsValidUuidV7Format(): void
    {
        $uuid = IdentifierValidator::generateUuid();

        // UUID format: 8-4-4-4-12 hex characters
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $uuid,
        );
    }

    #[Test]
    public function generateUuidReturnsUniqueValues(): void
    {
        $uuid1 = IdentifierValidator::generateUuid();
        $uuid2 = IdentifierValidator::generateUuid();

        self::assertNotSame($uuid1, $uuid2);
    }

    #[Test]
    public function generateUuidPassesValidation(): void
    {
        $uuid = IdentifierValidator::generateUuid();

        $this->expectNotToPerformAssertions();
        IdentifierValidator::validate($uuid);
    }

    #[Test]
    public function generateUuidHasVersionBit7(): void
    {
        $uuid = IdentifierValidator::generateUuid();

        // The version nibble (position 14) must be '7'
        self::assertSame('7', $uuid[14]);
    }

    #[Test]
    public function generateUuidHasCorrectVariantBits(): void
    {
        $uuid = IdentifierValidator::generateUuid();

        // The variant nibble (position 19) must be 8, 9, a, or b
        self::assertContains($uuid[19], ['8', '9', 'a', 'b']);
    }

    /**
     * The variant nibble (position 19) must draw bits 12-13 from randomness
     * (RFC 9562: 10xx). A regression that hard-codes those bits to zero leaves
     * the nibble pinned to '8' and loses ~2 bits of entropy. A single sample
     * can't catch that — collect the nibble over many generations and assert
     * the full {8, 9, a, b} set appears.
     */
    #[Test]
    public function generateUuidVariantNibbleCoversAllRfc9562Values(): void
    {
        // Collect nibble characters into a list (not array keys — numeric-string
        // keys like '8'/'9' would silently cast to int and break the compare).
        $variants = [];
        for ($i = 0; $i < 500; $i++) {
            $variants[] = IdentifierValidator::generateUuid()[19];
        }
        $variants = array_values(array_unique($variants));
        sort($variants);

        self::assertSame(
            ['8', '9', 'a', 'b'],
            $variants,
            'Variant nibble must vary across {8, 9, a, b}; a pinned value means '
            . 'the random variant bits (12-13) were lost.',
        );
        self::assertCount(4, $variants);
    }

    #[Test]
    public function looksLikeVaultIdentifierRecognisesUuidV7(): void
    {
        $uuid = IdentifierValidator::generateUuid();

        self::assertTrue(IdentifierValidator::looksLikeVaultIdentifier($uuid));
    }

    #[Test]
    public function looksLikeVaultIdentifierRecognisesVaultReferenceFormat(): void
    {
        self::assertTrue(IdentifierValidator::looksLikeVaultIdentifier('%vault(my_secret)%'));
        self::assertTrue(IdentifierValidator::looksLikeVaultIdentifier('%vault(site:main:key)%'));
    }

    #[Test]
    public function looksLikeVaultIdentifierRejectsLegacyTcaFormat(): void
    {
        // Legacy TCA format (table__field__uid) is not a vault identifier
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier('tx_myext__api_key__123'));
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier('pages__password__42'));
    }

    #[Test]
    public function looksLikeVaultIdentifierReturnsFalseForPlainValues(): void
    {
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier(''));
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier('my-api-key'));
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier('some_regular_value'));
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier('sk-1234567890abcdef'));
    }

    #[Test]
    public function looksLikeVaultIdentifierRejectsPartialVaultReference(): void
    {
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier('vault(key)'));
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier('%vault%'));
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier('%vault()%'));
    }

    #[Test]
    public function looksLikeVaultIdentifierRejectsIncompleteLegacyFormat(): void
    {
        // Only one double-underscore segment
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier('tx_myext__api_key'));
        // Missing UID
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier('tx_myext__api_key__'));
    }

    // =========================================================================
    // Strict boundary tests — kill IncrementInteger/DecrementInteger/CastInt
    // mutators on IdentifierValidator.php (especially around generateUuid()).
    // =========================================================================

    /**
     * @return iterable<string, array{int, bool}>
     */
    public static function lengthBoundaryProvider(): iterable
    {
        yield 'empty len=0 rejected' => [0, false];
        yield 'len=1 too short' => [1, false];
        yield 'len=2 too short (MIN_LENGTH - 1)' => [2, false];
        yield 'len=3 exactly MIN_LENGTH' => [3, true];
        yield 'len=4 one above MIN_LENGTH' => [4, true];
        yield 'len=50 safely valid' => [50, true];
        yield 'len=254 just below MAX_LENGTH' => [254, true];
        yield 'len=255 exactly MAX_LENGTH' => [255, true];
        yield 'len=256 MAX_LENGTH + 1 rejected' => [256, false];
        yield 'len=500 rejected' => [500, false];
    }

    #[Test]
    #[DataProvider('lengthBoundaryProvider')]
    public function validateEnforcesExactLengthBoundaries(int $length, bool $expectValid): void
    {
        // Build an identifier of exact length: "a" + ("b" * (length-1))
        // Length 0 → empty string (always rejected).
        $identifier = $length === 0 ? '' : 'a' . str_repeat('b', $length - 1);

        self::assertSame($expectValid, IdentifierValidator::isValid($identifier));
    }

    /**
     * MIN_LENGTH = 3 — hit exact boundary with assertSame to avoid off-by-one mutation escape.
     */
    #[Test]
    public function validateMinLengthBoundaryIsExactlyThree(): void
    {
        // Length 2 (one below) — must throw.
        $exceptionThrown = false;

        try {
            IdentifierValidator::validate('ab');
        } catch (ValidationException $e) {
            $exceptionThrown = true;
            self::assertStringContainsString('at least 3', $e->getMessage());
        }

        self::assertTrue($exceptionThrown, 'Length-2 identifier must throw');

        // Length 3 (at boundary) — must NOT throw.
        IdentifierValidator::validate('abc');
        self::assertTrue(IdentifierValidator::isValid('abc'));
    }

    /**
     * MAX_LENGTH = 255 — hit exact boundary with assertSame.
     */
    #[Test]
    public function validateMaxLengthBoundaryIsExactly255(): void
    {
        $at = 'a' . str_repeat('b', 254); // length 255
        $over = 'a' . str_repeat('b', 255); // length 256

        self::assertSame(255, \strlen($at));
        self::assertSame(256, \strlen($over));

        // At boundary: must pass.
        IdentifierValidator::validate($at);
        self::assertTrue(IdentifierValidator::isValid($at));

        // Over boundary: must throw with exact message containing "255".
        $exceptionThrown = false;

        try {
            IdentifierValidator::validate($over);
        } catch (ValidationException $e) {
            $exceptionThrown = true;
            self::assertStringContainsString('255', $e->getMessage());
            self::assertStringContainsString('exceed', $e->getMessage());
        }

        self::assertTrue($exceptionThrown, 'Length-256 identifier must throw');
    }

    /**
     * Kills IncrementInteger/DecrementInteger mutations on the UUID generation
     * bit-layout — runs `generateUuid()` many times and checks structural invariants.
     */
    #[Test]
    public function generateUuidStructuralInvariantsOver200Samples(): void
    {
        for ($i = 0; $i < 200; $i++) {
            $uuid = IdentifierValidator::generateUuid();

            // Exact length is always 36 (8+4+4+4+12 + 4 hyphens).
            self::assertSame(36, \strlen($uuid), "UUID must be exactly 36 chars, got: {$uuid}");

            // Hyphens are at positions 8, 13, 18, 23 — all four must be exactly '-'.
            self::assertSame('-', $uuid[8], "Hyphen at pos 8 missing in: {$uuid}");
            self::assertSame('-', $uuid[13], "Hyphen at pos 13 missing in: {$uuid}");
            self::assertSame('-', $uuid[18], "Hyphen at pos 18 missing in: {$uuid}");
            self::assertSame('-', $uuid[23], "Hyphen at pos 23 missing in: {$uuid}");

            // Version nibble at position 14 must be '7'.
            self::assertSame('7', $uuid[14], "Version nibble must be '7' in: {$uuid}");

            // Variant nibble at position 19 must be 8, 9, a, or b
            // (RFC 4122: 10xx — top two bits are '10').
            self::assertContains(
                $uuid[19],
                ['8', '9', 'a', 'b'],
                "Variant nibble must be 8|9|a|b in: {$uuid}",
            );

            // All non-hyphen chars must be lowercase hex.
            $stripped = str_replace('-', '', $uuid);
            self::assertSame(32, \strlen($stripped));
            self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $stripped, "Invalid hex in: {$uuid}");
        }
    }

    /**
     * Kills BitwiseAnd/BitwiseOr mutations on the timestamp encoding.
     * UUID v7 encodes a 48-bit millisecond timestamp in the first 48 bits.
     * Two UUIDs generated back-to-back must share the same approximate timestamp
     * (the 48-bit timestamp segment must be monotonically non-decreasing).
     */
    #[Test]
    public function generateUuidTimestampIsMonotonicallyNonDecreasing(): void
    {
        $uuids = [];
        for ($i = 0; $i < 50; $i++) {
            $uuids[] = IdentifierValidator::generateUuid();
            // Small delay to ensure the millisecond clock can tick sometimes.
            usleep(100);
        }

        $previousTimestamp = 0;
        foreach ($uuids as $uuid) {
            // Extract 48-bit timestamp from first 12 hex chars (after stripping hyphens).
            $hex = substr($uuid, 0, 8) . substr($uuid, 9, 4);
            self::assertSame(12, \strlen($hex));
            $ts = hexdec($hex);

            self::assertGreaterThanOrEqual(
                $previousTimestamp,
                $ts,
                "UUID timestamp must be monotonic: got {$ts} after {$previousTimestamp}",
            );
            $previousTimestamp = (int) $ts;
        }
    }

    /**
     * Kills CastInt mutation on `(int) (microtime(true) * 1000)`:
     * if the cast is removed, generateUuid() produces malformed UUIDs.
     */
    #[Test]
    public function generateUuidTimestampReflectsCurrentWallClock(): void
    {
        $beforeMs = (int) (microtime(true) * 1000);
        $uuid = IdentifierValidator::generateUuid();
        $afterMs = (int) (microtime(true) * 1000);

        // Extract the 48-bit timestamp.
        $hex = substr($uuid, 0, 8) . substr($uuid, 9, 4);
        $timestamp = (int) hexdec($hex);

        // The UUID timestamp must fall within [before, after] (with 5s tolerance).
        self::assertGreaterThanOrEqual($beforeMs - 1, $timestamp);
        self::assertLessThanOrEqual($afterMs + 5000, $timestamp);
    }

    /**
     * Kills DecrementInteger/IncrementInteger on `random_bytes(10)`:
     * generateUuid() uses exactly 10 random bytes. If the count is off
     * by one, PHP's sprintf may still format it but hex length would vary,
     * or \ord() on a short byte string would fail — we verify stability
     * across many calls.
     */
    #[Test]
    public function generateUuidIsStableAcross1000Calls(): void
    {
        $uuids = [];
        for ($i = 0; $i < 1000; $i++) {
            $uuid = IdentifierValidator::generateUuid();
            self::assertSame(36, \strlen($uuid));
            $uuids[] = $uuid;
        }

        // All 1000 UUIDs should be unique.
        self::assertSame(1000, \count(array_unique($uuids)));
    }

    #[Test]
    public function validateEmptyStringMessageContainsEmpty(): void
    {
        try {
            IdentifierValidator::validate('');
            self::fail(self::EXPECTED_VALIDATION_EXCEPTION);
        } catch (ValidationException $e) {
            // Kills ConcatOperandRemoval — exact message text matters.
            self::assertStringContainsString('empty', $e->getMessage());
        }
    }

    #[Test]
    public function validateTooShortMessageContainsMinLength(): void
    {
        try {
            IdentifierValidator::validate('a');
            self::fail(self::EXPECTED_VALIDATION_EXCEPTION);
        } catch (ValidationException $e) {
            // Kills IncrementInteger/DecrementInteger on MIN_LENGTH (3).
            self::assertStringContainsString('at least 3', $e->getMessage());
        }
    }

    #[Test]
    public function validateTooLongMessageContainsMaxLength(): void
    {
        try {
            IdentifierValidator::validate(str_repeat('a', 300));
            self::fail(self::EXPECTED_VALIDATION_EXCEPTION);
        } catch (ValidationException $e) {
            // Kills IncrementInteger/DecrementInteger on MAX_LENGTH (255).
            self::assertStringContainsString('255', $e->getMessage());
        }
    }

    /**
     * Kills UnwrapTrim mutation on sanitize() — empty/short inputs produce
     * an underscore-padded string of length exactly 3 (MIN_LENGTH).
     */
    #[Test]
    public function sanitizePadsToMinLengthWithUnderscoresForShortInput(): void
    {
        $result = IdentifierValidator::sanitize('ab');

        // When input is shorter than MIN_LENGTH, padded up. Trim happens first
        // but starts-with-number prepends 'secret_' — 'ab' is alpha so it just pads.
        // Expected: length is at least MIN_LENGTH (3).
        self::assertGreaterThanOrEqual(3, \strlen($result));
    }

    /**
     * Kills Increment/Decrement mutations on MAX_LENGTH (255) in sanitize().
     */
    #[Test]
    public function sanitizeTruncatesExactlyAtMaxLength(): void
    {
        $input = str_repeat('a', 1000);
        $result = IdentifierValidator::sanitize($input);

        self::assertSame(255, \strlen($result));
    }

    #[Test]
    public function sanitizeProducesLengthEqualToInputWhenMidRange(): void
    {
        $input = 'abc_def_ghi';
        $result = IdentifierValidator::sanitize($input);

        // Kills Increment/Decrement on MIN_LENGTH / MAX_LENGTH comparisons.
        self::assertSame('abc_def_ghi', $result);
    }

    /**
     * Kills ConcatOperandRemoval on sanitize `'secret_' . $identifier`.
     */
    #[Test]
    public function sanitizeNumericPrefixIsExactlySecretUnderscore(): void
    {
        $result = IdentifierValidator::sanitize('1key');

        // Exact prefix must be 'secret_'. Missing underscore or missing 'secret' kills this.
        self::assertStringStartsWith('secret_', $result);
        self::assertSame('secret_1key', $result);
    }

    #[Test]
    public function looksLikeVaultIdentifierUuidV7CaseInsensitive(): void
    {
        $lower = self::TEST_UUID;
        $upper = '01937B6E-4B6C-7ABC-8DEF-0123456789AB';

        self::assertTrue(IdentifierValidator::looksLikeVaultIdentifier($lower));
        self::assertTrue(IdentifierValidator::looksLikeVaultIdentifier($upper));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function uuidVariantProvider(): iterable
    {
        // Only [89ab] is a valid UUID variant (RFC 4122 10xx).
        yield 'variant 8' => [self::TEST_UUID, true];
        yield 'variant 9' => ['01937b6e-4b6c-7abc-9def-0123456789ab', true];
        yield 'variant a' => ['01937b6e-4b6c-7abc-adef-0123456789ab', true];
        yield 'variant b' => ['01937b6e-4b6c-7abc-bdef-0123456789ab', true];
        yield 'variant 0 rejected' => ['01937b6e-4b6c-7abc-0def-0123456789ab', false];
        yield 'variant 1 rejected' => ['01937b6e-4b6c-7abc-1def-0123456789ab', false];
        yield 'variant 7 rejected' => ['01937b6e-4b6c-7abc-7def-0123456789ab', false];
        yield 'variant c rejected' => ['01937b6e-4b6c-7abc-cdef-0123456789ab', false];
        yield 'variant f rejected' => ['01937b6e-4b6c-7abc-fdef-0123456789ab', false];
    }

    #[Test]
    #[DataProvider('uuidVariantProvider')]
    public function looksLikeVaultIdentifierEnforcesVariantBits(string $uuid, bool $expected): void
    {
        self::assertSame($expected, IdentifierValidator::looksLikeVaultIdentifier($uuid));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function uuidVersionProvider(): iterable
    {
        yield 'version 7 accepted' => [self::TEST_UUID, true];
        yield 'version 4 rejected' => ['01937b6e-4b6c-4abc-8def-0123456789ab', false];
        yield 'version 1 rejected' => ['01937b6e-4b6c-1abc-8def-0123456789ab', false];
        yield 'version 6 rejected' => ['01937b6e-4b6c-6abc-8def-0123456789ab', false];
        yield 'version 8 rejected' => ['01937b6e-4b6c-8abc-8def-0123456789ab', false];
    }

    #[Test]
    #[DataProvider('uuidVersionProvider')]
    public function looksLikeVaultIdentifierAcceptsOnlyVersion7(string $uuid, bool $expected): void
    {
        self::assertSame($expected, IdentifierValidator::looksLikeVaultIdentifier($uuid));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedUuidProvider(): iterable
    {
        yield 'missing hyphen' => ['01937b6e4b6c-7abc-8def-0123456789ab'];
        yield 'extra hyphen' => ['01937b6e--4b6c-7abc-8def-0123456789ab'];
        yield 'too short first segment' => ['937b6e-4b6c-7abc-8def-0123456789ab'];
        yield 'too long first segment' => ['001937b6e-4b6c-7abc-8def-0123456789ab'];
        yield 'too short last segment' => ['01937b6e-4b6c-7abc-8def-0123456789a'];
        yield 'non-hex chars' => ['01937b6e-4b6c-7xxx-8def-0123456789ab'];
        yield 'only hyphens' => ['--------'];
        yield 'trailing whitespace' => ['01937b6e-4b6c-7abc-8def-0123456789ab '];
        yield 'leading whitespace' => [' 01937b6e-4b6c-7abc-8def-0123456789ab'];
    }

    #[Test]
    #[DataProvider('malformedUuidProvider')]
    public function looksLikeVaultIdentifierRejectsMalformedUuids(string $uuid): void
    {
        self::assertFalse(IdentifierValidator::looksLikeVaultIdentifier($uuid));
    }

    /**
     * UUID v7 timestamp field is 48 bits = 12 hex chars.
     * Kill boundary mutations on the timestamp encoding.
     */
    #[Test]
    public function generateUuidTimestampFieldIsExactly12HexChars(): void
    {
        $uuid = IdentifierValidator::generateUuid();

        // First segment (8 hex) + second segment (4 hex) = 12 hex chars of timestamp.
        $first = substr($uuid, 0, 8);
        $second = substr($uuid, 9, 4);

        self::assertSame(8, \strlen($first));
        self::assertSame(4, \strlen($second));
        self::assertMatchesRegularExpression('/^[0-9a-f]{8}$/', $first);
        self::assertMatchesRegularExpression('/^[0-9a-f]{4}$/', $second);
    }

    /**
     * Kill Ternary on line 151 — `is_string($replaced) ? $replaced : $identifier`.
     * Swapping branches means invalid characters survive in the output.
     */
    #[Test]
    public function sanitizeRemovesConsecutiveUnderscoresExactly(): void
    {
        // Input with many consecutive underscores — result must collapse them.
        $result = IdentifierValidator::sanitize('abc___def____ghi');

        // If ternary is swapped, underscores stay multiple.
        self::assertSame('abc_def_ghi', $result);
    }

    /**
     * Kill UnwrapTrim on line 154 — leading/trailing underscores stripped.
     */
    #[Test]
    public function sanitizeStripsLeadingAndTrailingUnderscores(): void
    {
        // Input starts with a letter so no 'secret_' prefix is added.
        // 'api@key ' → lowercase → 'api@key ' → replace invalid → 'api_key_' →
        // collapse multi-underscores (no-op here) → trim '_' → 'api_key'.
        $result = IdentifierValidator::sanitize('api@key ');

        self::assertSame('api_key', $result);
        self::assertStringStartsNotWith('_', $result);
        self::assertStringEndsWith('y', $result);
    }

    /**
     * Kill LessThan on line 157 — strict less-than triggers padding.
     * At MIN_LENGTH=3, NO padding. Below 3 pads. If mutated to <=,
     * 3-char input also gets padded → length becomes 3 anyway (no change).
     * A 2-char input MUST be padded to >= 3.
     */
    #[Test]
    public function sanitizeShortInputPadsToAtLeastMinLength(): void
    {
        $result = IdentifierValidator::sanitize('ab');

        // 2-char input cannot become a 2-char output after padding.
        self::assertGreaterThanOrEqual(3, \strlen($result));
    }

    /**
     * Kill LessThan on line 157 — at exactly MIN_LENGTH=3, NO padding applied.
     */
    #[Test]
    public function sanitizeAtMinLengthReturnsExactLengthThree(): void
    {
        $result = IdentifierValidator::sanitize('abc');

        self::assertSame('abc', $result);
        self::assertSame(3, \strlen($result));
    }

    /**
     * Kill GreaterThan on line 161 — strict greater-than triggers truncation.
     * Exactly MAX_LENGTH=255: NO truncation. 256: truncate to 255.
     */
    #[Test]
    public function sanitizeExactlyAtMaxLengthDoesNotTruncate(): void
    {
        $input = 'a' . str_repeat('b', 254); // length 255
        self::assertSame(255, \strlen($input));

        $result = IdentifierValidator::sanitize($input);

        self::assertSame(255, \strlen($result));
    }

    /**
     * Kill IncrementInteger on line 162 — substr offset is 0, not 1.
     */
    #[Test]
    public function sanitizeTruncationStartsFromZeroOffset(): void
    {
        // Input of 300 'a' characters — no substitution needed, just length.
        $input = str_repeat('a', 300);
        $result = IdentifierValidator::sanitize($input);

        // Exactly MAX_LENGTH=255 a's starting at offset 0.
        self::assertSame(255, \strlen($result));
        self::assertSame(str_repeat('a', 255), $result);
    }

    /**
     * Kill IncrementInteger on line 162 — first char must be preserved.
     * With offset=0, result starts with the input's first char. With offset=1,
     * the result would shift by 1 and start with the second char.
     */
    #[Test]
    public function sanitizeTruncationPreservesFirstCharacter(): void
    {
        // Craft an input where first char is unique.
        $input = 'z' . str_repeat('a', 300);
        $result = IdentifierValidator::sanitize($input);

        // z must remain as first char — with offset=1 it would be 'a'.
        self::assertSame('z', $result[0]);
    }

    /**
     * Kill Ternary + UnwrapStrToLower/related mutations for input mixing
     * invalid chars, letters and multi-underscores.
     */
    #[Test]
    public function sanitizeFullPipelineResult(): void
    {
        $result = IdentifierValidator::sanitize('  API--KEY  test ');

        // Expected pipeline: lowercase → '  api--key  test ' →
        //                    replace invalid → '__api__key__test_' →
        //                    (starts with _, not ctype_alpha) → prepend 'secret_' →
        //                    'secret___api__key__test_' →
        //                    collapse '_+' → 'secret_api_key_test_' →
        //                    trim '_' → 'secret_api_key_test'
        self::assertSame('secret_api_key_test', $result);
    }
}
