<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Netresearch\NrVault\Hook\Dto\PendingSecret;
use Netresearch\NrVault\Hook\PendingSecretExtractor;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use stdClass;

/**
 * The extractor decides — for every vault field save — whether a secret is
 * created, rotated, deleted or left untouched. Two of those four outcomes are
 * destructive, so the tests below are written around the question "what must
 * NOT happen": a plain re-save must never wipe a stored secret (issue #223),
 * and a rotation must never be mistaken for a fresh store (which would orphan
 * the previous identifier).
 */
#[CoversClass(PendingSecretExtractor::class)]
final class PendingSecretExtractorTest extends TestCase
{
    private const UUID_V7_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

    private const EXISTING_UUID = '01937b6e-4b6c-7abc-8def-0123456789ab';

    private const EXISTING_CHECKSUM = 'checksum-of-the-stored-secret';

    private PendingSecretExtractor $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->subject = new PendingSecretExtractor();
    }

    /**
     * A bare scalar carries no identifier and no checksum, so it can only ever
     * describe a brand-new secret.
     */
    #[Test]
    public function scalarValueBecomesANewSecretWithAGeneratedIdentifier(): void
    {
        $plaintext = $this->fakeSecret();

        $pending = $this->subject->extract($plaintext);

        self::assertInstanceOf(PendingSecret::class, $pending);
        self::assertSame($plaintext, $pending->value);
        self::assertTrue($pending->isNew);
        self::assertSame('', $pending->originalChecksum);
        self::assertMatchesRegularExpression(self::UUID_V7_PATTERN, $pending->identifier);
    }

    #[Test]
    public function everyNewSecretGetsItsOwnIdentifier(): void
    {
        $first = $this->subject->extract($this->fakeSecret());
        $second = $this->subject->extract($this->fakeSecret());

        self::assertInstanceOf(PendingSecret::class, $first);
        self::assertInstanceOf(PendingSecret::class, $second);
        self::assertNotSame(
            $first->identifier,
            $second->identifier,
            'Reusing an identifier would overwrite an unrelated secret',
        );
    }

    /**
     * Identifier + checksum together mean "there is a stored secret and the
     * form still knows it": the new plaintext rotates it in place instead of
     * creating a second entry and orphaning the old one.
     */
    #[Test]
    public function valueWithIdentifierAndChecksumRotatesTheExistingSecret(): void
    {
        $plaintext = $this->fakeSecret();

        $pending = $this->subject->extract([
            'value' => $plaintext,
            '_vault_identifier' => self::EXISTING_UUID,
            '_vault_checksum' => self::EXISTING_CHECKSUM,
        ]);

        self::assertInstanceOf(PendingSecret::class, $pending);
        self::assertSame($plaintext, $pending->value);
        self::assertFalse($pending->isNew);
        self::assertSame(self::EXISTING_UUID, $pending->identifier);
        self::assertSame(self::EXISTING_CHECKSUM, $pending->originalChecksum);
    }

    /**
     * A blanked checksum is the clear control's signal. Combined with a new
     * plaintext it means "replace what was there", which is handled as a fresh
     * store under a fresh identifier rather than a rotation of the old one.
     */
    #[Test]
    public function valueWithIdentifierButBlankedChecksumStoresUnderAFreshIdentifier(): void
    {
        $pending = $this->subject->extract([
            'value' => $this->fakeSecret(),
            '_vault_identifier' => self::EXISTING_UUID,
            '_vault_checksum' => '',
        ]);

        self::assertInstanceOf(PendingSecret::class, $pending);
        self::assertTrue($pending->isNew);
        self::assertNotSame(self::EXISTING_UUID, $pending->identifier);
        self::assertMatchesRegularExpression(self::UUID_V7_PATTERN, $pending->identifier);
    }

    /**
     * Issue #223: the plaintext is never rendered back into the edit form, so
     * an untouched re-save arrives with an empty value. The surviving checksum
     * is what distinguishes it from an explicit clear — mis-reading it would
     * silently destroy the stored secret on every unrelated record save.
     */
    #[Test]
    public function untouchedResaveKeepsTheStoredSecret(): void
    {
        $pending = $this->subject->extract([
            'value' => '',
            '_vault_identifier' => self::EXISTING_UUID,
            '_vault_checksum' => self::EXISTING_CHECKSUM,
        ]);

        self::assertNull($pending, 'An untouched re-save must not produce any vault operation');
    }

    /**
     * Checksum blanked while the identifier survives: the user pressed clear,
     * so the stored secret is deleted. An empty-value pending IS the delete
     * instruction, hence the identifier must be carried through.
     */
    #[Test]
    public function clearedFieldRequestsDeletionOfTheStoredSecret(): void
    {
        $pending = $this->subject->extract([
            'value' => '',
            '_vault_identifier' => self::EXISTING_UUID,
            '_vault_checksum' => '',
        ]);

        self::assertInstanceOf(PendingSecret::class, $pending);
        self::assertSame('', $pending->value);
        self::assertSame(self::EXISTING_UUID, $pending->identifier);
        self::assertFalse($pending->isNew);
        self::assertSame('', $pending->originalChecksum);
    }

    #[Test]
    public function emptyFieldThatNeverHeldASecretIsANoOp(): void
    {
        self::assertNull($this->subject->extract(''));
        self::assertNull($this->subject->extract([
            'value' => '',
            '_vault_identifier' => '',
            '_vault_checksum' => '',
        ]));
    }

    /**
     * The FormEngine element submits `value`, but a plain TCA input arrives as
     * a positional array. Both shapes must reach the same decision.
     */
    #[Test]
    public function positionalArrayValueIsReadFromIndexZero(): void
    {
        $plaintext = $this->fakeSecret();

        $pending = $this->subject->extract([$plaintext]);

        self::assertInstanceOf(PendingSecret::class, $pending);
        self::assertSame($plaintext, $pending->value);
    }

    #[Test]
    public function namedValueKeyWinsOverThePositionalFallback(): void
    {
        $named = $this->fakeSecret();

        $pending = $this->subject->extract(['value' => $named, 0 => 'positional-decoy']);

        self::assertInstanceOf(PendingSecret::class, $pending);
        self::assertSame($named, $pending->value);
    }

    /**
     * `'0'` and `0` are falsy but perfectly valid secrets — a truthiness check
     * here would drop the value and, worse, be read as an explicit clear.
     */
    #[DataProvider('falsyButRealValueProvider')]
    #[Test]
    public function falsyScalarIsTreatedAsARealSecret(mixed $value, string $expected): void
    {
        $pending = $this->subject->extract($value);

        self::assertInstanceOf(PendingSecret::class, $pending);
        self::assertSame($expected, $pending->value);
        self::assertTrue($pending->isNew);
    }

    /**
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function falsyButRealValueProvider(): iterable
    {
        yield 'string zero' => ['0', '0'];
        yield 'integer zero' => [0, '0'];
        yield 'string zero in array shape' => [['value' => '0'], '0'];
    }

    #[Test]
    public function integerValueIsNormalisedToItsStringForm(): void
    {
        $pending = $this->subject->extract(4711);

        self::assertInstanceOf(PendingSecret::class, $pending);
        self::assertSame('4711', $pending->value);
    }

    /**
     * Anything the extractor cannot faithfully render as a string is discarded
     * rather than coerced — a stringified object or a `true` would otherwise be
     * stored as the secret.
     */
    #[DataProvider('unusableScalarProvider')]
    #[Test]
    public function valueOfAnUnsupportedTypeIsTreatedAsEmpty(mixed $value): void
    {
        self::assertNull($this->subject->extract($value));
    }

    /**
     * @return iterable<string, array{0: mixed}>
     */
    public static function unusableScalarProvider(): iterable
    {
        yield 'null' => [null];
        yield 'boolean true' => [true];
        yield 'boolean false' => [false];
        yield 'float' => [1.5];
        yield 'object' => [new stdClass()];
    }

    /**
     * A nested array in the value slot must not become a pending secret, and —
     * because it collapses to the empty value with no checksum and no
     * identifier — it must not trigger a delete either.
     */
    #[Test]
    public function nestedArrayValueYieldsNoOperation(): void
    {
        self::assertNull($this->subject->extract(['value' => ['nested']]));
    }

    /**
     * Identifier and checksum arrive from the request. A non-string there must
     * degrade to "absent" rather than being coerced: a coerced identifier would
     * address the wrong vault entry.
     */
    #[DataProvider('nonStringMetadataProvider')]
    #[Test]
    public function nonStringIdentifierOrChecksumIsIgnored(mixed $identifier, mixed $checksum): void
    {
        $pending = $this->subject->extract([
            'value' => $this->fakeSecret(),
            '_vault_identifier' => $identifier,
            '_vault_checksum' => $checksum,
        ]);

        self::assertInstanceOf(PendingSecret::class, $pending);
        self::assertTrue($pending->isNew, 'Unusable metadata must not be read as "an existing secret"');
        self::assertMatchesRegularExpression(self::UUID_V7_PATTERN, $pending->identifier);
        self::assertSame('', $pending->originalChecksum);
    }

    /**
     * @return iterable<string, array{0: mixed, 1: mixed}>
     */
    public static function nonStringMetadataProvider(): iterable
    {
        yield 'integer identifier' => [42, self::EXISTING_CHECKSUM];
        yield 'array identifier' => [[self::EXISTING_UUID], self::EXISTING_CHECKSUM];
        yield 'integer checksum' => [self::EXISTING_UUID, 42];
        yield 'null checksum' => [self::EXISTING_UUID, null];
    }

    /**
     * A non-string identifier on an otherwise-empty submission collapses to
     * "no identifier", so nothing is deleted — the extractor never guesses
     * which entry to remove.
     */
    #[Test]
    public function emptySubmissionWithUnusableIdentifierDeletesNothing(): void
    {
        self::assertNull($this->subject->extract([
            'value' => '',
            '_vault_identifier' => 42,
            '_vault_checksum' => '',
        ]));
    }

    /**
     * A clearly synthetic, runtime-generated stand-in for secret material.
     */
    private function fakeSecret(): string
    {
        return 'FAKE-TEST-SECRET-' . bin2hex(random_bytes(8));
    }
}
