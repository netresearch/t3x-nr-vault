<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptionService;
use Netresearch\NrVault\Crypto\EnvelopeCodec;
use Netresearch\NrVault\Crypto\EnvelopeCodecInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\EnvelopeFormatException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The codec is exercised against the REAL {@see EncryptionService}, not a mock:
 * the point of these tests is that a sealed string survives a full
 * encrypt/decrypt round trip and that tampering with it fails authentication —
 * neither of which a mocked cipher would prove.
 */
#[CoversClass(EnvelopeCodec::class)]
#[AllowMockObjectsWithoutExpectations]
final class EnvelopeCodecTest extends TestCase
{
    private const IDENTIFIER = 'nrvault:test:payload';

    private EnvelopeCodec $subject;

    private EncryptionService $encryptionService;

    private string $masterKey;

    protected function setUp(): void
    {
        parent::setUp();

        $this->masterKey = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);
        $this->encryptionService = $this->encryptionServiceFor($this->masterKey);
        $this->subject = new EnvelopeCodec($this->encryptionService);
    }

    #[Test]
    public function aSealedPayloadOpensBackToTheOriginal(): void
    {
        $plaintext = '{"messages":[{"role":"user","content":"hello"}]}';

        $sealed = $this->subject->seal($plaintext, self::IDENTIFIER);

        self::assertNotSame($plaintext, $sealed);
        self::assertStringNotContainsString('hello', $sealed);
        self::assertSame($plaintext, $this->subject->open($sealed, self::IDENTIFIER));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function payloadProvider(): iterable
    {
        yield 'empty string' => [''];
        yield 'single character' => ['x'];
        yield 'json' => ['{"a":1,"b":[2,3]}'];
        yield 'multibyte' => ['Schlüssel — 鍵 — ключ 🔑'];
        yield 'newlines and tabs' => ["line1\nline2\tend"];
        yield 'large payload' => [str_repeat('abcdefghij', 5000)];
        yield 'nul byte' => ["before\0after"];
        yield 'looks like an envelope' => ['nrv1:not-really-an-envelope'];
    }

    #[Test]
    #[DataProvider('payloadProvider')]
    public function roundTripPreservesAnyPayload(string $plaintext): void
    {
        $sealed = $this->subject->seal($plaintext, self::IDENTIFIER);

        self::assertSame($plaintext, $this->subject->open($sealed, self::IDENTIFIER));
    }

    #[Test]
    public function sealingTheSamePayloadTwiceProducesDifferentCiphertext(): void
    {
        $plaintext = 'identical input';

        self::assertNotSame(
            $this->subject->seal($plaintext, self::IDENTIFIER),
            $this->subject->seal($plaintext, self::IDENTIFIER),
            'A fresh DEK and nonce per seal must make identical payloads look different.',
        );
    }

    #[Test]
    public function theWireFormatIsTheMarkerPlusBase64EncodedJson(): void
    {
        $sealed = $this->subject->seal('payload', self::IDENTIFIER);

        self::assertStringStartsWith(EnvelopeCodecInterface::MARKER, $sealed);

        $body = base64_decode(substr($sealed, \strlen(EnvelopeCodecInterface::MARKER)), true);
        self::assertIsString($body);

        $decoded = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        foreach ([
            'encrypted_value',
            'encrypted_dek',
            'dek_nonce',
            'value_nonce',
            'value_checksum',
            'encryption_version',
            'encryption_algorithm',
        ] as $field) {
            self::assertArrayHasKey($field, $decoded);
        }
    }

    #[Test]
    public function isSealedDistinguishesEnvelopesFromPlainValues(): void
    {
        self::assertTrue($this->subject->isSealed($this->subject->seal('x', self::IDENTIFIER)));
        self::assertFalse($this->subject->isSealed(''));
        self::assertFalse($this->subject->isSealed('{"plain":"json"}'));
        self::assertFalse($this->subject->isSealed('v2:legacy-marker-from-a-consumer'));
    }

    /**
     * A payload sealed under one identifier must not open under another: the
     * identifier is bound to the ciphertext as additional authenticated data, so
     * an envelope cannot be lifted from one column or purpose into a different one.
     */
    #[Test]
    public function anEnvelopeDoesNotOpenUnderADifferentIdentifier(): void
    {
        $sealed = $this->subject->seal('payload', 'purpose:a');

        $this->expectException(EncryptionException::class);
        $this->subject->open($sealed, 'purpose:b');
    }

    #[Test]
    public function aTamperedCiphertextFailsAuthenticationInsteadOfDecrypting(): void
    {
        $sealed = $this->subject->seal('payload', self::IDENTIFIER);
        $tampered = $this->rewriteEnvelope($sealed, static function (array $envelope): array {
            $raw = base64_decode($envelope['encrypted_value'], true);
            self::assertIsString($raw);
            // Flip one bit of the ciphertext.
            $raw[0] = \chr(\ord($raw[0]) ^ 0x01);
            $envelope['encrypted_value'] = base64_encode($raw);

            return $envelope;
        });

        $this->expectException(EncryptionException::class);
        $this->subject->open($tampered, self::IDENTIFIER);
    }

    #[Test]
    public function anEnvelopeSealedUnderAnotherMasterKeyDoesNotOpen(): void
    {
        $sealed = $this->subject->seal('payload', self::IDENTIFIER);

        $otherCodec = new EnvelopeCodec($this->encryptionServiceFor(
            random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES),
        ));

        $this->expectException(EncryptionException::class);
        $otherCodec->open($sealed, self::IDENTIFIER);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedEnvelopeProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'no marker' => ['just a plain value'];
        yield 'legacy consumer marker' => ['v2:eyJhIjoxfQ=='];
        yield 'marker only' => ['nrv1:'];
        yield 'not base64' => ['nrv1:!!!not-base64!!!'];
        yield 'base64 but not json' => ['nrv1:' . self::b64('this is not json')];
        yield 'json scalar' => ['nrv1:' . self::b64('42')];
        yield 'json list' => ['nrv1:' . self::b64('[1,2,3]')];
        yield 'empty object' => ['nrv1:' . self::b64('{}')];
        yield 'missing dek' => ['nrv1:' . self::b64(
            '{"encrypted_value":"a","dek_nonce":"b","value_nonce":"c","encryption_version":2,"encryption_algorithm":"aes256gcm"}',
        )];
        yield 'version is a string' => ['nrv1:' . self::b64(
            '{"encrypted_value":"a","encrypted_dek":"b","dek_nonce":"c","value_nonce":"d","encryption_version":"2","encryption_algorithm":"aes256gcm"}',
        )];
        yield 'algorithm is a number' => ['nrv1:' . self::b64(
            '{"encrypted_value":"a","encrypted_dek":"b","dek_nonce":"c","value_nonce":"d","encryption_version":2,"encryption_algorithm":7}',
        )];
        yield 'nested value' => ['nrv1:' . self::b64(
            '{"encrypted_value":{"nested":true},"encrypted_dek":"b","dek_nonce":"c","value_nonce":"d","encryption_version":2,"encryption_algorithm":"aes256gcm"}',
        )];
    }

    /**
     * Malformed input must be distinguishable from a failed MAC check, so a
     * consumer can tell corruption from tampering.
     */
    #[Test]
    #[DataProvider('malformedEnvelopeProvider')]
    public function malformedEnvelopesRaiseAFormatErrorNotAnAuthenticationError(string $sealed): void
    {
        $this->expectException(EnvelopeFormatException::class);
        $this->subject->open($sealed, self::IDENTIFIER);
    }

    /**
     * Wire compatibility with what nr-llm's AgentStateCodec has been writing
     * since nr-llm 0.24.0: `<marker>` + base64( json( EncryptedData::toArray() ) ).
     * A consumer that swaps its own marker for this codec's must find its
     * existing rows still open, with no data migration.
     */
    #[Test]
    public function abodyBuiltTheWayAConsumerBuiltItStillOpens(): void
    {
        $encrypted = $this->encryptionService->encrypt('consumer payload', self::IDENTIFIER);

        $consumerBody = base64_encode(json_encode($encrypted->toArray(), JSON_THROW_ON_ERROR));

        self::assertSame(
            'consumer payload',
            $this->subject->open(EnvelopeCodecInterface::MARKER . $consumerBody, self::IDENTIFIER),
        );
    }

    /**
     * Forward and backward tolerance: an unknown extra field must not break
     * parsing, and the change-detection checksum is not required to open.
     */
    #[Test]
    public function unknownFieldsAreIgnoredAndTheChecksumIsOptional(): void
    {
        $sealed = $this->subject->seal('payload', self::IDENTIFIER);

        $modified = $this->rewriteEnvelope($sealed, static function (array $envelope): array {
            unset($envelope['value_checksum']);
            $envelope['a_field_from_the_future'] = 'ignored';

            return $envelope;
        });

        self::assertSame('payload', $this->subject->open($modified, self::IDENTIFIER));
    }

    #[Test]
    public function rewrappingMovesAnEnvelopeToANewMasterKeyWithoutTouchingThePayload(): void
    {
        $newMasterKey = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);
        $sealed = $this->subject->seal('payload', self::IDENTIFIER);

        $rewrapped = $this->subject->rewrap($sealed, self::IDENTIFIER, $this->masterKey, $newMasterKey);

        // The payload ciphertext is carried over untouched: re-wrapping changes
        // the DEK layer only and never materialises the plaintext.
        self::assertSame(
            $this->envelopeField($sealed, 'encrypted_value'),
            $this->envelopeField($rewrapped, 'encrypted_value'),
        );
        self::assertSame(
            $this->envelopeField($sealed, 'value_nonce'),
            $this->envelopeField($rewrapped, 'value_nonce'),
        );
        self::assertNotSame(
            $this->envelopeField($sealed, 'encrypted_dek'),
            $this->envelopeField($rewrapped, 'encrypted_dek'),
        );

        // It opens under the new key...
        $newCodec = new EnvelopeCodec($this->encryptionServiceFor($newMasterKey));
        self::assertSame('payload', $newCodec->open($rewrapped, self::IDENTIFIER));
    }

    #[Test]
    public function aRewrappedEnvelopeNoLongerOpensUnderTheOldMasterKey(): void
    {
        $newMasterKey = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);
        $rewrapped = $this->subject->rewrap(
            $this->subject->seal('payload', self::IDENTIFIER),
            self::IDENTIFIER,
            $this->masterKey,
            $newMasterKey,
        );

        $this->expectException(EncryptionException::class);
        $this->subject->open($rewrapped, self::IDENTIFIER);
    }

    #[Test]
    public function rewrappingWithTheWrongOldKeyFails(): void
    {
        $sealed = $this->subject->seal('payload', self::IDENTIFIER);

        $this->expectException(EncryptionException::class);
        $this->subject->rewrap(
            $sealed,
            self::IDENTIFIER,
            random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES),
            random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES),
        );
    }

    #[Test]
    public function rewrappingRejectsAMalformedEnvelope(): void
    {
        $this->expectException(EnvelopeFormatException::class);
        $this->subject->rewrap(
            'not an envelope',
            self::IDENTIFIER,
            $this->masterKey,
            random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES),
        );
    }

    #[Test]
    public function rewrappingIsRepeatableAcrossSuccessiveRotations(): void
    {
        $keyTwo = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);
        $keyThree = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);

        $sealed = $this->subject->seal('payload', self::IDENTIFIER);
        $afterFirst = $this->subject->rewrap($sealed, self::IDENTIFIER, $this->masterKey, $keyTwo);

        $codecTwo = new EnvelopeCodec($this->encryptionServiceFor($keyTwo));
        $afterSecond = $codecTwo->rewrap($afterFirst, self::IDENTIFIER, $keyTwo, $keyThree);

        $codecThree = new EnvelopeCodec($this->encryptionServiceFor($keyThree));
        self::assertSame('payload', $codecThree->open($afterSecond, self::IDENTIFIER));
    }

    /**
     * The read path tolerates unknown fields, so the rotation path must preserve
     * them. Rebuilding the body from the fields this version knows made rotation
     * lossy in exactly the case the tolerance exists for: a body written by a
     * newer vault opened fine until an operator rotated, then came back stripped
     * — irreversibly, once the old key was destroyed.
     */
    #[Test]
    public function rewrappingPreservesFieldsThisVersionDoesNotKnow(): void
    {
        $newMasterKey = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);

        $sealed = $this->rewriteEnvelope(
            $this->subject->seal('payload', self::IDENTIFIER),
            static function (array $envelope): array {
                $envelope['a_field_from_the_future'] = 'must survive';
                $envelope['another_one'] = 42;

                return $envelope;
            },
        );

        $rewrapped = $this->subject->rewrap($sealed, self::IDENTIFIER, $this->masterKey, $newMasterKey);

        self::assertSame('must survive', $this->envelopeField($rewrapped, 'a_field_from_the_future'));

        $body = base64_decode(substr($rewrapped, \strlen(EnvelopeCodecInterface::MARKER)), true);
        self::assertIsString($body);
        $decoded = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertArrayHasKey('another_one', $decoded);
        self::assertSame(42, $decoded['another_one']);

        // And it still opens under the new key.
        $newCodec = new EnvelopeCodec($this->encryptionServiceFor($newMasterKey));
        self::assertSame('payload', $newCodec->open($rewrapped, self::IDENTIFIER));
    }

    /**
     * An envelope that legitimately carried no checksum must not come back with an
     * invented empty one.
     */
    #[Test]
    public function rewrappingDoesNotInventAnAbsentOptionalField(): void
    {
        $newMasterKey = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);

        $sealed = $this->rewriteEnvelope(
            $this->subject->seal('payload', self::IDENTIFIER),
            static function (array $envelope): array {
                unset($envelope['value_checksum']);

                return $envelope;
            },
        );

        $rewrapped = $this->subject->rewrap($sealed, self::IDENTIFIER, $this->masterKey, $newMasterKey);

        $body = base64_decode(substr($rewrapped, \strlen(EnvelopeCodecInterface::MARKER)), true);
        self::assertIsString($body);
        $decoded = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        self::assertArrayNotHasKey('value_checksum', $decoded);
    }

    private function encryptionServiceFor(string $masterKey): EncryptionService
    {
        $provider = $this->createMock(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willReturn($masterKey);

        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('preferXChaCha20')->willReturn(false);

        return new EncryptionService($provider, $configuration);
    }

    /**
     * Decode a sealed string, hand the envelope array to $mutate, re-encode.
     *
     * @param callable(array<string, mixed>): array<string, mixed> $mutate
     */
    private function rewriteEnvelope(string $sealed, callable $mutate): string
    {
        $body = base64_decode(substr($sealed, \strlen(EnvelopeCodecInterface::MARKER)), true);
        self::assertIsString($body);

        $envelope = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($envelope);

        /** @var array<string, mixed> $envelope */
        $mutated = $mutate($envelope);

        return EnvelopeCodecInterface::MARKER . base64_encode(json_encode($mutated, JSON_THROW_ON_ERROR));
    }

    private function envelopeField(string $sealed, string $field): string
    {
        $body = base64_decode(substr($sealed, \strlen(EnvelopeCodecInterface::MARKER)), true);
        self::assertIsString($body);

        $envelope = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($envelope);
        self::assertArrayHasKey($field, $envelope);
        self::assertIsString($envelope[$field]);

        return $envelope[$field];
    }

    private static function b64(string $value): string
    {
        return base64_encode($value);
    }
}
