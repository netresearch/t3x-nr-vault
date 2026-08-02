<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use ErrorException;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptionService;
use Netresearch\NrVault\Crypto\EnvelopeCodec;
use Netresearch\NrVault\Crypto\EnvelopeCodecInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\EnvelopeFormatException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Robustness properties of the sealed-envelope wire format.
 *
 * {@see CryptoFuzzTest} fuzzes the {@see EncryptionService} boundary (bit flips
 * in the four base64 columns, wrong identifier, invalid base64). This suite
 * attacks the layer ABOVE it — the `nrv1:` + base64(JSON) framing parsed by
 * {@see EnvelopeCodec} — where a malformed input reaches `substr()`,
 * `base64_decode()` and `json_decode()` before any key material is touched.
 *
 * The invariant defended here is deliberately phrased in terms of what the
 * AEAD actually authenticates:
 *
 *   Corrupting a sealed envelope MUST either fail loudly — EnvelopeFormatException
 *   (framing broken) or EncryptionException (framing intact, authentication
 *   failed) — or return the ORIGINAL plaintext unchanged. It must never return a
 *   different value, and never surface as a raw PHP warning/notice instead of a
 *   domain exception.
 *
 * The "or return the original plaintext" arm is not slack in the crypto, it is
 * slack in the FRAMING, and two sources of it are real and by design:
 *
 *  1. base64 padding is malleable — `…fQ==` and `…fQ` decode to identical bytes,
 *     so trimming padding produces a different envelope STRING for the same
 *     authenticated bytes ({@see droppingBase64PaddingStillOpensTheSameEnvelope}).
 *  2. `value_checksum` is optional and unknown fields are ignored by
 *     {@see EnvelopeCodec}, so damage confined to them changes nothing the
 *     codec reads ({@see damageConfinedToTheOptionalChecksumStillOpens}).
 *
 * Neither weakens confidentiality or integrity: the payload, the wrapped DEK,
 * both nonces, the identifier (AAD) and the algorithm marker are all covered by
 * the AEAD tag, and {@see aBitFlipInAnyAuthenticatedFieldIsAlwaysRejected} pins
 * that any change to them is refused unconditionally.
 *
 * The no-PHP-diagnostic half is enforced twice over: `Build/phpunit.xml` sets
 * `failOnWarning="true"`, and the sweeps below additionally install an error
 * handler that promotes any diagnostic to {@see ErrorException}, so a warning
 * raised inside the codec fails on the exception TYPE at the call site instead
 * of being attributed to the test run at large.
 */
#[CoversClass(EnvelopeCodec::class)]
final class EnvelopeRobustnessFuzzTest extends TestCase
{
    private const IDENTIFIER = '01937b6e-4b6c-7abc-8def-e0e0e0e0e001';

    private const PLAINTEXT = 'envelope-robustness-canary-value';

    /** Fields covered by the AEAD tag — damage to any of them must be refused. */
    private const AUTHENTICATED_FIELDS = [
        'encrypted_value',
        'encrypted_dek',
        'dek_nonce',
        'value_nonce',
    ];

    private EnvelopeCodec $subject;

    private string $sealed;

    /** Value returned by the most recent successful {@see captureFailure()} call. */
    private ?string $opened = null;

    protected function setUp(): void
    {
        parent::setUp();

        $provider = self::createStub(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willReturn(random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES));

        // Pin XChaCha20 for BOTH the new-envelope marker and the legacy
        // host-derived path, so a mutated version marker cannot change which
        // algorithm the codec picks as a side effect of test configuration.
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('preferXChaCha20')->willReturn(true);
        $configuration->method('getEncryptionAlgorithm')->willReturn('xchacha20poly1305');

        $this->subject = new EnvelopeCodec(new EncryptionService($provider, $configuration));
        $this->sealed = $this->subject->seal(self::PLAINTEXT, self::IDENTIFIER);
    }

    /**
     * Truncation sweep: cutting a sealed envelope at EVERY byte offset — one
     * byte short, halfway, marker-only, empty — must never yield a foreign
     * plaintext, and anything that cuts into the encoded body must be refused
     * outright.
     *
     * A single loop rather than ~560 data-provider rows: the assertion is one
     * property over the whole offset range, and the sweep is the cheapest way
     * to prove there is no "lucky" length that parses into a partial decrypt.
     */
    #[Test]
    public function everyTruncationOfASealedEnvelopeIsRejected(): void
    {
        $length = \strlen($this->sealed);
        self::assertGreaterThan(\strlen(EnvelopeCodecInterface::MARKER), $length);

        $openedAt = [];

        for ($cut = 0; $cut < $length; $cut++) {
            if ($this->assertNeverYieldsForeignPlaintext(
                substr($this->sealed, 0, $cut),
                \sprintf('envelope truncated to %d of %d bytes', $cut, $length),
            )) {
                $openedAt[] = $cut;
            }
        }

        // The only truncations allowed to open are those that remove nothing but
        // base64 padding, i.e. the last two bytes of the envelope. A cut further
        // left that still opens would mean the body is being parsed loosely.
        foreach ($openedAt as $cut) {
            self::assertGreaterThanOrEqual(
                $length - 2,
                $cut,
                \sprintf(
                    'Truncation to %d of %d bytes opened the envelope — only base64 padding '
                    . '(the final two bytes) may be droppable without changing the decoded body',
                    $cut,
                    $length,
                ),
            );
        }
    }

    /**
     * Truncation from the FRONT (marker eaten) and from the MIDDLE (a byte
     * excised from an otherwise complete body) are separate framing attacks:
     * the first loses the marker, the second keeps a valid-looking prefix.
     */
    #[Test]
    public function envelopesMissingLeadingOrInteriorBytesAreRejected(): void
    {
        $length = \strlen($this->sealed);
        $half = (int) ($length / 2);

        $mutilated = [
            'leading byte removed' => substr($this->sealed, 1),
            'marker removed' => substr($this->sealed, \strlen(EnvelopeCodecInterface::MARKER)),
            'interior byte excised' => substr($this->sealed, 0, $half) . substr($this->sealed, $half + 1),
            'body halved' => substr($this->sealed, 0, $half),
        ];

        foreach ($mutilated as $label => $candidate) {
            self::assertFalse(
                $this->assertNeverYieldsForeignPlaintext($candidate, $label),
                $label . ' must not open',
            );
        }
    }

    /**
     * Bit-flip sweep over the SEALED STRING (not the decoded columns): flipping
     * any single bit of the marker, the base64 alphabet or the encoded JSON must
     * never produce a foreign plaintext. Most offsets break framing
     * (EnvelopeFormatException) or authentication (EncryptionException); the
     * handful that land in the optional checksum or in base64 padding slack
     * legitimately return the original value unchanged.
     */
    #[Test]
    public function noSingleBitFlipInASealedEnvelopeYieldsAForeignPlaintext(): void
    {
        $length = \strlen($this->sealed);

        for ($offset = 0; $offset < $length; $offset++) {
            foreach ([0x01, 0x20, 0x80] as $mask) {
                $flipped = $this->sealed;
                $flipped[$offset] = \chr(\ord($flipped[$offset]) ^ $mask);

                if ($flipped === $this->sealed) {
                    continue;
                }

                $this->assertNeverYieldsForeignPlaintext(
                    $flipped,
                    \sprintf('bit flip at offset %d (mask 0x%02x)', $offset, $mask),
                );
            }
        }
    }

    /**
     * The strong form of the tamper property, on the fields the AEAD actually
     * covers: flipping a bit anywhere inside the ciphertext, the wrapped DEK or
     * either nonce must ALWAYS be refused — no framing slack applies here.
     *
     * Flips are applied to the DECODED bytes and re-encoded, so each case
     * exercises authentication rather than base64 validation.
     *
     * @return iterable<string, array{string, int, int}>
     */
    public static function authenticatedFieldFlipProvider(): iterable
    {
        foreach (self::AUTHENTICATED_FIELDS as $field) {
            foreach ([0, 1, 7, 11, 15, 23, 31, 47] as $position) {
                foreach ([0x01, 0x80] as $mask) {
                    yield \sprintf('%s byte %d xor 0x%02x', $field, $position, $mask) => [$field, $position, $mask];
                }
            }
        }
    }

    #[Test]
    #[DataProvider('authenticatedFieldFlipProvider')]
    public function aBitFlipInAnyAuthenticatedFieldIsAlwaysRejected(string $field, int $position, int $mask): void
    {
        $tampered = $this->rewriteEnvelope(static function (array $envelope) use ($field, $position, $mask): array {
            $encoded = $envelope[$field];
            self::assertIsString($encoded, $field . ' must be a string');

            $raw = base64_decode($encoded, true);
            self::assertIsString($raw, $field . ' must be decodable');
            self::assertNotSame('', $raw, $field . ' must not be empty');

            $index = $position % \strlen($raw);
            $raw[$index] = \chr(\ord($raw[$index]) ^ $mask);
            $envelope[$field] = base64_encode($raw);

            return $envelope;
        });

        $thrown = $this->captureFailure($tampered);

        self::assertInstanceOf(
            EncryptionException::class,
            $thrown,
            \sprintf(
                'Flipping byte %d of %s must fail authentication, got %s',
                $position,
                $field,
                $thrown instanceof Throwable ? $thrown::class : 'PLAINTEXT (envelope opened!)',
            ),
        );
    }

    /**
     * CHARACTERISATION — base64 padding is not canonical.
     *
     * `…fQ==` and `…fQ` decode to the same bytes, so an envelope has more than
     * one valid string form. Harmless for confidentiality and integrity (the
     * AEAD authenticates the decoded bytes, not their encoding), but it means a
     * sealed string is NOT a canonical identity: anything that compares,
     * de-duplicates or keys a cache on the envelope string must normalise it
     * first rather than assume byte equality implies value equality.
     *
     * Whether a given envelope carries padding depends on its body length mod 3,
     * and the class-level {@see PLAINTEXT} happens to encode without any — so
     * this seals progressively longer payloads until a padded envelope appears
     * instead of skipping. In theory three extra bytes cycle the remainder;
     * in practice one CI run (2026-08-02, combined coverage suite) found no
     * padded envelope within four consecutive lengths, so the probe now spans
     * two full base64 block periods and reports what it actually observed —
     * a bare "not found" hides exactly the numbers needed to diagnose it.
     */
    #[Test]
    public function droppingBase64PaddingStillOpensTheSameEnvelope(): void
    {
        $observed = [];

        for ($extra = 0; $extra <= 8; $extra++) {
            $plaintext = self::PLAINTEXT . str_repeat('.', $extra);
            $sealed = $this->subject->seal($plaintext, self::IDENTIFIER);
            $unpadded = rtrim($sealed, '=');

            if ($unpadded === $sealed) {
                $observed[] = \sprintf('+%d bytes -> length %d, unpadded', $extra, \strlen($sealed));
                continue;
            }

            self::assertSame(
                $plaintext,
                $this->subject->open($unpadded, self::IDENTIFIER),
                'Stripping base64 padding must not change the decoded envelope',
            );

            return;
        }

        self::fail(
            'No padded envelope found in nine consecutive payload lengths — base64 framing changed. Observed: '
            . implode('; ', $observed),
        );
    }

    /**
     * CHARACTERISATION — `value_checksum` is a change-detection token, not an
     * integrity mechanism (ADR-002 / SEC-CRYPTO-1). {@see EnvelopeCodec} treats
     * it as optional and ignores unknown fields, so corrupting it, renaming its
     * key or deleting it outright still opens the envelope. Integrity is the
     * AEAD tag's job, which
     * {@see aBitFlipInAnyAuthenticatedFieldIsAlwaysRejected} covers.
     *
     * @return iterable<string, array{'replace'|'rename'|'remove'}>
     */
    public static function checksumDamageProvider(): iterable
    {
        yield 'checksum value replaced' => ['replace'];
        yield 'checksum key renamed' => ['rename'];
        yield 'checksum removed' => ['remove'];
    }

    /**
     * @param 'remove'|'rename'|'replace' $damage
     */
    #[Test]
    #[DataProvider('checksumDamageProvider')]
    public function damageConfinedToTheOptionalChecksumStillOpens(string $damage): void
    {
        $tampered = $this->rewriteEnvelope(static function (array $envelope) use ($damage): array {
            unset($envelope['value_checksum']);

            if ($damage === 'replace') {
                $envelope['value_checksum'] = str_repeat('0', 64);
            } elseif ($damage === 'rename') {
                // A renamed key is an UNKNOWN field, which the codec ignores.
                $envelope['valte_checksum'] = str_repeat('a', 64);
            }

            return $envelope;
        });

        self::assertSame(
            self::PLAINTEXT,
            $this->subject->open($tampered, self::IDENTIFIER),
            'The checksum is a change detector, not an integrity check — the AEAD tag protects the payload',
        );
    }

    /**
     * Field-swap provider: the envelope's four base64 columns are all
     * structurally interchangeable strings, so a confused writer (or an
     * attacker with write access to the row) can swap them without breaking
     * the framing. Each swap must fail authentication.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function swappedFieldProvider(): iterable
    {
        yield 'ciphertext and wrapped DEK exchanged' => ['encrypted_value', 'encrypted_dek'];
        yield 'DEK nonce and value nonce exchanged' => ['dek_nonce', 'value_nonce'];
    }

    #[Test]
    #[DataProvider('swappedFieldProvider')]
    public function swappingTwoEnvelopeFieldsIsRejected(string $first, string $second): void
    {
        $tampered = $this->rewriteEnvelope(static function (array $envelope) use ($first, $second): array {
            [$envelope[$first], $envelope[$second]] = [$envelope[$second], $envelope[$first]];

            return $envelope;
        });

        $thrown = $this->captureFailure($tampered);

        self::assertInstanceOf(
            EncryptionException::class,
            $thrown,
            \sprintf(
                'Swapping %s with %s must fail authentication, got %s',
                $first,
                $second,
                $thrown instanceof Throwable ? $thrown::class : 'PLAINTEXT (envelope opened!)',
            ),
        );
    }

    /**
     * Copying one field over another (rather than exchanging them) is the other
     * half of the confusion attack — notably reusing the value nonce as the DEK
     * nonce, which is what a nonce-reuse bug would look like on the wire.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function overwrittenFieldProvider(): iterable
    {
        yield 'value nonce reused as DEK nonce' => ['dek_nonce', 'value_nonce'];
        yield 'DEK nonce reused as value nonce' => ['value_nonce', 'dek_nonce'];
        yield 'wrapped DEK written over ciphertext' => ['encrypted_value', 'encrypted_dek'];
        yield 'ciphertext written over wrapped DEK' => ['encrypted_dek', 'encrypted_value'];
    }

    #[Test]
    #[DataProvider('overwrittenFieldProvider')]
    public function overwritingOneEnvelopeFieldWithAnotherIsRejected(string $target, string $source): void
    {
        $tampered = $this->rewriteEnvelope(static function (array $envelope) use ($target, $source): array {
            $envelope[$target] = $envelope[$source];

            return $envelope;
        });

        $thrown = $this->captureFailure($tampered);

        self::assertInstanceOf(
            EncryptionException::class,
            $thrown,
            \sprintf(
                'Writing %s over %s must fail authentication, got %s',
                $source,
                $target,
                $thrown instanceof Throwable ? $thrown::class : 'PLAINTEXT (envelope opened!)',
            ),
        );
    }

    /**
     * Unknown algorithm markers on a version-2-or-newer envelope. The marker is
     * authoritative for version >= 2 ({@see EncryptionService::resolveAlgorithm()}),
     * so an unrecognised or empty id must abort instead of falling back to a
     * host-derived guess.
     *
     * @return iterable<string, array{int, string}>
     */
    public static function unknownAlgorithmMarkerProvider(): iterable
    {
        yield 'current version, unknown id' => [2, 'rot13'];
        yield 'current version, empty id' => [2, ''];
        yield 'current version, near-miss id' => [2, 'xchacha20poly1306'];
        yield 'current version, wrong case' => [2, 'XChaCha20Poly1305'];
        yield 'current version, legacy openssl name' => [2, 'aes-256-gcm'];
        yield 'future version, unknown id' => [3, 'rot13'];
        yield 'far-future version, unknown id' => [99, 'some-future-aead'];
    }

    #[Test]
    #[DataProvider('unknownAlgorithmMarkerProvider')]
    public function anUnknownAlgorithmMarkerIsRejected(int $version, string $algorithm): void
    {
        $tampered = $this->rewriteEnvelope(static function (array $envelope) use ($version, $algorithm): array {
            $envelope['encryption_version'] = $version;
            $envelope['encryption_algorithm'] = $algorithm;

            return $envelope;
        });

        $thrown = $this->captureFailure($tampered);

        self::assertInstanceOf(
            EncryptionException::class,
            $thrown,
            \sprintf(
                'Envelope claiming version %d with algorithm "%s" must be refused, got %s',
                $version,
                $algorithm,
                $thrown instanceof Throwable ? $thrown::class : 'PLAINTEXT (envelope opened!)',
            ),
        );
        self::assertStringNotContainsString(
            self::PLAINTEXT,
            $thrown->getMessage(),
            'The refusal message must not leak the protected value',
        );
    }

    /**
     * A marker naming a REAL but different algorithm must fail authentication
     * rather than decrypt: the recorded algorithm is what the payload was
     * sealed with, and disagreeing with it is indistinguishable from tampering.
     */
    #[Test]
    public function aValidButMismatchedAlgorithmMarkerFailsAuthentication(): void
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            self::markTestSkipped('AES-256-GCM not available on this platform');
        }

        $tampered = $this->rewriteEnvelope(static function (array $envelope): array {
            // Sealed with XChaCha20-Poly1305; claim AES-256-GCM instead.
            $envelope['encryption_algorithm'] = 'aes256gcm';

            return $envelope;
        });

        self::assertInstanceOf(
            EncryptionException::class,
            $this->captureFailure($tampered),
            'A mismatched-but-known algorithm marker must fail authentication, not decrypt',
        );
    }

    /**
     * An envelope claiming a version this build does not implement must be
     * refused, never opened under the current version's rules: a future
     * version may change the framing, the KDF or the AAD, and decrypting it
     * with the wrong recipe is worse than failing. Forward compatibility has
     * to be a deliberate code change, not an accident of a `>=` comparison.
     */
    #[Test]
    public function anEnvelopeClaimingAnUnimplementedVersionIsRefused(): void
    {
        foreach ([0, 3, 99, \PHP_INT_MAX] as $version) {
            $tampered = $this->rewriteEnvelope(static function (array $envelope) use ($version): array {
                $envelope['encryption_version'] = $version;

                return $envelope;
            });

            $refused = false;

            try {
                $this->subject->open($tampered, self::IDENTIFIER);
            } catch (EncryptionException|EnvelopeFormatException) {
                $refused = true;
            }

            self::assertTrue(
                $refused,
                \sprintf('Envelope claiming unimplemented version %d was opened.', $version),
            );
        }
    }

    /**
     * Assert the corrupted candidate either fails with a domain exception or
     * returns the ORIGINAL plaintext (framing slack only) — never a foreign
     * value, never a PHP diagnostic.
     *
     * @return bool whether the envelope opened (true) or was refused (false)
     */
    private function assertNeverYieldsForeignPlaintext(string $candidate, string $label): bool
    {
        $thrown = $this->captureFailure($candidate);

        if (!$thrown instanceof Throwable) {
            self::assertSame(
                self::PLAINTEXT,
                $this->opened,
                \sprintf('%s opened and returned a value other than the sealed plaintext', $label),
            );

            return true;
        }

        self::assertThat(
            $thrown,
            self::logicalOr(
                self::isInstanceOf(EnvelopeFormatException::class),
                self::isInstanceOf(EncryptionException::class),
            ),
            \sprintf('%s must raise a domain exception, got %s: %s', $label, $thrown::class, $thrown->getMessage()),
        );

        return false;
    }

    /**
     * Open the candidate and return the exception it raised, or null if it
     * opened successfully (in which case the plaintext is in {@see $opened}).
     *
     * Any PHP diagnostic raised inside the codec is promoted to
     * {@see ErrorException} so it is reported as a wrong exception TYPE at the
     * call site instead of a detached test-run warning.
     */
    private function captureFailure(string $candidate): ?Throwable
    {
        $this->opened = null;

        set_error_handler(
            static function (int $severity, string $message, string $file, int $line): bool {
                throw new ErrorException($message, 0, $severity, $file, $line);
            },
        );

        try {
            $this->opened = $this->subject->open($candidate, self::IDENTIFIER);

            return null;
        } catch (Throwable $exception) {
            return $exception;
        } finally {
            restore_error_handler();
        }
    }

    /**
     * Decode the sealed envelope, hand its fields to $mutate, re-encode.
     *
     * @param callable(array<string, mixed>): array<string, mixed> $mutate
     */
    private function rewriteEnvelope(callable $mutate): string
    {
        $body = base64_decode(substr($this->sealed, \strlen(EnvelopeCodecInterface::MARKER)), true);
        self::assertIsString($body);

        $envelope = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        self::assertIsArray($envelope);

        /** @var array<string, mixed> $envelope */
        return EnvelopeCodecInterface::MARKER
            . base64_encode(json_encode($mutate($envelope), JSON_THROW_ON_ERROR));
    }
}
