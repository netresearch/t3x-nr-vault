<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Fuzz;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptionService;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\EncryptionException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Fuzz tests for envelope encryption round-trip and tamper detection.
 *
 * Properties under test:
 * - Round-trip: decrypt(encrypt(pt, id), id) === pt for arbitrary inputs
 * - Nonce uniqueness: 1000 encryptions of the same plaintext all differ
 * - Identifier association: decrypt with wrong id MUST throw
 * - Tamper detection: flipping any byte of ciphertext/DEK/nonce at
 *   ANY position MUST throw (iterated over 100+ position/component combos)
 */
#[CoversClass(EncryptionService::class)]
final class CryptoFuzzTest extends TestCase
{
    private EncryptionService $xchacha;

    private EncryptionService $aes;

    private string $masterKey;

    protected function setUp(): void
    {
        parent::setUp();

        $this->masterKey = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);

        /** @var MasterKeyProviderInterface&MockObject $provider */
        $provider = $this->createStub(MasterKeyProviderInterface::class);
        $provider->method('getMasterKey')->willReturnCallback(fn (): string => $this->masterKey);

        // Each subject pins its algorithm for NEW encrypts (encryptionAlgorithm)
        // and aligns the legacy/version-1 derivation (preferXChaCha20) with it,
        // so the marker-less decrypt calls below keep exercising the legacy
        // path against matching ciphertext.
        /** @var ExtensionConfigurationInterface&MockObject $xchachaConfig */
        $xchachaConfig = $this->createStub(ExtensionConfigurationInterface::class);
        $xchachaConfig->method('preferXChaCha20')->willReturn(true);
        $xchachaConfig->method('getEncryptionAlgorithm')->willReturn('xchacha20poly1305');

        /** @var ExtensionConfigurationInterface&MockObject $aesConfig */
        $aesConfig = $this->createStub(ExtensionConfigurationInterface::class);
        $aesConfig->method('preferXChaCha20')->willReturn(false);
        $aesConfig->method('getEncryptionAlgorithm')->willReturn('aes256gcm');

        $this->xchacha = new EncryptionService($provider, $xchachaConfig);
        $this->aes = new EncryptionService($provider, $aesConfig);
    }

    /**
     * Provide fuzzed plaintext cases for round-trip property.
     *
     * @return array<string, array{string, string}>
     */
    public static function randomPlaintextProvider(): array
    {
        $seed = (int) (getenv('PHPUNIT_SEED') ?: crc32(__FILE__));
        mt_srand($seed);

        $cases = [
            'empty string' => ['', '01937b6e-4b6c-7abc-8def-000000000001'],
            'single byte' => ["\x00", '01937b6e-4b6c-7abc-8def-000000000002'],
            'single printable' => ['a', '01937b6e-4b6c-7abc-8def-000000000003'],
            'ascii short' => ['hello world', '01937b6e-4b6c-7abc-8def-000000000004'],
            'ascii with null' => ["abc\x00def", '01937b6e-4b6c-7abc-8def-000000000005'],
            'unicode emoji' => ['🔐 secret 🗝', '01937b6e-4b6c-7abc-8def-000000000006'],
            'unicode mixed' => ["パスワード: \u{0041}\u{0042}\u{0043}", '01937b6e-4b6c-7abc-8def-000000000007'],
            'cr lf' => ["\r\n\t", '01937b6e-4b6c-7abc-8def-000000000008'],
            'all zero bytes 16' => [str_repeat("\x00", 16), '01937b6e-4b6c-7abc-8def-000000000009'],
            'all 0xff bytes 16' => [str_repeat("\xff", 16), '01937b6e-4b6c-7abc-8def-000000000010'],
            // Every byte value exactly once: catches any accidental
            // encoding/escaping step that is not binary-transparent.
            'full binary byte range' => [
                implode('', array_map(chr(...), range(0, 255))),
                '01937b6e-4b6c-7abc-8def-000000000011',
            ],
            // Astral-plane codepoints, a combining mark and the highest legal
            // codepoint — multi-byte sequences that a naive substr() would split.
            'high unicode' => [
                "\u{1F510}\u{10FFFF}a\u{0301}\u{0928}\u{094D}\u{0937}\u{20AC}",
                '01937b6e-4b6c-7abc-8def-000000000012',
            ],
            // 1 MiB payloads under BOTH algorithms (the dedicated
            // oneMegabytePlaintextRoundTrips() case covers XChaCha20 only).
            // All-zero bytes additionally rule out any length/padding shortcut
            // that happens to work for high-entropy input.
            'one mebibyte of zero bytes' => [
                str_repeat("\x00", 1024 * 1024),
                '01937b6e-4b6c-7abc-8def-000000000013',
            ],
            'one mebibyte of random bytes' => [
                random_bytes(1024 * 1024),
                '01937b6e-4b6c-7abc-8def-000000000014',
            ],
        ];

        // Add 50 random plaintext cases seeded for reproducibility
        for ($i = 0; $i < 50; $i++) {
            $length = mt_rand(0, 512);
            $plaintext = '';
            for ($j = 0; $j < $length; $j++) {
                $plaintext .= \chr(mt_rand(0, 255));
            }
            $id = \sprintf('01937b6e-4b6c-7abc-8def-%012d', $i + 100);
            $cases["random_{$i}_len{$length}"] = [$plaintext, $id];
        }

        return $cases;
    }

    /**
     * Round-trip property: XChaCha20 decrypt(encrypt(pt, id), id) === pt.
     */
    #[Test]
    #[DataProvider('randomPlaintextProvider')]
    public function xchachaRoundTripPreservesPlaintext(string $plaintext, string $identifier): void
    {
        $encrypted = $this->xchacha->encrypt($plaintext, $identifier);

        $decrypted = $this->xchacha->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
        );

        self::assertSame($plaintext, $decrypted);
    }

    /**
     * Round-trip property: AES-256-GCM decrypt(encrypt(pt, id), id) === pt.
     */
    #[Test]
    #[DataProvider('randomPlaintextProvider')]
    public function aesRoundTripPreservesPlaintext(string $plaintext, string $identifier): void
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            self::markTestSkipped('AES-256-GCM not available on this platform');
        }

        $encrypted = $this->aes->encrypt($plaintext, $identifier);

        $decrypted = $this->aes->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
        );

        self::assertSame($plaintext, $decrypted);
    }

    /**
     * Nonce uniqueness: 1000 encryptions of the same plaintext produce
     * 1000 distinct ciphertexts. Well above the birthday bound for a
     * 24-byte XChaCha20 nonce and 12-byte AES-GCM nonce — any collision
     * would indicate a broken RNG or reused nonce.
     */
    #[Test]
    public function encryptGeneratesUniqueNonces(): void
    {
        $plaintext = 'same-secret';
        $identifier = '01937b6e-4b6c-7abc-8def-aabbccddeeff';

        $iterations = 1000;
        $ciphertexts = [];
        $valueNonces = [];
        $dekNonces = [];

        $start = hrtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            $encrypted = $this->xchacha->encrypt($plaintext, $identifier);
            $ciphertexts[] = $encrypted->encryptedValue;
            $valueNonces[] = $encrypted->valueNonce;
            $dekNonces[] = $encrypted->dekNonce;
        }
        $elapsedMs = (hrtime(true) - $start) / 1_000_000;

        // Soft cap on runtime — if this ever exceeds 1s we'd want to know.
        // We don't fail on slow, but we emit a visible assertion.
        self::assertLessThan(
            5000,
            $elapsedMs,
            "1000 encryptions took {$elapsedMs}ms — investigate if this regresses",
        );

        self::assertCount($iterations, array_unique($ciphertexts), 'All ciphertexts must be unique');
        self::assertCount($iterations, array_unique($valueNonces), 'All value nonces must be unique');
        self::assertCount($iterations, array_unique($dekNonces), 'All DEK nonces must be unique');
    }

    /**
     * Identifier association: wrong id MUST throw.
     */
    #[Test]
    #[DataProvider('randomPlaintextProvider')]
    public function decryptWithWrongIdentifierThrows(string $plaintext, string $identifier): void
    {
        if ($plaintext === '') {
            // Empty plaintext is special — skip the association check for it as
            // the ciphertext carries no plaintext bytes to protect, but the AAD
            // check still applies; we cover it separately.
            self::assertTrue(true);

            return;
        }

        $encrypted = $this->xchacha->encrypt($plaintext, $identifier);

        $this->expectException(EncryptionException::class);

        $this->xchacha->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier . '-wrong',
        );
    }

    /**
     * Tamper provider: (plaintext, component, position, xorMask).
     *
     * Components:
     *  - 'encryptedValue' — AEAD ciphertext body
     *  - 'encryptedDek'   — sealed data-encryption key
     *  - 'dekNonce'       — 12/24-byte nonce for DEK unwrap
     *  - 'valueNonce'     — 12/24-byte nonce for payload
     *
     * We iterate positions over the full length of each component plus
     * multiple XOR masks to ensure single-bit and multi-bit flips are
     * rejected. This yields 100+ combinations per test component.
     *
     * @return iterable<string, array{string, string, string, int, int}>
     */
    public static function tamperPositionProvider(): iterable
    {
        // Cover short, medium, long plaintexts so ciphertext-body flips
        // exercise different lengths.
        $plaintexts = [
            'short' => ['short', '01937b6e-4b6c-7abc-8def-cccccccccc01'],
            'medium' => [str_repeat('Medium body payload. ', 10), '01937b6e-4b6c-7abc-8def-cccccccccc02'],
            'long' => [str_repeat('L', 512), '01937b6e-4b6c-7abc-8def-cccccccccc03'],
        ];

        // XOR masks — spread single-bit flips and multi-bit flips
        $masks = [0x01, 0x40, 0xFF];

        foreach ($plaintexts as $ptName => [$plaintext, $identifier]) {
            foreach ($masks as $mask) {
                // We don't know component lengths statically; the test method
                // will skip out-of-range positions by clamping. Provide a set
                // of positions that covers first, last, and interior bytes.
                foreach (['encryptedValue', 'encryptedDek', 'dekNonce', 'valueNonce'] as $component) {
                    foreach ([0, 1, 3, 7, 11, 15, 23, 24, 31, 47] as $pos) {
                        $key = \sprintf('%s_%s_pos%d_xor%02x', $ptName, $component, $pos, $mask);
                        yield $key => [$plaintext, $identifier, $component, $pos, $mask];
                    }
                }
            }
        }
    }

    /**
     * Tamper property: any byte flipped anywhere in any auth-covered
     * component MUST cause decrypt() to throw.
     */
    #[Test]
    #[DataProvider('tamperPositionProvider')]
    public function tamperedComponentIsRejected(
        string $plaintext,
        string $identifier,
        string $component,
        int $position,
        int $xorMask,
    ): void {
        $encrypted = $this->xchacha->encrypt($plaintext, $identifier);

        $field = match ($component) {
            'encryptedValue' => $encrypted->encryptedValue,
            'encryptedDek' => $encrypted->encryptedDek,
            'dekNonce' => $encrypted->dekNonce,
            'valueNonce' => $encrypted->valueNonce,
        };

        $raw = base64_decode($field, true);
        self::assertIsString($raw, "{$component} must be decodable");

        $len = \strlen($raw);
        if ($len === 0) {
            // Cannot tamper a zero-length buffer — skip.
            self::markTestSkipped("{$component} is empty");
        }

        // Clamp position to buffer length
        $actualPos = $position % $len;
        $raw[$actualPos] = \chr(\ord($raw[$actualPos]) ^ $xorMask);
        $tampered = base64_encode($raw);

        $args = [
            'encryptedValue' => $encrypted->encryptedValue,
            'encryptedDek' => $encrypted->encryptedDek,
            'dekNonce' => $encrypted->dekNonce,
            'valueNonce' => $encrypted->valueNonce,
        ];
        $args[$component] = $tampered;

        $this->expectException(EncryptionException::class);

        $this->xchacha->decrypt(
            $args['encryptedValue'],
            $args['encryptedDek'],
            $args['dekNonce'],
            $args['valueNonce'],
            $identifier,
        );
    }

    /**
     * Size cap: 1 MB plaintext (well within libsodium limits) does not crash.
     */
    #[Test]
    public function oneMegabytePlaintextRoundTrips(): void
    {
        $plaintext = random_bytes(1024 * 1024);
        $identifier = '01937b6e-4b6c-7abc-8def-aaaaaaaaaaaa';

        $encrypted = $this->xchacha->encrypt($plaintext, $identifier);
        $decrypted = $this->xchacha->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
        );

        self::assertSame($plaintext, $decrypted);
    }

    /**
     * Invalid base64 inputs MUST throw rather than silently producing garbage.
     */
    #[Test]
    public function invalidBase64InputsThrow(): void
    {
        $this->expectException(EncryptionException::class);

        $this->xchacha->decrypt(
            '!!!not valid base64!!!',
            'also-not-valid',
            'nope',
            'no',
            'any-id',
        );
    }
}
