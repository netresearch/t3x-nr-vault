<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptedData;
use Netresearch\NrVault\Crypto\EncryptionAlgorithm;
use Netresearch\NrVault\Crypto\EncryptionService;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;

#[CoversClass(EncryptionService::class)]
#[AllowMockObjectsWithoutExpectations]
final class EncryptionServiceTest extends TestCase
{
    private EncryptionService $subject;

    private MasterKeyProviderInterface&MockObject $masterKeyProvider;

    private ExtensionConfigurationInterface&MockObject $configuration;

    private string $testMasterKey;

    protected function setUp(): void
    {
        parent::setUp();

        // Generate a test master key (32 bytes)
        $this->testMasterKey = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);

        $this->masterKeyProvider = $this->createMock(MasterKeyProviderInterface::class);
        $this->masterKeyProvider
            ->method('getMasterKey')
            ->willReturn($this->testMasterKey);

        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->configuration
            ->method('preferXChaCha20')
            ->willReturn(false);

        $this->subject = new EncryptionService(
            $this->masterKeyProvider,
            $this->configuration,
        );
    }

    #[Test]
    public function encryptReturnsExpectedDtoStructure(): void
    {
        $plaintext = 'my-secret-api-key-12345';
        $identifier = 'test-secret';

        $result = $this->subject->encrypt($plaintext, $identifier);

        self::assertInstanceOf(EncryptedData::class, $result);
        self::assertNotEmpty($result->encryptedValue);
        self::assertNotEmpty($result->encryptedDek);
        self::assertNotEmpty($result->dekNonce);
        self::assertNotEmpty($result->valueNonce);
        self::assertNotEmpty($result->valueChecksum);
    }

    #[Test]
    public function encryptedValueIsDifferentFromPlaintext(): void
    {
        $plaintext = 'sensitive-password-123';
        $identifier = 'password-secret';

        $result = $this->subject->encrypt($plaintext, $identifier);

        // Encrypted value should be base64 encoded and different from plaintext
        self::assertNotEquals($plaintext, $result->encryptedValue);
        self::assertNotEmpty($result->encryptedValue);

        // Verify it's valid base64
        $decoded = base64_decode($result->encryptedValue, true);
        self::assertNotFalse($decoded);
    }

    #[Test]
    public function encryptGeneratesUniqueNoncesPerCall(): void
    {
        $plaintext = 'test-secret';
        $identifier = 'nonce-test';

        $result1 = $this->subject->encrypt($plaintext, $identifier);
        $result2 = $this->subject->encrypt($plaintext, $identifier);

        // Each encryption should use unique nonces
        self::assertNotEquals($result1->dekNonce, $result2->dekNonce);
        self::assertNotEquals($result1->valueNonce, $result2->valueNonce);

        // Each encryption generates a new DEK
        self::assertNotEquals($result1->encryptedDek, $result2->encryptedDek);
    }

    #[Test]
    public function decryptReturnsOriginalPlaintext(): void
    {
        $plaintext = 'original-secret-value';
        $identifier = 'decrypt-test';

        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        $decrypted = $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
            $encrypted->encryptionVersion,
            $encrypted->encryptionAlgorithm->value,
        );

        self::assertEquals($plaintext, $decrypted);
    }

    #[Test]
    public function decryptRefusesAnUnimplementedEncryptionVersion(): void
    {
        $plaintext = 'version-guard';
        $identifier = 'version-guard-test';

        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        // A version above the current one may change framing, KDF or AAD; the
        // reader must refuse it rather than decrypt under version-2 rules.
        $this->expectException(EncryptionException::class);

        $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
            $encrypted->encryptionVersion + 1,
            $encrypted->encryptionAlgorithm->value,
        );
    }

    #[Test]
    public function decryptRefusesAnEncryptionVersionBelowLegacy(): void
    {
        $plaintext = 'version-floor';
        $identifier = 'version-floor-test';

        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        $this->expectException(EncryptionException::class);

        $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
            0,
            $encrypted->encryptionAlgorithm->value,
        );
    }

    #[Test]
    public function decryptWithWrongIdentifierThrowsException(): void
    {
        $plaintext = 'secret-with-aad';
        $identifier = 'correct-identifier';

        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        $this->expectException(EncryptionException::class);

        $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            'wrong-identifier', // Different AAD
            $encrypted->encryptionVersion,
            $encrypted->encryptionAlgorithm->value,
        );
    }

    #[Test]
    public function decryptWithTamperedDataThrowsException(): void
    {
        $plaintext = 'untampered-secret';
        $identifier = 'tamper-test';

        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        // Flip every bit in the last ciphertext byte. The previous
        // implementation appended a literal 'X' which collided with the
        // original byte on ~1/256 runs (when it happened to already be
        // 0x58) and let decryption succeed correctly — a real CI flake
        // (see PR #147 / main-CI on 222009c). XOR-with-0xFF guarantees
        // a different byte regardless of the underlying value.
        $raw = base64_decode($encrypted->encryptedValue, true);
        self::assertIsString($raw, 'EncryptedData::$encryptedValue must be valid base64');
        $lastIndex = \strlen($raw) - 1;
        $flipped = \chr(\ord($raw[$lastIndex]) ^ 0xFF);
        $tamperedValue = base64_encode(substr($raw, 0, $lastIndex) . $flipped);

        $this->expectException(EncryptionException::class);

        $this->subject->decrypt(
            $tamperedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
            $encrypted->encryptionVersion,
            $encrypted->encryptionAlgorithm->value,
        );
    }

    #[Test]
    public function decryptWithInvalidBase64ThrowsException(): void
    {
        $this->expectException(EncryptionException::class);

        $this->subject->decrypt(
            '!!!invalid-base64!!!',
            'also-invalid',
            'not-valid',
            'nope',
            'test',
        );
    }

    #[Test]
    public function generateDekReturnsCorrectKeyLength(): void
    {
        $dek = $this->subject->generateDek();

        // AES-256-GCM key should be 32 bytes
        self::assertEquals(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES, \strlen($dek));
    }

    #[Test]
    public function generateDekReturnsRandomBytes(): void
    {
        $dek1 = $this->subject->generateDek();
        $dek2 = $this->subject->generateDek();

        // Each call should generate a unique key
        self::assertNotEquals($dek1, $dek2);
    }

    #[Test]
    public function calculateChecksumReturnsSha256Hash(): void
    {
        $plaintext = 'checksum-test-value';

        $checksum = $this->subject->calculateChecksum($plaintext);

        // SHA-256 produces 64 hex characters
        self::assertEquals(64, \strlen($checksum));
        self::assertEquals(hash('sha256', $plaintext), $checksum);
    }

    #[Test]
    public function checksumIsDeterministic(): void
    {
        $plaintext = 'deterministic-value';

        $checksum1 = $this->subject->calculateChecksum($plaintext);
        $checksum2 = $this->subject->calculateChecksum($plaintext);

        self::assertEquals($checksum1, $checksum2);
    }

    #[Test]
    public function encryptValueChecksumIsHex64(): void
    {
        $encrypted = $this->subject->encrypt('shape-check', 'shape-id');

        // Keep the 64-hex shape so downstream/audit usage is unchanged.
        self::assertSame(64, \strlen($encrypted->valueChecksum));
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $encrypted->valueChecksum);
    }

    #[Test]
    public function encryptValueChecksumIsNotPlaintextSha256(): void
    {
        $plaintext = 'low-entropy-guessable-secret';

        $encrypted = $this->subject->encrypt($plaintext, 'oracle-id');

        // The stored change-detection token must NOT be an offline-computable
        // function of the plaintext (SEC-CRYPTO-1): no sha256(plaintext) oracle.
        self::assertNotSame(hash('sha256', $plaintext), $encrypted->valueChecksum);
    }

    #[Test]
    public function encryptValueChecksumDiffersPerSecretForIdenticalPlaintext(): void
    {
        $plaintext = 'identical-plaintext-across-secrets';

        $first = $this->subject->encrypt($plaintext, 'secret-a');
        $second = $this->subject->encrypt($plaintext, 'secret-b');

        // Per-secret DEK => per-secret MAC key + per-call ciphertext => the
        // checksum must not leak plaintext equality across secrets.
        self::assertNotSame($first->valueChecksum, $second->valueChecksum);
    }

    #[Test]
    public function decryptStillSucceedsAfterTamperedDecryptInSameRequest(): void
    {
        // Proves the throw path's DEK wipe (a finally on a fresh local $dek)
        // does not clobber the shared request-cached master key: a tampered
        // decrypt throws, yet a subsequent legitimate decrypt still works.
        $plaintext = 'sequential-decrypt-secret';
        $identifier = 'seq-id';

        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        $raw = base64_decode($encrypted->encryptedValue, true);
        self::assertIsString($raw);
        $lastIndex = \strlen($raw) - 1;
        $flipped = \chr(\ord($raw[$lastIndex]) ^ 0xFF);
        $tamperedValue = base64_encode(substr($raw, 0, $lastIndex) . $flipped);

        $threw = false;

        try {
            $this->subject->decrypt(
                $tamperedValue,
                $encrypted->encryptedDek,
                $encrypted->dekNonce,
                $encrypted->valueNonce,
                $identifier,
                $encrypted->encryptionVersion,
                $encrypted->encryptionAlgorithm->value,
            );
        } catch (EncryptionException) {
            $threw = true;
        }
        self::assertTrue($threw, 'tampered ciphertext must fail closed on the throw path');

        // Same request, legitimate decrypt must still round-trip.
        $decrypted = $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
            $encrypted->encryptionVersion,
            $encrypted->encryptionAlgorithm->value,
        );
        self::assertSame($plaintext, $decrypted);
    }

    #[Test]
    public function reEncryptDekWorksWithNewMasterKey(): void
    {
        $plaintext = 'reencrypt-test';
        $identifier = 'reencrypt-secret';
        $oldMasterKey = $this->testMasterKey;
        $newMasterKey = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);

        // First encrypt with old master key
        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        // Re-encrypt DEK with new master key, honouring the stored marker
        $reEncrypted = $this->subject->reEncryptDek(
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $identifier,
            $oldMasterKey,
            $newMasterKey,
            $encrypted->encryptionVersion,
            $encrypted->encryptionAlgorithm->value,
        );

        self::assertNotEmpty($reEncrypted->encryptedDek);
        self::assertNotEmpty($reEncrypted->nonce);

        // The new encrypted DEK should be different
        self::assertNotEquals($encrypted->encryptedDek, $reEncrypted->encryptedDek);
    }

    #[Test]
    public function encryptHandlesEmptyString(): void
    {
        $plaintext = '';
        $identifier = 'empty-secret';

        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        self::assertNotEmpty($encrypted->encryptedValue);

        $decrypted = $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
            $encrypted->encryptionVersion,
            $encrypted->encryptionAlgorithm->value,
        );

        self::assertEquals('', $decrypted);
    }

    #[Test]
    public function encryptHandlesLargePayload(): void
    {
        // 1MB of random data
        $plaintext = random_bytes(1024 * 1024);
        $identifier = 'large-secret';

        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        $decrypted = $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
            $encrypted->encryptionVersion,
            $encrypted->encryptionAlgorithm->value,
        );

        self::assertEquals($plaintext, $decrypted);
    }

    #[Test]
    public function encryptHandlesUnicodeContent(): void
    {
        $plaintext = 'Secret with emoji: 🔐🔑 and unicode: äöü 中文';
        $identifier = 'unicode-secret';

        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        $decrypted = $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
            $encrypted->encryptionVersion,
            $encrypted->encryptionAlgorithm->value,
        );

        self::assertEquals($plaintext, $decrypted);
    }

    #[Test]
    public function encryptWithXChaCha20WhenConfigured(): void
    {
        // Configure to prefer XChaCha20
        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->configuration
            ->method('preferXChaCha20')
            ->willReturn(true);

        $subject = new EncryptionService(
            $this->masterKeyProvider,
            $this->configuration,
        );

        $plaintext = 'xchacha-test';
        $identifier = 'xchacha-secret';

        $encrypted = $subject->encrypt($plaintext, $identifier);

        // Should still work with XChaCha20
        self::assertNotEmpty($encrypted->encryptedValue);
        self::assertNotEmpty($encrypted->encryptedDek);
    }

    #[Test]
    public function encryptAndDecryptRoundtripWithXChaCha20(): void
    {
        // Configure to prefer XChaCha20. The marker-less decrypt below
        // deliberately exercises the LEGACY (version-1) resolution path,
        // which resolves to XChaCha20 here and matches the new envelope.
        $xchachaConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $xchachaConfig
            ->method('preferXChaCha20')
            ->willReturn(true);

        $subject = new EncryptionService(
            $this->masterKeyProvider,
            $xchachaConfig,
        );

        $plaintext = 'xchacha-roundtrip-secret';
        $identifier = 'xchacha-roundtrip';

        $encrypted = $subject->encrypt($plaintext, $identifier);

        $decrypted = $subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
        );

        self::assertEquals($plaintext, $decrypted);
    }

    #[Test]
    public function generateDekWithXChaCha20ReturnsCorrectLength(): void
    {
        $xchachaConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $xchachaConfig
            ->method('preferXChaCha20')
            ->willReturn(true);

        $subject = new EncryptionService(
            $this->masterKeyProvider,
            $xchachaConfig,
        );

        $dek = $subject->generateDek();

        // XChaCha20-Poly1305 key should be 32 bytes
        self::assertEquals(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, \strlen($dek));
    }

    #[Test]
    public function reEncryptDekWithXChaCha20(): void
    {
        $xchachaConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $xchachaConfig
            ->method('preferXChaCha20')
            ->willReturn(true);

        $subject = new EncryptionService(
            $this->masterKeyProvider,
            $xchachaConfig,
        );

        $plaintext = 'reencrypt-xchacha';
        $identifier = 'reencrypt-xchacha-secret';
        $oldMasterKey = $this->testMasterKey;
        $newMasterKey = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);

        $encrypted = $subject->encrypt($plaintext, $identifier);

        $reEncrypted = $subject->reEncryptDek(
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $identifier,
            $oldMasterKey,
            $newMasterKey,
        );

        self::assertNotEmpty($reEncrypted->encryptedDek);
        self::assertNotEmpty($reEncrypted->nonce);
        self::assertNotEquals($encrypted->encryptedDek, $reEncrypted->encryptedDek);
    }

    #[Test]
    public function reEncryptDekWithInvalidBase64Throws(): void
    {
        $this->expectException(EncryptionException::class);

        $this->subject->reEncryptDek(
            '!!!invalid!!!',
            'also-invalid',
            'test',
            $this->testMasterKey,
            random_bytes(32),
        );
    }

    // ---------------------------------------------------------------
    // Encryption version / algorithm marker (encryption version 2).
    // ---------------------------------------------------------------

    #[Test]
    public function encryptRecordsVersionTwoWithXChaChaDefaultAlgorithm(): void
    {
        // The default subject's config prefers AES for LEGACY decrypts
        // (preferXChaCha20=false) — new envelopes must nonetheless default
        // to the host-independent XChaCha20-Poly1305 and record it.
        $encrypted = $this->subject->encrypt('marker-test', 'marker-id');

        self::assertSame(EncryptionService::ENCRYPTION_VERSION_CURRENT, $encrypted->encryptionVersion);
        self::assertSame(EncryptionAlgorithm::XChaCha20Poly1305, $encrypted->encryptionAlgorithm);
    }

    #[Test]
    public function encryptRecordsConfiguredAesAlgorithm(): void
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            self::markTestSkipped('AES-256-GCM not available on this platform');
        }

        $aesConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $aesConfig->method('getEncryptionAlgorithm')->willReturn('aes256gcm');

        $subject = new EncryptionService($this->masterKeyProvider, $aesConfig);

        $encrypted = $subject->encrypt('aes-marker-test', 'aes-marker-id');

        self::assertSame(EncryptionAlgorithm::Aes256Gcm, $encrypted->encryptionAlgorithm);

        $decrypted = $subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            'aes-marker-id',
            $encrypted->encryptionVersion,
            $encrypted->encryptionAlgorithm->value,
        );
        self::assertSame('aes-marker-test', $decrypted);
    }

    #[Test]
    public function encryptThrowsOnUnknownConfiguredAlgorithm(): void
    {
        $brokenConfig = $this->createMock(ExtensionConfigurationInterface::class);
        $brokenConfig->method('getEncryptionAlgorithm')->willReturn('rot13');

        $subject = new EncryptionService($this->masterKeyProvider, $brokenConfig);

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unknown encryptionAlgorithm');

        $subject->encrypt('value', 'id');
    }

    #[Test]
    public function decryptSelectsAlgorithmFromStoredMarkerNotHostPreference(): void
    {
        // The envelope is XChaCha20 (version 2 marker); the subject's legacy
        // host-derivation would pick AES on AES-capable hosts. Passing the
        // stored marker must decrypt correctly regardless of host preference.
        $encrypted = $this->subject->encrypt('marker-dispatch', 'marker-dispatch-id');

        $decrypted = $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            'marker-dispatch-id',
            $encrypted->encryptionVersion,
            $encrypted->encryptionAlgorithm->value,
        );

        self::assertSame('marker-dispatch', $decrypted);

        // Counter-check: OMITTING the marker (legacy version-1 resolution)
        // must NOT silently decrypt this XChaCha envelope on hosts whose
        // legacy derivation resolves to AES — the implicitness the marker
        // removes. Only assertable where AES is actually available.
        if (sodium_crypto_aead_aes256gcm_is_available()) {
            $this->expectException(EncryptionException::class);

            $this->subject->decrypt(
                $encrypted->encryptedValue,
                $encrypted->encryptedDek,
                $encrypted->dekNonce,
                $encrypted->valueNonce,
                'marker-dispatch-id',
            );
        }
    }

    #[Test]
    public function decryptVersionTwoWithEmptyAlgorithmMarkerThrows(): void
    {
        $encrypted = $this->subject->encrypt('v2-no-marker', 'v2-no-marker-id');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unknown encryption algorithm marker');

        $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            'v2-no-marker-id',
            EncryptionService::ENCRYPTION_VERSION_CURRENT,
            '',
        );
    }

    #[Test]
    public function decryptVersionTwoWithUnknownAlgorithmMarkerThrows(): void
    {
        $encrypted = $this->subject->encrypt('v2-bad-marker', 'v2-bad-marker-id');

        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Unknown encryption algorithm marker');

        $this->subject->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            'v2-bad-marker-id',
            EncryptionService::ENCRYPTION_VERSION_CURRENT,
            'rot13',
        );
    }
}
