<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptedData;
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
        );

        self::assertEquals($plaintext, $decrypted);
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
    public function reEncryptDekWorksWithNewMasterKey(): void
    {
        $plaintext = 'reencrypt-test';
        $identifier = 'reencrypt-secret';
        $oldMasterKey = $this->testMasterKey;
        $newMasterKey = random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);

        // First encrypt with old master key
        $encrypted = $this->subject->encrypt($plaintext, $identifier);

        // Re-encrypt DEK with new master key
        $reEncrypted = $this->subject->reEncryptDek(
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $identifier,
            $oldMasterKey,
            $newMasterKey,
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
        // Configure to prefer XChaCha20
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
}
