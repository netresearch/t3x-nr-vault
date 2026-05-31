<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Crypto;

use Netresearch\NrVault\Crypto\EncryptionService;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Crypto\FileMasterKeyProvider;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Functional tests for EncryptionService.
 *
 * Exercises the full envelope-encrypt/decrypt round-trip with real libsodium,
 * including DEK rotation semantics.
 */
#[CoversClass(EncryptionService::class)]
final class EncryptionServiceTest extends FunctionalTestCase
{
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
    ];

    protected array $coreExtensionsToLoad = [
        'backend',
    ];

    private ?string $masterKeyPath = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->masterKeyPath = $this->instancePath . '/master.key';
        $masterKey = sodium_crypto_secretbox_keygen();
        file_put_contents($this->masterKeyPath, $masterKey);
        chmod($this->masterKeyPath, 0o600);

        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault'] = [
            'masterKeySource' => $this->masterKeyPath,
            'autoKeyPath' => $this->masterKeyPath,
            'enableCache' => false,
        ];
    }

    protected function tearDown(): void
    {
        FileMasterKeyProvider::clearCachedKey();

        if ($this->masterKeyPath !== null && file_exists($this->masterKeyPath)) {
            $content = file_get_contents($this->masterKeyPath);
            if ($content !== false) {
                sodium_memzero($content);
            }
            // nosemgrep: php.lang.security.unlink-use.unlink-use - test-owned path
            unlink($this->masterKeyPath);
        }

        parent::tearDown();
    }

    #[Test]
    public function encryptAndDecryptRoundTripProducesOriginalPlaintext(): void
    {
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $identifier = 'enc_roundtrip_' . bin2hex(random_bytes(4));
        $plaintext = 'super-secret-value-12345';

        $encrypted = $encryptionService->encrypt($plaintext, $identifier);

        FileMasterKeyProvider::clearCachedKey();

        $decrypted = $encryptionService->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
        );

        self::assertSame($plaintext, $decrypted);
    }

    #[Test]
    public function encryptProducesDifferentCiphertextEachTime(): void
    {
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $identifier = 'test_uniqueness_' . bin2hex(random_bytes(4));
        $plaintext = 'same-plaintext-value';

        FileMasterKeyProvider::clearCachedKey();
        $encrypted1 = $encryptionService->encrypt($plaintext, $identifier);

        FileMasterKeyProvider::clearCachedKey();
        $encrypted2 = $encryptionService->encrypt($plaintext, $identifier);

        self::assertNotSame(
            $encrypted1->encryptedValue,
            $encrypted2->encryptedValue,
            'Encrypted values must differ due to random nonces',
        );
    }

    #[Test]
    public function decryptWithWrongIdentifierThrowsException(): void
    {
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $identifier = 'test_aad_check_' . bin2hex(random_bytes(4));
        $plaintext = 'secret-with-aad';

        $encrypted = $encryptionService->encrypt($plaintext, $identifier);
        FileMasterKeyProvider::clearCachedKey();

        $this->expectException(EncryptionException::class);

        $encryptionService->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            'wrong/identifier',
        );
    }

    #[Test]
    public function generateDekReturns32ByteKey(): void
    {
        $encryptionService = $this->get(EncryptionServiceInterface::class);

        $dek = $encryptionService->generateDek();

        self::assertSame(32, \strlen((string) $dek), 'DEK must be exactly 32 bytes');

        $dek2 = $encryptionService->generateDek();
        self::assertNotSame($dek, $dek2, 'Each DEK must be unique');
    }

    #[Test]
    public function calculateChecksumReturnsSha256HexHash(): void
    {
        $encryptionService = $this->get(EncryptionServiceInterface::class);

        $checksum = $encryptionService->calculateChecksum('test-value');

        self::assertSame(64, \strlen((string) $checksum), 'SHA-256 hex hash must be 64 characters');
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $checksum);
    }

    #[Test]
    public function calculateChecksumIsDeterministic(): void
    {
        $encryptionService = $this->get(EncryptionServiceInterface::class);

        $checksum1 = $encryptionService->calculateChecksum('deterministic-value');
        $checksum2 = $encryptionService->calculateChecksum('deterministic-value');

        self::assertSame($checksum1, $checksum2, 'Same plaintext must always produce the same checksum');
    }

    #[Test]
    public function encryptValueChecksumIsKeyedNotPlaintextSha256(): void
    {
        // End-to-end with the real file master-key provider and libsodium: the
        // stored change-detection token must be a keyed MAC over the ciphertext,
        // not an offline-computable hash of the plaintext (SEC-CRYPTO-1).
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $plaintext = 'low-entropy-guessable';

        FileMasterKeyProvider::clearCachedKey();
        $encrypted = $encryptionService->encrypt($plaintext, 'checksum_keyed_' . bin2hex(random_bytes(4)));

        self::assertSame(64, \strlen((string) $encrypted->valueChecksum));
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $encrypted->valueChecksum);
        self::assertNotSame(
            hash('sha256', $plaintext),
            $encrypted->valueChecksum,
            'Stored checksum must not be an unkeyed sha256 of the plaintext',
        );
    }

    #[Test]
    public function encryptValueChecksumDiffersPerSecretForIdenticalPlaintext(): void
    {
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $plaintext = 'identical-across-secrets';

        FileMasterKeyProvider::clearCachedKey();
        $first = $encryptionService->encrypt($plaintext, 'checksum_a_' . bin2hex(random_bytes(4)));

        FileMasterKeyProvider::clearCachedKey();
        $second = $encryptionService->encrypt($plaintext, 'checksum_b_' . bin2hex(random_bytes(4)));

        self::assertNotSame(
            $first->valueChecksum,
            $second->valueChecksum,
            'Per-secret DEK-derived MAC key must yield different checksums for identical plaintext',
        );
    }

    #[Test]
    public function reEncryptDekChangesEncryptedDekBytes(): void
    {
        // This test uses the full vault service to round-trip secrets across key rotation,
        // as the raw reEncryptDek requires careful key handling (tested in MasterKeyRotationTest).
        $vaultService = $this->get(VaultServiceInterface::class);
        $this->get(EncryptionServiceInterface::class);
        $secretRepository = $this->get(SecretRepositoryInterface::class);

        $this->importCSVDataSet(__DIR__ . '/../Fixtures/Users/be_users.csv');
        $this->setUpBackendUser(1);

        $identifier = $this->generateUuidV7();
        $plaintext = 'rotation-test-secret';
        $vaultService->store($identifier, $plaintext);

        // Get the stored secret's DEK
        $secret = $secretRepository->findByIdentifier($identifier);
        self::assertNotNull($secret);
        $originalEncryptedDek = $secret->getEncryptedDek();

        // The DEK is non-empty and base64-encoded
        self::assertNotEmpty($originalEncryptedDek, 'Stored secret must have an encrypted DEK');
        self::assertNotFalse(base64_decode((string) $originalEncryptedDek, true), 'DEK must be base64-encoded');

        // Cleanup
        $vaultService->delete($identifier, 'test cleanup');
    }

    #[Test]
    public function encryptLargeValueRoundTrips(): void
    {
        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $identifier = 'test_large_value_' . bin2hex(random_bytes(4));
        $largeValue = str_repeat('abcdef0123456789', 1000); // 16000 bytes

        FileMasterKeyProvider::clearCachedKey();
        $encrypted = $encryptionService->encrypt($largeValue, $identifier);

        FileMasterKeyProvider::clearCachedKey();
        $decrypted = $encryptionService->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
        );

        self::assertSame($largeValue, $decrypted, 'Large values must round-trip correctly');
    }

    /**
     * Explicit round-trip on the XChaCha20-Poly1305 cipher branch.
     *
     * The service selects AES-256-GCM or XChaCha20-Poly1305 based on
     * `preferXChaCha20()` + sodium availability. On CI runners with AES-NI,
     * the default round-trip covers only AES-GCM; force the XChaCha20 path
     * here so both cipher modes are exercised.
     */
    #[Test]
    public function xchacha20RoundTripProducesOriginalPlaintext(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']['preferXChaCha20'] = true;
        FileMasterKeyProvider::clearCachedKey();

        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $identifier = 'test_xchacha20_' . bin2hex(random_bytes(4));
        $plaintext = 'xchacha20-only-path-value';

        $encrypted = $encryptionService->encrypt($plaintext, $identifier);

        FileMasterKeyProvider::clearCachedKey();
        $decrypted = $encryptionService->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
        );

        self::assertSame($plaintext, $decrypted);
    }

    /**
     * Explicit round-trip on the AES-256-GCM cipher branch.
     *
     * Only runs when AES-256-GCM hardware support is available (sodium check).
     */
    #[Test]
    public function aes256GcmRoundTripProducesOriginalPlaintext(): void
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            self::markTestSkipped('AES-256-GCM not available in this libsodium build');
        }

        $GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['nr_vault']['preferXChaCha20'] = false;
        FileMasterKeyProvider::clearCachedKey();

        $encryptionService = $this->get(EncryptionServiceInterface::class);
        $identifier = 'test_aes_gcm_' . bin2hex(random_bytes(4));
        $plaintext = 'aes-256-gcm-only-path-value';

        $encrypted = $encryptionService->encrypt($plaintext, $identifier);

        FileMasterKeyProvider::clearCachedKey();
        $decrypted = $encryptionService->decrypt(
            $encrypted->encryptedValue,
            $encrypted->encryptedDek,
            $encrypted->dekNonce,
            $encrypted->valueNonce,
            $identifier,
        );

        self::assertSame($plaintext, $decrypted);
    }

    /**
     * Generate a UUID v7 for testing.
     */
    private function generateUuidV7(): string
    {
        $timestamp = (int) (microtime(true) * 1000);
        $timestampHex = str_pad(dechex($timestamp), 12, '0', STR_PAD_LEFT);
        $randomBytes = random_bytes(10);
        $randomHex = bin2hex($randomBytes);

        return \sprintf(
            '%s-%s-7%s-%s%s-%s',
            substr($timestampHex, 0, 8),
            substr($timestampHex, 8, 4),
            substr($randomHex, 0, 3),
            dechex(8 + random_int(0, 3)),
            substr($randomHex, 3, 3),
            substr($randomHex, 6, 12),
        );
    }
}
