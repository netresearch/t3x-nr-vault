<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Crypto\EncryptedData;
use Netresearch\NrVault\Crypto\EncryptionAlgorithm;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(EncryptedData::class)]
final class EncryptedDataTest extends TestCase
{
    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $subject = new EncryptedData(
            encryptedValue: 'base64value==',
            encryptedDek: 'base64dek==',
            dekNonce: 'base64deknonce==',
            valueNonce: 'base64valuenonce==',
            valueChecksum: 'abc123checksum',
        );

        self::assertSame('base64value==', $subject->encryptedValue);
        self::assertSame('base64dek==', $subject->encryptedDek);
        self::assertSame('base64deknonce==', $subject->dekNonce);
        self::assertSame('base64valuenonce==', $subject->valueNonce);
        self::assertSame('abc123checksum', $subject->valueChecksum);
        // Marker defaults describe what encrypt() currently produces.
        self::assertSame(EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT, $subject->encryptionVersion);
        self::assertSame(EncryptionAlgorithm::XChaCha20Poly1305, $subject->encryptionAlgorithm);
    }

    #[Test]
    public function constructorAcceptsExplicitMarker(): void
    {
        $subject = new EncryptedData(
            encryptedValue: 'v',
            encryptedDek: 'd',
            dekNonce: 'dn',
            valueNonce: 'vn',
            valueChecksum: 'cs',
            encryptionVersion: EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT,
            encryptionAlgorithm: EncryptionAlgorithm::Aes256Gcm,
        );

        self::assertSame(EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT, $subject->encryptionVersion);
        self::assertSame(EncryptionAlgorithm::Aes256Gcm, $subject->encryptionAlgorithm);
    }

    #[Test]
    public function fromRawBase64EncodesEncryptedValue(): void
    {
        $rawValue = 'raw-ciphertext-bytes';

        $subject = EncryptedData::fromRaw(
            encryptedValue: $rawValue,
            encryptedDek: 'rawdek',
            dekNonce: 'rawnonce1',
            valueNonce: 'rawnonce2',
            valueChecksum: 'hexchecksum',
        );

        self::assertSame(base64_encode($rawValue), $subject->encryptedValue);
    }

    #[Test]
    public function fromRawBase64EncodesEncryptedDek(): void
    {
        $rawDek = 'raw-dek-bytes';

        $subject = EncryptedData::fromRaw(
            encryptedValue: 'rawvalue',
            encryptedDek: $rawDek,
            dekNonce: 'rawnonce1',
            valueNonce: 'rawnonce2',
            valueChecksum: 'hexchecksum',
        );

        self::assertSame(base64_encode($rawDek), $subject->encryptedDek);
    }

    #[Test]
    public function fromRawBase64EncodesDekNonce(): void
    {
        $rawDekNonce = 'raw-dek-nonce';

        $subject = EncryptedData::fromRaw(
            encryptedValue: 'rawvalue',
            encryptedDek: 'rawdek',
            dekNonce: $rawDekNonce,
            valueNonce: 'rawnonce2',
            valueChecksum: 'hexchecksum',
        );

        self::assertSame(base64_encode($rawDekNonce), $subject->dekNonce);
    }

    #[Test]
    public function fromRawBase64EncodesValueNonce(): void
    {
        $rawValueNonce = 'raw-value-nonce';

        $subject = EncryptedData::fromRaw(
            encryptedValue: 'rawvalue',
            encryptedDek: 'rawdek',
            dekNonce: 'rawnonce1',
            valueNonce: $rawValueNonce,
            valueChecksum: 'hexchecksum',
        );

        self::assertSame(base64_encode($rawValueNonce), $subject->valueNonce);
    }

    #[Test]
    public function fromRawPassesThroughChecksumUnchanged(): void
    {
        $checksum = 'sha256hexstring0123456789abcdef';

        $subject = EncryptedData::fromRaw(
            encryptedValue: 'rawvalue',
            encryptedDek: 'rawdek',
            dekNonce: 'rawnonce1',
            valueNonce: 'rawnonce2',
            valueChecksum: $checksum,
        );

        self::assertSame($checksum, $subject->valueChecksum);
    }

    #[Test]
    public function fromRawWithBinaryDataProducesValidBase64(): void
    {
        $binaryData = random_bytes(32);

        $subject = EncryptedData::fromRaw(
            encryptedValue: $binaryData,
            encryptedDek: $binaryData,
            dekNonce: $binaryData,
            valueNonce: $binaryData,
            valueChecksum: bin2hex($binaryData),
        );

        // Verify all values are valid base64 by decoding them
        self::assertSame($binaryData, base64_decode($subject->encryptedValue, true));
        self::assertSame($binaryData, base64_decode($subject->encryptedDek, true));
        self::assertSame($binaryData, base64_decode($subject->dekNonce, true));
        self::assertSame($binaryData, base64_decode($subject->valueNonce, true));
    }

    #[Test]
    public function toArrayReturnsCorrectStructure(): void
    {
        $subject = new EncryptedData(
            encryptedValue: 'enc_val',
            encryptedDek: 'enc_dek',
            dekNonce: 'dn',
            valueNonce: 'vn',
            valueChecksum: 'chk',
        );

        self::assertSame([
            'encrypted_value' => 'enc_val',
            'encrypted_dek' => 'enc_dek',
            'dek_nonce' => 'dn',
            'value_nonce' => 'vn',
            'value_checksum' => 'chk',
            'encryption_version' => EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT,
            'encryption_algorithm' => 'xchacha20poly1305',
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayContainsExactlySevenKeys(): void
    {
        $subject = new EncryptedData('a', 'b', 'c', 'd', 'e');

        self::assertCount(7, $subject->toArray());
    }

    #[Test]
    public function fromRawRoundTripPreservesAllValues(): void
    {
        $rawValue = 'ciphertext';
        $rawDek = 'encrypted-dek';
        $rawDekNonce = 'dek-nonce';
        $rawValueNonce = 'value-nonce';
        $checksum = 'hexchecksum';

        $subject = EncryptedData::fromRaw($rawValue, $rawDek, $rawDekNonce, $rawValueNonce, $checksum);
        $array = $subject->toArray();

        self::assertSame(base64_encode($rawValue), $array['encrypted_value']);
        self::assertSame(base64_encode($rawDek), $array['encrypted_dek']);
        self::assertSame(base64_encode($rawDekNonce), $array['dek_nonce']);
        self::assertSame(base64_encode($rawValueNonce), $array['value_nonce']);
        self::assertSame($checksum, $array['value_checksum']);
    }

    #[Test]
    public function fromRawPassesMarkerThroughUnencoded(): void
    {
        $subject = EncryptedData::fromRaw(
            encryptedValue: 'raw',
            encryptedDek: 'raw',
            dekNonce: 'raw',
            valueNonce: 'raw',
            valueChecksum: 'cs',
            encryptionVersion: EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT,
            encryptionAlgorithm: EncryptionAlgorithm::Aes256Gcm,
        );

        self::assertSame(EncryptionServiceInterface::ENCRYPTION_VERSION_CURRENT, $subject->encryptionVersion);
        self::assertSame(EncryptionAlgorithm::Aes256Gcm, $subject->encryptionAlgorithm);
        self::assertSame('aes256gcm', $subject->toArray()['encryption_algorithm']);
    }
}
