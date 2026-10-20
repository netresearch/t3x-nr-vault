<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto;

use Netresearch\NrVault\Crypto\ReEncryptedDek;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(ReEncryptedDek::class)]
final class ReEncryptedDekTest extends TestCase
{
    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $subject = new ReEncryptedDek(
            encryptedDek: 'base64dek==',
            nonce: 'base64nonce==',
        );

        self::assertSame('base64dek==', $subject->encryptedDek);
        self::assertSame('base64nonce==', $subject->nonce);
    }

    #[Test]
    public function fromRawBase64EncodesEncryptedDek(): void
    {
        $rawDek = 'raw-encrypted-dek-bytes';

        $subject = ReEncryptedDek::fromRaw(
            encryptedDek: $rawDek,
            nonce: 'rawnonce',
        );

        self::assertSame(base64_encode($rawDek), $subject->encryptedDek);
    }

    #[Test]
    public function fromRawBase64EncodesNonce(): void
    {
        $rawNonce = 'raw-nonce-bytes';

        $subject = ReEncryptedDek::fromRaw(
            encryptedDek: 'rawdek',
            nonce: $rawNonce,
        );

        self::assertSame(base64_encode($rawNonce), $subject->nonce);
    }

    #[Test]
    public function fromRawWithBinaryDataProducesValidBase64(): void
    {
        $binaryDek   = random_bytes(48);
        $binaryNonce = random_bytes(24);

        $subject = ReEncryptedDek::fromRaw($binaryDek, $binaryNonce);

        self::assertSame($binaryDek, base64_decode($subject->encryptedDek, true));
        self::assertSame($binaryNonce, base64_decode($subject->nonce, true));
    }

    #[Test]
    public function toArrayReturnsCorrectStructure(): void
    {
        $subject = new ReEncryptedDek(
            encryptedDek: 'enc_dek_val',
            nonce: 'nonce_val',
        );

        self::assertSame([
            'encrypted_dek' => 'enc_dek_val',
            'nonce'         => 'nonce_val',
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayContainsExactlyTwoKeys(): void
    {
        $subject = new ReEncryptedDek('a', 'b');

        self::assertCount(2, $subject->toArray());
    }

    #[Test]
    public function fromRawRoundTripPreservesAllValues(): void
    {
        $rawDek   = 'my-encrypted-dek';
        $rawNonce = 'my-nonce';

        $subject = ReEncryptedDek::fromRaw($rawDek, $rawNonce);
        $array   = $subject->toArray();

        self::assertSame(base64_encode($rawDek), $array['encrypted_dek']);
        self::assertSame(base64_encode($rawNonce), $array['nonce']);
    }

    #[Test]
    public function constructorRoundTripToArray(): void
    {
        $subject = new ReEncryptedDek('dek123', 'nonce456');
        $array   = $subject->toArray();

        self::assertSame('dek123', $array['encrypted_dek']);
        self::assertSame('nonce456', $array['nonce']);
    }
}
