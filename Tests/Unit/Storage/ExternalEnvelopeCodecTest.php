<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage;

use LogicException;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Storage\ExternalEnvelopeCodec;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(ExternalEnvelopeCodec::class)]
final class ExternalEnvelopeCodecTest extends TestCase
{
    private const BINARY = "cipher\x00\xff\x10text";

    #[Test]
    public function encodesTheEnvelopeLosslesslyWithTheMarkers(): void
    {
        $payload = ExternalEnvelopeCodec::encode($this->secret(), 'marker-1');

        self::assertSame(1, $payload['format']);
        self::assertSame('marker-1', $payload['installation']);
        self::assertSame('api_key', $payload['identifier']);
        self::assertSame(base64_encode(self::BINARY), $payload['encrypted_value']);
        self::assertSame(base64_encode('wrapped-dek'), $payload['encrypted_dek']);
        self::assertSame(base64_encode('dek-nonce'), $payload['dek_nonce']);
        self::assertSame(base64_encode('value-nonce'), $payload['value_nonce']);
        self::assertSame(hash('sha256', self::BINARY), $payload['value_checksum']);
        self::assertSame(2, $payload['encryption_version']);
        self::assertSame('xchacha20poly1305', $payload['encryption_algorithm']);
    }

    #[Test]
    public function decodesWhatItEncodedIntoTheRow(): void
    {
        $secret = $this->secret();
        $row    = new Secret(identifier: 'api_key', uid: 7);

        $decoded = ExternalEnvelopeCodec::decode($row, ExternalEnvelopeCodec::encode($secret, 'm'), $this->unusable(...));

        self::assertSame(7, $decoded->getUid());
        self::assertSame(self::BINARY, $decoded->getEncryptedValue());
        self::assertSame('wrapped-dek', $decoded->getEncryptedDek());
        self::assertSame('dek-nonce', $decoded->getDekNonce());
        self::assertSame('value-nonce', $decoded->getValueNonce());
        self::assertSame(hash('sha256', self::BINARY), $decoded->getValueChecksum());
        self::assertSame(2, $decoded->getEncryptionVersion());
        self::assertSame('xchacha20poly1305', $decoded->getEncryptionAlgorithm());
    }

    #[Test]
    public function theEnvelopeListFollowsTheModelOrder(): void
    {
        self::assertSame(
            [self::BINARY, 'wrapped-dek', 'dek-nonce', 'value-nonce', hash('sha256', self::BINARY), 2, 'xchacha20poly1305'],
            ExternalEnvelopeCodec::envelopeOf($this->secret()),
        );
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function unusablePayloads(): iterable
    {
        yield 'another identifier' => [['identifier' => 'other_key']];
        yield 'another format' => [['format' => 2]];
        yield 'no format' => [['format' => null]];
        yield 'value not base64' => [['encrypted_value' => '***']];
        yield 'dek not a string' => [['encrypted_dek' => 5]];
        yield 'nonce missing' => [['dek_nonce' => null]];
        yield 'checksum not a string' => [['value_checksum' => 5]];
        yield 'algorithm not a string' => [['encryption_algorithm' => null]];
        yield 'version not an int' => [['encryption_version' => '2']];
        yield 'unknown algorithm' => [['encryption_algorithm' => 'made-up-algorithm']];
    }

    /**
     * @param array<string, mixed> $override
     */
    #[Test]
    #[DataProvider('unusablePayloads')]
    public function refusesAPayloadThatIsNotAnEnvelopeOfThisRow(array $override): void
    {
        $payload = array_replace(ExternalEnvelopeCodec::encode($this->secret(), 'm'), $override);

        try {
            ExternalEnvelopeCodec::decode(new Secret(identifier: 'api_key', uid: 7), $payload, $this->unusable(...));
            self::fail('The payload must be refused.');
        } catch (LogicException $e) {
            self::assertSame('unusable:api_key', $e->getMessage(), 'the exception factory of the adapter builds the error');
        }
    }

    private function unusable(string $identifier): LogicException
    {
        return new LogicException('unusable:' . $identifier);
    }

    private function secret(): Secret
    {
        return new Secret(
            identifier: 'api_key',
            encryptedValue: self::BINARY,
            encryptedDek: 'wrapped-dek',
            dekNonce: 'dek-nonce',
            valueNonce: 'value-nonce',
            encryptionVersion: 2,
            encryptionAlgorithm: 'xchacha20poly1305',
            valueChecksum: hash('sha256', self::BINARY),
        );
    }
}
