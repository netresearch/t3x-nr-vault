<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook\Dto;

use Netresearch\NrVault\Hook\Dto\PendingSecret;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(PendingSecret::class)]
final class PendingSecretTest extends TestCase
{
    #[Test]
    public function constructorSetsAllProperties(): void
    {
        $subject = new PendingSecret(
            value: 'mysecretvalue',
            identifier: 'app/api-key',
            originalChecksum: 'abc123',
            isNew: false,
        );

        self::assertSame('mysecretvalue', $subject->value);
        self::assertSame('app/api-key', $subject->identifier);
        self::assertSame('abc123', $subject->originalChecksum);
        self::assertFalse($subject->isNew);
    }

    #[Test]
    public function constructorWithIsNewTrue(): void
    {
        $subject = new PendingSecret('val', 'id', '', true);

        self::assertTrue($subject->isNew);
    }

    #[Test]
    public function createNewSetsIsNewTrueAndEmptyChecksum(): void
    {
        $subject = PendingSecret::createNew('secretval', 'service/token');

        self::assertSame('secretval', $subject->value);
        self::assertSame('service/token', $subject->identifier);
        self::assertSame('', $subject->originalChecksum);
        self::assertTrue($subject->isNew);
    }

    #[Test]
    public function createUpdateSetsIsNewFalseAndChecksum(): void
    {
        $subject = PendingSecret::createUpdate('newvalue', 'app/key', 'originalchecksum');

        self::assertSame('newvalue', $subject->value);
        self::assertSame('app/key', $subject->identifier);
        self::assertSame('originalchecksum', $subject->originalChecksum);
        self::assertFalse($subject->isNew);
    }

    #[Test]
    #[DataProvider('hasChangedProvider')]
    public function hasChangedReturnsCorrectResult(
        string $originalChecksum,
        string $currentChecksum,
        bool $expected,
    ): void {
        $subject = new PendingSecret('val', 'id', $originalChecksum, false);

        self::assertSame($expected, $subject->hasChanged($currentChecksum));
    }

    public static function hasChangedProvider(): iterable
    {
        yield 'different checksums => changed' => ['original', 'different', true];
        yield 'same checksums => not changed' => ['same', 'same', false];
        yield 'empty original, non-empty current => changed' => ['', 'newchecksum', true];
        yield 'both empty => not changed' => ['', '', false];
    }

    #[Test]
    public function hasChangedReturnsFalseWhenChecksumMatches(): void
    {
        $checksum = 'sha256:abc123def456';
        $subject = PendingSecret::createUpdate('val', 'id', $checksum);

        self::assertFalse($subject->hasChanged($checksum));
    }

    #[Test]
    public function hasChangedReturnsTrueWhenChecksumDiffers(): void
    {
        $subject = PendingSecret::createUpdate('val', 'id', 'originalchecksum');

        self::assertTrue($subject->hasChanged('newchecksum'));
    }

    #[Test]
    public function createNewAlwaysHasChangedForNonEmptyCurrentChecksum(): void
    {
        // createNew sets originalChecksum to '', so any non-empty checksum means changed
        $subject = PendingSecret::createNew('val', 'id');

        self::assertTrue($subject->hasChanged('anychecksum'));
    }

    #[Test]
    public function toArrayReturnsCorrectStructure(): void
    {
        $subject = new PendingSecret(
            value: 'secretvalue',
            identifier: 'my/identifier',
            originalChecksum: 'oldchecksum',
            isNew: false,
        );

        // toArray() redacts the secret value: the plaintext must never leak
        // into a logged/serialised array (SEC / VO-DTO hardening).
        self::assertSame([
            'value' => '[REDACTED]',
            'identifier' => 'my/identifier',
            'originalChecksum' => 'oldchecksum',
            'isNew' => false,
        ], $subject->toArray());
    }

    #[Test]
    public function toArrayForNewSecretHasEmptyChecksumAndIsNewTrue(): void
    {
        $subject = PendingSecret::createNew('val', 'id');

        $array = $subject->toArray();

        self::assertSame('', $array['originalChecksum']);
        self::assertTrue($array['isNew']);
    }

    #[Test]
    public function toArrayForUpdatedSecretHasIsNewFalse(): void
    {
        $subject = PendingSecret::createUpdate('val', 'id', 'chk');

        self::assertFalse($subject->toArray()['isNew']);
    }

    #[Test]
    public function toArrayContainsExactlyFourKeys(): void
    {
        $subject = PendingSecret::createNew('val', 'id');

        self::assertCount(4, $subject->toArray());
    }
}
