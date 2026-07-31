<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Anchor;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(ChainTipAnchor::class)]
final class ChainTipAnchorTest extends TestCase
{
    #[Test]
    public function toArrayExposesTheFourAnchorFields(): void
    {
        $anchor = new ChainTipAnchor(sequence: 42, chainTip: 'tip', timestamp: 1_750_000_000, hmacEpoch: 3);

        self::assertSame(
            ['sequence' => 42, 'chainTip' => 'tip', 'timestamp' => 1_750_000_000, 'hmacEpoch' => 3],
            $anchor->toArray(),
        );
    }

    #[Test]
    public function jsonSerializationMatchesTheArrayForm(): void
    {
        $anchor = new ChainTipAnchor(1, 'tip', 2, 3);

        self::assertSame($anchor->toArray(), $anchor->jsonSerialize());
    }

    /**
     * The published JSON is read back by the verifier, so the round trip has to
     * be lossless — a silent field rename would leave every anchor unusable.
     */
    #[Test]
    public function anchorSurvivesAJsonRoundTrip(): void
    {
        $original = new ChainTipAnchor(sequence: 987, chainTip: 'deadbeef', timestamp: 1_750_000_123, hmacEpoch: 2);

        $decoded = json_decode(json_encode($original, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        /** @var array<string, mixed> $decoded */
        $restored = ChainTipAnchor::fromArray($decoded);

        self::assertInstanceOf(ChainTipAnchor::class, $restored);
        self::assertSame($original->toArray(), $restored->toArray());
    }

    /**
     * Numeric strings arrive from JSON produced by other tooling. Accepting them
     * keeps a hand-written or replayed anchor usable.
     */
    #[Test]
    public function numericStringsAreCoercedToIntegers(): void
    {
        $anchor = ChainTipAnchor::fromArray([
            'sequence' => '42',
            'chainTip' => 'tip',
            'timestamp' => '1750000000',
            'hmacEpoch' => '3',
        ]);

        self::assertInstanceOf(ChainTipAnchor::class, $anchor);
        self::assertSame(42, $anchor->sequence);
        self::assertSame(1_750_000_000, $anchor->timestamp);
        self::assertSame(3, $anchor->hmacEpoch);
    }

    /**
     * An incomplete record must not become a comparison baseline: defaulting a
     * missing `chainTip` to '' could make a rebuilt chain compare as unchanged.
     *
     * @param array<string, mixed> $data
     */
    #[Test]
    #[DataProvider('incompletePayloadProvider')]
    public function structurallyIncompletePayloadYieldsNull(array $data): void
    {
        self::assertNull(ChainTipAnchor::fromArray($data));
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function incompletePayloadProvider(): iterable
    {
        $complete = ['sequence' => 1, 'chainTip' => 'tip', 'timestamp' => 2, 'hmacEpoch' => 3];

        yield 'empty' => [[]];

        foreach (array_keys($complete) as $missing) {
            $payload = $complete;
            unset($payload[$missing]);
            yield 'missing ' . $missing => [$payload];
        }

        yield 'non-string chainTip' => [['sequence' => 1, 'chainTip' => 5, 'timestamp' => 2, 'hmacEpoch' => 3]];
        yield 'non-numeric sequence' => [['sequence' => 'x', 'chainTip' => 'tip', 'timestamp' => 2, 'hmacEpoch' => 3]];
        yield 'null sequence' => [['sequence' => null, 'chainTip' => 'tip', 'timestamp' => 2, 'hmacEpoch' => 3]];
    }

    #[Test]
    #[DataProvider('emptyAnchorProvider')]
    public function anchorWithoutAUsableTipIsReportedEmpty(int $sequence, string $chainTip): void
    {
        self::assertTrue((new ChainTipAnchor($sequence, $chainTip, 1, 3))->isEmpty());
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function emptyAnchorProvider(): iterable
    {
        yield 'zero sequence' => [0, 'tip'];
        yield 'negative sequence' => [-1, 'tip'];
        yield 'blank tip' => [5, ''];
        yield 'both blank' => [0, ''];
    }

    #[Test]
    public function anchorWithSequenceAndTipIsNotEmpty(): void
    {
        self::assertFalse((new ChainTipAnchor(1, 'tip', 1, 3))->isEmpty());
    }
}
