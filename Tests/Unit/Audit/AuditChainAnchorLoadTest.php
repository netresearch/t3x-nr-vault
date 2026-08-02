<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Netresearch\NrVault\Audit\AuditChainAnchor;
use Netresearch\NrVault\Audit\AuditChainAnchorLoad;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

/**
 * The double-read stability rule in `AuditLogService::verifyAnchor()` compares
 * two loads by their `$raw` bytes, not by their parsed anchors: only the raw
 * form distinguishes "nothing happened" from "re-sealed to the same tip". That
 * makes byte-exact pass-through of `$raw` — including the empty-string default
 * for statuses that carry no anchor — the load's actual contract.
 */
#[CoversClass(AuditChainAnchorLoad::class)]
final class AuditChainAnchorLoadTest extends TestCase
{
    #[Test]
    public function carriesStatusAnchorAndRawBytes(): void
    {
        $anchor = new AuditChainAnchor(9, str_repeat('a', 64), 1_750_000_000);
        $raw = '{"uid":9,"entryHash":"' . str_repeat('a', 64) . '","tstamp":1750000000}';

        $load = new AuditChainAnchorLoad(AuditChainAnchorStatus::Ok, $anchor, $raw);

        self::assertSame(AuditChainAnchorStatus::Ok, $load->status);
        self::assertSame($anchor, $load->anchor);
        self::assertSame($raw, $load->raw);
    }

    /**
     * The statuses that mean "there is nothing to compare against" must be
     * constructible from the status alone.
     */
    #[Test]
    public function anchorAndRawAreOptionalSoAStatusOnlyLoadIsValid(): void
    {
        $load = new AuditChainAnchorLoad(AuditChainAnchorStatus::Unanchored);

        self::assertSame(AuditChainAnchorStatus::Unanchored, $load->status);
        self::assertNull($load->anchor);
        self::assertSame('', $load->raw);
    }

    /**
     * `Unreadable` is the case where the bytes exist but do not parse or do not
     * verify — the load must still surface them, or the diagnostics have nothing
     * to report.
     */
    #[Test]
    public function keepsRawBytesEvenWhenNoAnchorCouldBeParsed(): void
    {
        $load = new AuditChainAnchorLoad(AuditChainAnchorStatus::Unreadable, null, 'not-json{');

        self::assertNull($load->anchor);
        self::assertSame('not-json{', $load->raw);
    }

    /**
     * Byte-wise pass-through: no trimming, no normalisation. Two re-seals that
     * differ only in whitespace or key order must remain distinguishable.
     */
    #[Test]
    public function rawIsStoredByteForByte(): void
    {
        $raw = "  {\"uid\": 9,\n \"entryHash\": \"ff\"}\t";

        self::assertSame($raw, (new AuditChainAnchorLoad(AuditChainAnchorStatus::Ok, null, $raw))->raw);
    }

    /**
     * Two loads of the same anchor value with different stored bytes stay
     * distinguishable — that is precisely what the double-read rule relies on.
     */
    #[Test]
    public function equalAnchorValuesWithDifferentBytesRemainDistinguishable(): void
    {
        $first = new AuditChainAnchorLoad(
            AuditChainAnchorStatus::Ok,
            new AuditChainAnchor(9, 'ff', 1_750_000_000),
            '{"uid":9,"entryHash":"ff","tstamp":1750000000}',
        );
        $second = new AuditChainAnchorLoad(
            AuditChainAnchorStatus::Ok,
            new AuditChainAnchor(9, 'ff', 1_750_000_000),
            '{"entryHash":"ff","tstamp":1750000000,"uid":9}',
        );

        self::assertEquals($first->anchor, $second->anchor);
        self::assertNotSame($first->raw, $second->raw);
    }

    #[Test]
    #[DataProvider('everyStatusProvider')]
    public function acceptsEveryAnchorStatus(AuditChainAnchorStatus $status): void
    {
        self::assertSame($status, (new AuditChainAnchorLoad($status))->status);
    }

    /**
     * Immutability keeps a load usable as the "before" side of the double read:
     * the second read cannot overwrite the first one's bytes, so the comparison
     * still describes two distinct observations.
     */
    #[Test]
    public function everyFieldIsReadonlyAndTheClassIsFinal(): void
    {
        $reflection = new ReflectionClass(AuditChainAnchorLoad::class);

        self::assertTrue($reflection->isReadOnly(), 'AuditChainAnchorLoad must stay a readonly class');
        self::assertTrue($reflection->isFinal(), 'AuditChainAnchorLoad must not be subclassable');

        foreach (['status', 'anchor', 'raw'] as $property) {
            self::assertTrue(
                $reflection->getProperty($property)->isReadOnly(),
                \sprintf('%s must be readonly', $property),
            );
        }
    }

    /**
     * @return iterable<string, array{AuditChainAnchorStatus}>
     */
    public static function everyStatusProvider(): iterable
    {
        foreach (AuditChainAnchorStatus::cases() as $status) {
            yield $status->value => [$status];
        }
    }
}
