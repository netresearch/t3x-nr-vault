<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditIntegrityReport;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AuditIntegrityReport::class)]
final class AuditIntegrityReportTest extends TestCase
{
    #[Test]
    public function reportWithoutFindingsIsValid(): void
    {
        $report = new AuditIntegrityReport(findings: [], chainValid: true, currentSequence: 10);

        self::assertTrue($report->isValid());
        self::assertFalse($report->hasTamperEvidence());
        self::assertSame([], $report->getReasonCodes());
    }

    #[Test]
    public function anyFindingMakesTheReportInvalid(): void
    {
        $report = new AuditIntegrityReport(
            findings: [AuditIntegrityAlert::create(AuditIntegrityReason::NoExternalSink, 'none enabled')],
            chainValid: true,
            currentSequence: 10,
        );

        self::assertFalse($report->isValid());
    }

    /**
     * The distinction alerting rules act on: a configuration gap is not an
     * incident, a hash mismatch is.
     */
    #[Test]
    #[DataProvider('tamperEvidenceProvider')]
    public function tamperEvidenceIsReportedPerReasonCode(AuditIntegrityReason $reason, bool $expected): void
    {
        $report = new AuditIntegrityReport(
            findings: [AuditIntegrityAlert::create($reason, 'detail')],
            chainValid: false,
            currentSequence: 1,
        );

        self::assertSame($expected, $report->hasTamperEvidence());
    }

    /**
     * @return iterable<string, array{AuditIntegrityReason, bool}>
     */
    public static function tamperEvidenceProvider(): iterable
    {
        yield 'hash mismatch' => [AuditIntegrityReason::HashMismatch, true];
        yield 'uid gap' => [AuditIntegrityReason::UidGap, true];
        yield 'table reset' => [AuditIntegrityReason::TableReset, true];
        yield 'epoch downgrade' => [AuditIntegrityReason::EpochDowngrade, true];
        yield 'sink failure' => [AuditIntegrityReason::SinkFailure, false];
        yield 'no external sink' => [AuditIntegrityReason::NoExternalSink, false];
        yield 'break glass' => [AuditIntegrityReason::BreakGlass, false];
    }

    #[Test]
    public function tamperEvidenceIsDetectedAmongNonTamperFindings(): void
    {
        $report = new AuditIntegrityReport(
            findings: [
                AuditIntegrityAlert::create(AuditIntegrityReason::SinkFailure, 'webhook down'),
                AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'chain shrank'),
            ],
            chainValid: true,
            currentSequence: 1,
        );

        self::assertTrue($report->hasTamperEvidence());
    }

    #[Test]
    public function hasReasonMatchesOnlyThePresentCodes(): void
    {
        $report = new AuditIntegrityReport(
            findings: [AuditIntegrityAlert::create(AuditIntegrityReason::UidGap, '3 missing')],
            chainValid: false,
            currentSequence: 1,
        );

        self::assertTrue($report->hasReason(AuditIntegrityReason::UidGap));
        self::assertFalse($report->hasReason(AuditIntegrityReason::TableReset));
    }

    /**
     * Codes drive monitoring rules, so duplicates must collapse and order must be
     * stable rather than depending on how many rows happened to fail.
     */
    #[Test]
    public function reasonCodesAreDeduplicatedInFirstSeenOrder(): void
    {
        $report = new AuditIntegrityReport(
            findings: [
                AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'a'),
                AuditIntegrityAlert::create(AuditIntegrityReason::UidGap, 'b'),
                AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'c'),
            ],
            chainValid: false,
            currentSequence: 1,
        );

        self::assertSame(['TABLE_RESET', 'UID_GAP'], $report->getReasonCodes());
    }

    #[Test]
    public function arrayFormCarriesTheAnchorWhenOneWasCompared(): void
    {
        $anchor = new ChainTipAnchor(sequence: 50, chainTip: 'tip', timestamp: 1_750_000_000, hmacEpoch: 3);
        $report = new AuditIntegrityReport(
            findings: [],
            chainValid: true,
            currentSequence: 60,
            anchor: $anchor,
        );

        $array = $report->toArray();

        self::assertSame($anchor->toArray(), $array['anchor']);
        self::assertSame(60, $array['currentSequence']);
        self::assertTrue($array['valid']);
        self::assertFalse($array['tamperEvidence']);
    }

    #[Test]
    public function arrayFormReportsANullAnchorWhenNoneWasAvailable(): void
    {
        $report = new AuditIntegrityReport(findings: [], chainValid: true, currentSequence: 1);

        self::assertNull($report->toArray()['anchor']);
    }

    /**
     * A valid chain and a fully migrated chain are different statements. The
     * report carries the per-epoch distribution the walk counted for free, so a
     * monitor reading the JSON can tell a stalled `vault:audit-migrate-hmac` run
     * from a healthy installation — neither raises a finding.
     */
    #[Test]
    public function arrayFormCarriesTheEpochDistributionAndItsBounds(): void
    {
        $report = new AuditIntegrityReport(
            findings: [],
            chainValid: true,
            currentSequence: 945,
            epochCounts: [1 => 45, 3 => 900],
        );

        $array = $report->toArray();

        self::assertTrue($array['valid']);
        self::assertSame([1 => 45, 3 => 900], $array['epochCounts']);
        self::assertSame(1, $array['minEpoch']);
        self::assertSame(3, $array['maxEpoch']);
    }

    /**
     * Null, not 0 — epoch 0 is a real state ("keyless") and must not be how an
     * empty chain reports itself.
     */
    #[Test]
    public function anEmptyChainReportsNoEpochBounds(): void
    {
        $report = new AuditIntegrityReport(findings: [], chainValid: true, currentSequence: 0);

        self::assertSame([], $report->epochCounts);
        self::assertNull($report->getMinEpoch());
        self::assertNull($report->getMaxEpoch());
    }

    /**
     * The JSON output is a machine interface for monitoring, so it must stay
     * serialisable and carry every finding.
     */
    #[Test]
    public function arrayFormIsJsonSerialisableAndListsEveryFinding(): void
    {
        $report = new AuditIntegrityReport(
            findings: [
                AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'reset', ['anchoredSequence' => 9]),
                AuditIntegrityAlert::create(AuditIntegrityReason::UidGap, 'gap', ['missingUidCount' => 2]),
            ],
            chainValid: false,
            currentSequence: 3,
            warnings: [7 => 'HMAC key epoch boundary: 2 -> 3'],
        );

        $decoded = json_decode(json_encode($report->toArray(), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);
        self::assertIsArray($decoded['findings']);
        self::assertCount(2, $decoded['findings']);
        self::assertSame('TABLE_RESET', $decoded['findings'][0]['reason']);
        self::assertSame(9, $decoded['findings'][0]['context']['anchoredSequence']);
        self::assertSame(['TABLE_RESET', 'UID_GAP'], $decoded['reasonCodes']);
        self::assertSame('HMAC key epoch boundary: 2 -> 3', $decoded['warnings']['7']);
    }

    /**
     * `chainValid` reports the internal hash pass alone, so a chain that verifies
     * against itself but fails the external anchor check must still say so.
     */
    #[Test]
    public function chainValidRemainsIndependentOfAnchorFindings(): void
    {
        $report = new AuditIntegrityReport(
            findings: [AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'reset')],
            chainValid: true,
            currentSequence: 1,
        );

        self::assertTrue($report->chainValid);
        self::assertFalse($report->isValid());
    }
}
