<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * The backing strings are an external contract (webhook payloads, syslog
 * structured data, the NDJSON anchor stream) and `isTamperEvidence()` is what a
 * listener switches on to decide between paging someone and writing a log line.
 * Both are pinned here rather than left to be inferred from the enum body.
 */
#[CoversClass(AuditIntegrityReason::class)]
final class AuditIntegrityReasonTest extends TestCase
{
    #[Test]
    #[DataProvider('tamperEvidenceProvider')]
    public function tamperEvidenceClassificationIsExplicitPerCase(
        AuditIntegrityReason $reason,
        bool $expected,
    ): void {
        self::assertSame($expected, $reason->isTamperEvidence());
    }

    /**
     * @return iterable<string, array{AuditIntegrityReason, bool}>
     */
    public static function tamperEvidenceProvider(): iterable
    {
        yield 'hash mismatch is tamper evidence' => [AuditIntegrityReason::HashMismatch, true];
        yield 'uid gap is tamper evidence' => [AuditIntegrityReason::UidGap, true];
        yield 'table reset is tamper evidence' => [AuditIntegrityReason::TableReset, true];
        yield 'epoch downgrade is tamper evidence' => [AuditIntegrityReason::EpochDowngrade, true];
        yield 'sink failure is availability only' => [AuditIntegrityReason::SinkFailure, false];
        yield 'missing external sink is configuration only' => [AuditIntegrityReason::NoExternalSink, false];
        yield 'break glass is its own severity class' => [AuditIntegrityReason::BreakGlass, false];
    }

    /**
     * A new case added without a `match` arm would raise `UnhandledMatchError`
     * at runtime — inside the verifier, i.e. exactly where an integrity check
     * must not blow up. Cover every declared case so that failure is a test
     * failure instead.
     */
    #[Test]
    public function everyDeclaredCaseIsClassified(): void
    {
        $classified = array_map(
            static fn (array $case): AuditIntegrityReason => $case[0],
            iterator_to_array(self::tamperEvidenceProvider()),
        );

        self::assertEqualsCanonicalizing(AuditIntegrityReason::cases(), array_values($classified));
    }

    /**
     * These strings travel to external systems and are matched on by SIEM rules,
     * so they are API, not labels.
     */
    #[Test]
    #[DataProvider('backingValueProvider')]
    public function backingValuesAreStable(AuditIntegrityReason $reason, string $expected): void
    {
        self::assertSame($expected, $reason->value);
    }

    /**
     * @return iterable<string, array{AuditIntegrityReason, string}>
     */
    public static function backingValueProvider(): iterable
    {
        yield 'HASH_MISMATCH' => [AuditIntegrityReason::HashMismatch, 'HASH_MISMATCH'];
        yield 'UID_GAP' => [AuditIntegrityReason::UidGap, 'UID_GAP'];
        yield 'TABLE_RESET' => [AuditIntegrityReason::TableReset, 'TABLE_RESET'];
        yield 'EPOCH_DOWNGRADE' => [AuditIntegrityReason::EpochDowngrade, 'EPOCH_DOWNGRADE'];
        yield 'SINK_FAILURE' => [AuditIntegrityReason::SinkFailure, 'SINK_FAILURE'];
        yield 'NO_EXTERNAL_SINK' => [AuditIntegrityReason::NoExternalSink, 'NO_EXTERNAL_SINK'];
        yield 'BREAK_GLASS' => [AuditIntegrityReason::BreakGlass, 'BREAK_GLASS'];
    }

    #[Test]
    #[DataProvider('labelProvider')]
    public function labelHumanisesTheBackingValue(AuditIntegrityReason $reason, string $expected): void
    {
        self::assertSame($expected, $reason->label());
    }

    /**
     * @return iterable<string, array{AuditIntegrityReason, string}>
     */
    public static function labelProvider(): iterable
    {
        yield 'single underscore' => [AuditIntegrityReason::HashMismatch, 'Hash Mismatch'];
        yield 'short word' => [AuditIntegrityReason::UidGap, 'Uid Gap'];
        yield 'two underscores' => [AuditIntegrityReason::NoExternalSink, 'No External Sink'];
    }

    #[Test]
    public function labelNeverLeaksTheUnderscoredWireFormat(): void
    {
        foreach (AuditIntegrityReason::cases() as $reason) {
            self::assertStringNotContainsString('_', $reason->label());
        }
    }

    #[Test]
    public function unknownCodeIsNotAReason(): void
    {
        self::assertNull(AuditIntegrityReason::tryFrom('CHAIN_ON_FIRE'));
    }
}
