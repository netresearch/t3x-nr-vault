<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit;

use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * The alert is the payload that leaves the installation — it is what a webhook
 * collector, a syslog daemon and the NDJSON anchor stream all receive. Its array
 * shape is therefore an external contract, and `tamperEvidence` is the field a
 * SIEM rule routes on.
 */
#[CoversClass(AuditIntegrityAlert::class)]
final class AuditIntegrityAlertTest extends TestCase
{
    #[Test]
    public function constructorKeepsEveryFieldVerbatim(): void
    {
        $alert = new AuditIntegrityAlert(
            AuditIntegrityReason::TableReset,
            'chain shrank from 9 to 2',
            1_750_000_000,
            ['anchoredSequence' => 9],
        );

        self::assertSame(AuditIntegrityReason::TableReset, $alert->reason);
        self::assertSame('chain shrank from 9 to 2', $alert->detail);
        self::assertSame(1_750_000_000, $alert->timestamp);
        self::assertSame(['anchoredSequence' => 9], $alert->context);
    }

    #[Test]
    public function contextDefaultsToEmpty(): void
    {
        $alert = new AuditIntegrityAlert(AuditIntegrityReason::SinkFailure, 'webhook refused', 1);

        self::assertSame([], $alert->context);
    }

    /**
     * `create()` is the constructor used everywhere in the verifier, and the
     * timestamp it stamps is the only record of WHEN a finding was raised.
     */
    #[Test]
    public function createStampsTheCurrentTime(): void
    {
        $before = time();
        $alert = AuditIntegrityAlert::create(AuditIntegrityReason::UidGap, '3 rows missing');
        $after = time();

        self::assertGreaterThanOrEqual($before, $alert->timestamp);
        self::assertLessThanOrEqual($after, $alert->timestamp);
    }

    #[Test]
    public function createPassesReasonDetailAndContextThrough(): void
    {
        $alert = AuditIntegrityAlert::create(
            AuditIntegrityReason::EpochDowngrade,
            'epoch 3 relabelled to 0',
            ['firstUid' => 12, 'affectedRows' => 4],
        );

        self::assertSame(AuditIntegrityReason::EpochDowngrade, $alert->reason);
        self::assertSame('epoch 3 relabelled to 0', $alert->detail);
        self::assertSame(['firstUid' => 12, 'affectedRows' => 4], $alert->context);
    }

    #[Test]
    public function createDefaultsToAnEmptyContext(): void
    {
        self::assertSame([], AuditIntegrityAlert::create(AuditIntegrityReason::BreakGlass, 'x')->context);
    }

    /**
     * The wire shape: exactly these five keys, with the reason flattened to its
     * backing string so a consumer needs no PHP enum to read it.
     */
    #[Test]
    public function toArrayEmitsTheExternalWireShape(): void
    {
        $alert = new AuditIntegrityAlert(
            AuditIntegrityReason::HashMismatch,
            'row 7 hashes differently',
            1_750_000_123,
            ['affectedRows' => 1],
        );

        $array = $alert->toArray();

        self::assertSame(
            ['reason', 'tamperEvidence', 'detail', 'timestamp', 'context'],
            array_keys($array),
        );
        self::assertSame('HASH_MISMATCH', $array['reason']);
        self::assertSame('row 7 hashes differently', $array['detail']);
        self::assertSame(1_750_000_123, $array['timestamp']);
        self::assertSame(['affectedRows' => 1], $array['context']);
    }

    /**
     * The flag is derived, not stored: a caller cannot hand a listener a
     * TABLE_RESET marked as harmless.
     */
    #[Test]
    public function tamperEvidenceIsDerivedFromTheReason(): void
    {
        self::assertTrue(
            AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'reset')->toArray()['tamperEvidence'],
        );
        self::assertFalse(
            AuditIntegrityAlert::create(AuditIntegrityReason::SinkFailure, 'refused')->toArray()['tamperEvidence'],
        );
    }

    #[Test]
    public function jsonSerializeMatchesToArray(): void
    {
        $alert = AuditIntegrityAlert::create(AuditIntegrityReason::NoExternalSink, 'none enabled', ['profile' => 'hardened']);

        self::assertSame($alert->toArray(), $alert->jsonSerialize());
    }

    #[Test]
    public function encodesToJsonWithoutLosingTheReasonCode(): void
    {
        $alert = AuditIntegrityAlert::create(AuditIntegrityReason::UidGap, '2 missing', ['missingUidSample' => '4,5']);

        $decoded = json_decode(json_encode($alert, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);
        self::assertSame('UID_GAP', $decoded['reason']);
        self::assertTrue($decoded['tamperEvidence']);
        self::assertSame(['missingUidSample' => '4,5'], $decoded['context']);
    }
}
