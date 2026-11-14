<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Acknowledgement;

use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingItem;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingOverlay;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AuditFindingItem::class)]
#[CoversClass(AuditFindingOverlay::class)]
final class AuditFindingItemTest extends TestCase
{
    #[Test]
    public function theFingerprintIgnoresTheOrderOfTheItemsButNotTheirSet(): void
    {
        $a = $this->item('a');
        $b = $this->item('b');

        self::assertSame(AuditFindingItem::fingerprint([$a, $b]), AuditFindingItem::fingerprint([$b, $a]));
        self::assertNotSame(AuditFindingItem::fingerprint([$a, $b]), AuditFindingItem::fingerprint([$a]));
        self::assertNotSame(AuditFindingItem::fingerprint([$a]), AuditFindingItem::fingerprint([]));
    }

    #[Test]
    public function anAcknowledgedCopyKeepsItsIdentity(): void
    {
        $item = $this->item('a');

        $acknowledged = $item->withAcknowledgement(42);

        self::assertFalse($item->isAcknowledged());
        self::assertTrue($acknowledged->isAcknowledged());
        self::assertSame($item->key, $acknowledged->key);
        self::assertSame(42, $acknowledged->acknowledgedBy);
    }

    #[Test]
    public function theKeyChangesWithTheStoredContentOfTheRow(): void
    {
        $raw = HashChainVerificationResult::invalid([5 => 'Entry hash mismatch - possible tampering']);

        $first  = AuditFindingOverlay::itemsFrom($raw, [5 => 'digest-one'])[0];
        $second = AuditFindingOverlay::itemsFrom($raw, [5 => 'digest-two'])[0];

        self::assertNotSame($first->key, $second->key);
    }

    #[Test]
    public function errorsAndGapsBecomeSeparateItemsWithTheirReasonCodes(): void
    {
        $raw = HashChainVerificationResult::invalid(
            errors: [
                5  => 'Audit log uid gap detected: missing uids 3..4 (chain could have been tampered)',
                7  => 'HMAC key epoch downgrade detected: 3 -> 0 (possible algorithm-downgrade forgery)',
                9  => 'Entry hash mismatch - possible tampering',
                -1 => 'Audit chain tip anchor is unreadable',
            ],
            missingUids: [3, 4],
            gaps: [['start' => 3, 'end' => 4, 'uid' => 5]],
        );

        $items = AuditFindingOverlay::itemsFrom($raw, []);

        self::assertSame(
            ['UID_GAP', 'EPOCH_DOWNGRADE', 'HASH_MISMATCH', 'HASH_MISMATCH'],
            array_map(static fn (AuditFindingItem $item): string => $item->reason->value, $items),
            'the gap error string is not counted again as a hash error',
        );
        self::assertSame([3, 7, 9, 0], array_map(static fn (AuditFindingItem $item): int => $item->rangeStart, $items));
        self::assertSame(4, $items[0]->rangeEnd);
    }

    private function item(string $key): AuditFindingItem
    {
        return new AuditFindingItem($key, AuditIntegrityReason::HashMismatch, 1, 1, 'detail');
    }
}
