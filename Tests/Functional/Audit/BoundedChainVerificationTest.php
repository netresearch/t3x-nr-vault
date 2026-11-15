<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Audit;

use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingItem;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingOverlayInterface;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * A bounded verification starts in the middle of the chain, so its first row
 * links to a row outside the range. The security-readiness check
 * `audit.hash_chain` verifies the newest 1000 rows this way and reported one
 * failure on every installation with more than 1000 audit rows, although the
 * stored chain was intact.
 */
#[CoversClass(AuditLogService::class)]
final class BoundedChainVerificationTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Service/Fixtures/be_users.csv';

    #[Test]
    public function boundedRangeOfAnIntactChainIsValid(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 8);

        self::assertTrue($auditLogService->verifyHashChain()->isValid(), 'precondition: the full chain is valid');

        $result = $auditLogService->verifyHashChain(4);

        self::assertSame([], $result->errors);
        self::assertTrue($result->isValid());
    }

    #[Test]
    public function boundedRangeStillDetectsATamperedRowInsideIt(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 8);

        $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->update('tx_nrvault_audit_log', ['reason' => 'edited after the fact'], ['uid' => 6]);

        $result = $auditLogService->verifyHashChain(4);

        self::assertFalse($result->isValid());
        self::assertSame([6], array_keys($result->errors));
    }

    #[Test]
    public function boundedRangeDetectsARewrittenPredecessorLink(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 8);

        // The first row of the range links to a row outside it: a patched
        // previous_hash there must still fail.
        $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->update('tx_nrvault_audit_log', ['previous_hash' => str_repeat('0', 64)], ['uid' => 4]);

        $result = $auditLogService->verifyHashChain(4);

        self::assertFalse($result->isValid());
        self::assertSame([4], array_keys($result->errors));
    }

    /**
     * A range that starts inside a gap continues from the nearest row before
     * it, so it reports the gap with the bounds of the full pass whenever such
     * a row exists (a gap at the head of the chain has none). The gap's
     * finding key carries those bounds: with a shorter gap the Doctor check,
     * which verifies only the newest rows, would reopen a gap an administrator
     * acknowledged against the full chain.
     */
    #[Test]
    public function aRangeStartingInsideAGapReportsTheGapOfTheFullPass(): void
    {
        $auditLogService = $this->get(AuditLogServiceInterface::class);
        $this->writeEntries($auditLogService, 12);

        $connection = $this->get(ConnectionPool::class)->getConnectionForTable('tx_nrvault_audit_log');
        foreach ([4, 5, 6, 7] as $uid) {
            $connection->delete('tx_nrvault_audit_log', ['uid' => $uid]);
        }

        $full    = $auditLogService->verifyHashChain();
        $bounded = $auditLogService->verifyHashChain(6);

        self::assertSame([['start' => 4, 'end' => 7, 'uid' => 8]], $full->gaps);
        self::assertSame($full->gaps, $bounded->gaps);
        self::assertSame(array_keys($full->errors), array_keys($bounded->errors));

        $overlay = $this->get(AuditFindingOverlayInterface::class);
        self::assertSame(
            array_map(static fn (AuditFindingItem $item): string => $item->key, $overlay->chainItems($full)),
            array_map(static fn (AuditFindingItem $item): string => $item->key, $overlay->chainItems($bounded)),
        );
    }

    private function writeEntries(AuditLogServiceInterface $auditLogService, int $count): void
    {
        for ($i = 0; $i < $count; ++$i) {
            $auditLogService->log('bounded-' . $i, 'read', true, null, 'bounded range test');
        }
    }
}
