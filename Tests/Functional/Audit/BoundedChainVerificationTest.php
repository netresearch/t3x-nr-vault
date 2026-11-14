<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Audit;

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

    private function writeEntries(AuditLogServiceInterface $auditLogService, int $count): void
    {
        for ($i = 0; $i < $count; ++$i) {
            $auditLogService->log('bounded-' . $i, 'read', true, null, 'bounded range test');
        }
    }
}
