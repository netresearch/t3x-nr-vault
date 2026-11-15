<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Audit;

use Netresearch\NrVault\Audit\Acknowledgement\AcknowledgementStatus;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingAcknowledger;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingAcknowledgerInterface;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingItem;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Below HMAC epoch 3 the MAC does not cover `reason`, `context` or the actor
 * columns, so an acknowledgement could be forged or edited without the key.
 */
#[CoversClass(AuditFindingAcknowledger::class)]
final class AuditFindingAcknowledgementLowEpochTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Command/Fixtures/be_users_audit_permission.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
        'auditHmacEpoch'    => 2,
    ];

    #[Test]
    public function acknowledgingIsRefusedAtAnEpochWhoseMacDoesNotCoverTheAcknowledgement(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        for ($i = 0; $i < 6; ++$i) {
            $auditService->log('low-' . $i, 'read', true, null, 'low epoch test');
        }

        $this->get(ConnectionPool::class)
            ->getConnectionForTable('tx_nrvault_audit_log')
            ->update('tx_nrvault_audit_log', ['secret_identifier' => 'rewritten'], ['uid' => 3]);

        $open = $this->get(ChainTipAnchorServiceInterface::class)->inspect()->getOpenItems();
        self::assertNotSame([], $open, 'precondition: the tampered row is an open finding');

        $outcome = $this->get(AuditFindingAcknowledgerInterface::class)
            ->acknowledge(AuditFindingItem::fingerprint($open), 'would be forgeable', '', 0);

        self::assertSame(AcknowledgementStatus::EpochTooLow, $outcome->status);
        self::assertNotSame([], $this->get(ChainTipAnchorServiceInterface::class)->inspect()->getOpenItems());
    }
}
