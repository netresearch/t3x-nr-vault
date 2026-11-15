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
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Fixtures\TransactionProbe\TransactionProbeSink;
use Netresearch\NrVault\Tests\Functional\Traits\AuditSinkSandboxTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * The acknowledgement row is written inside the vault mutation transaction:
 * the chain lock is held from reading the tip until the commit, and the sinks
 * receive the row only once it is committed. Outside it, log() released the
 * lock and published the row while the outer transaction was still open.
 */
#[CoversClass(AuditFindingAcknowledger::class)]
final class AuditFindingAcknowledgementTransactionTest extends AbstractVaultFunctionalTestCase
{
    use AuditSinkSandboxTrait;

    protected ?string $backendUserFixture = __DIR__ . '/../Command/Fixtures/be_users_audit_permission.csv';

    /** @var list<string> */
    protected array $testExtensionsToLoad = [
        'netresearch/nr-vault',
        __DIR__ . '/../Fixtures/Extensions/vault_transaction_probe_sink',
    ];

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
        'auditHmacEpoch'    => 3,
    ];

    protected function setUp(): void
    {
        $this->extensionConfiguration       = $this->prepareAuditSinkSandbox($this->extensionConfiguration);
        TransactionProbeSink::$observations = [];

        parent::setUp();
    }

    protected function tearDown(): void
    {
        $this->cleanUpAuditSinkSandbox();
        TransactionProbeSink::$observations = [];

        parent::tearDown();
    }

    #[Test]
    public function theSinksReceiveTheAcknowledgementOnlyAfterItIsCommitted(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        for ($i = 0; $i < 8; ++$i) {
            $auditService->log('probe-' . $i, 'read', true, null, 'transaction probe');
        }

        $this->get(ConnectionPool::class)->getConnectionForTable(AuditLogService::TABLE_NAME)
            ->update(AuditLogService::TABLE_NAME, ['reason' => 'edited after the fact'], ['uid' => 5]);

        $report  = $this->get(ChainTipAnchorServiceInterface::class)->inspect();
        $outcome = $this->get(AuditFindingAcknowledgerInterface::class)->acknowledge(
            AuditFindingItem::fingerprint($report->getOpenItems()),
            'probe',
            '',
            0,
        );
        self::assertSame(AcknowledgementStatus::Acknowledged, $outcome->status);

        $acknowledgements = array_values(array_filter(
            TransactionProbeSink::$observations,
            static fn (array $observation): bool => $observation['action'] === AuditAction::AuditFindingsAcknowledged->value,
        ));
        self::assertCount(1, $acknowledgements, 'the probe sink received the acknowledgement row');
        self::assertFalse($acknowledgements[0]['transactionActive'], 'the row reached the sinks while its transaction was still open');
    }
}
