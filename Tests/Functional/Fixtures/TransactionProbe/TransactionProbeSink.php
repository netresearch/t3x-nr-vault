<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\TransactionProbe;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\Sink\AuditSinkInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Records, per published entry, whether the audit connection still had an
 * open transaction: a sink must only hear of an entry once it is committed.
 */
final class TransactionProbeSink implements AuditSinkInterface
{
    /** @var list<array{action: string, transactionActive: bool}> */
    public static array $observations = [];

    public function __construct(
        private readonly ConnectionPool $connectionPool,
    ) {}

    public function publish(AuditLogEntry $entry, string $chainTip): void
    {
        self::$observations[] = [
            'action'            => $entry->action,
            'transactionActive' => $this->connectionPool->getConnectionForTable(AuditLogService::TABLE_NAME)->isTransactionActive(),
        ];
    }

    public function publishAnchor(ChainTipAnchor $anchor): void
    {
        // Anchors carry no audit row, so there is no transaction to observe.
    }

    public function publishAlert(AuditIntegrityAlert $alert): void
    {
        // Alerts carry no audit row, so there is no transaction to observe.
    }

    public function getIdentifier(): string
    {
        return 'transaction-probe';
    }

    public function isEnabled(): bool
    {
        return true;
    }
}
