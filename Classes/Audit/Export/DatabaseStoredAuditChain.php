<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Export;

use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

use function is_array;
use function is_numeric;
use function is_string;

/**
 * The stored audit chain, read from `tx_nrvault_audit_log` without any
 * restrictions.
 */
final readonly class DatabaseStoredAuditChain implements StoredAuditChainInterface
{
    private const TABLE_NAME = 'tx_nrvault_audit_log';

    public function __construct(
        private ConnectionPool $connectionPool,
    ) {}

    public function exportRowAt(int $uid): ?array
    {
        $queryBuilder = $this->queryBuilder();
        $row          = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchAssociative();

        return is_array($row) ? AuditChainExporter::exportRow($row) : null;
    }

    public function entryHashAt(int $uid): ?string
    {
        $queryBuilder = $this->queryBuilder();
        $value        = $queryBuilder
            ->select('entry_hash')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return is_string($value) ? $value : null;
    }

    public function countAfter(int $uid): int
    {
        $queryBuilder = $this->queryBuilder();
        $value        = $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->gt('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return is_numeric($value) ? (int) $value : 0;
    }

    private function queryBuilder(): QueryBuilder
    {
        $queryBuilder = $this->connectionPool->getConnectionForTable(self::TABLE_NAME)->createQueryBuilder();
        $queryBuilder->getRestrictions()->removeAll();

        return $queryBuilder;
    }
}
