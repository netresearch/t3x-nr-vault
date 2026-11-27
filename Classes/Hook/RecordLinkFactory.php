<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

use Netresearch\NrVault\Domain\Dto\SecretRecordLink;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

use function is_numeric;

/**
 * Builds the `metadata` record link for a secret a DataHandler hook creates.
 *
 * The link always names the LIVE record. Inside a workspace the hooks can be
 * handed the uid of a workspace version; publishing moves the version's values
 * onto the live uid and deletes the version row, so a link to the version uid
 * would point at a row that no longer exists while the live record holds the
 * secret. A version row (`t3ver_oid > 0`) is therefore linked through its
 * `t3ver_oid`. A record created inside a workspace keeps its uid on publish
 * and is linked as is.
 */
final readonly class RecordLinkFactory implements RecordLinkFactoryInterface
{
    public function __construct(
        private ConnectionPool $connectionPool,
        private TcaSchemaFactory $tcaSchemaFactory,
    ) {}

    /**
     * @param array<string, mixed> $extra
     *
     * @return array<string, mixed>
     */
    public function forField(string $source, string $table, string $field, int $uid, array $extra = []): array
    {
        return SecretRecordLink::forField($source, $table, $field, $this->liveUid($table, $uid), $extra);
    }

    /**
     * @param array<string, mixed> $extra
     *
     * @return array<string, mixed>
     */
    public function forFlexField(string $source, string $table, string $flexField, int $uid, array $extra = []): array
    {
        return SecretRecordLink::forFlexField($source, $table, $flexField, $this->liveUid($table, $uid), $extra);
    }

    /**
     * The live uid of a record: its `t3ver_oid` when the row is a workspace
     * version, the uid itself otherwise.
     */
    public function liveUid(string $table, int $uid): int
    {
        if ($uid <= 0
            || !$this->tcaSchemaFactory->has($table)
            || !$this->tcaSchemaFactory->get($table)->isWorkspaceAware()
        ) {
            return $uid;
        }

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $originalUid = $queryBuilder
            ->select('t3ver_oid')
            ->from($table)
            ->where(
                $queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($originalUid) && (int) $originalUid > 0 ? (int) $originalUid : $uid;
    }
}
