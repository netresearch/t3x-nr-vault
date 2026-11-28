<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use Netresearch\NrVault\Domain\Dto\OrphanReference;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function is_numeric;

/**
 * Decides whether a linked secret is an orphan: the one question both orphan
 * cleanups (`OrphanCleanupTask`, `vault:cleanup-orphans`) ask before they
 * delete.
 *
 * A secret is an orphan when its linked record (table, uid) no longer exists,
 * deleted rows included.
 *
 * Fails CLOSED. Only a lookup that succeeds and finds no row may answer true,
 * because true is a DELETE trigger. A table or connection the checker cannot
 * resolve, or a query that errors, proves nothing about the record and answers
 * false.
 */
final readonly class OrphanReferenceChecker
{
    public function __construct(
        private ConnectionPool $connectionPool,
        private LoggerInterface $logger = new NullLogger(),
    ) {}

    public function isOrphaned(OrphanReference $reference, string $identifier): bool
    {
        $context = [
            'table'      => $reference->table,
            'uid'        => $reference->uid,
            'identifier' => $identifier,
        ];

        try {
            // A table mapped to another connection lives in that database.
            $connection = $this->connectionPool->getConnectionForTable($reference->table);
            if (!$connection->createSchemaManager()->tablesExist([$reference->table])) {
                $this->logger->warning('Orphan reference names an unknown table; keeping the secret', $context);

                return false;
            }

            $queryBuilder = $this->connectionPool->getQueryBuilderForTable($reference->table);
            $queryBuilder->getRestrictions()->removeAll();

            $count = $queryBuilder
                ->count('*')
                ->from($reference->table)
                ->where(
                    $queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($reference->uid, Connection::PARAM_INT)),
                )
                ->executeQuery()
                ->fetchOne();

            // Anything but a count proves nothing: keep the secret.
            return is_numeric($count) && (int) $count === 0;
        } catch (Throwable $e) {
            $this->logger->warning(
                'Orphan reference could not be resolved; keeping the secret',
                $context + ['error' => $e->getMessage()],
            );

            return false;
        }
    }
}
