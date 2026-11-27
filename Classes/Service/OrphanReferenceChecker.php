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

use function array_keys;
use function array_map;
use function in_array;
use function strtolower;
use function strval;

/**
 * Decides whether a linked secret is an orphan: the one question both orphan
 * cleanups (`OrphanCleanupTask`, `vault:cleanup-orphans`) ask before they
 * delete.
 *
 * Fails CLOSED. Only lookups that succeed and find nothing may answer true,
 * because true is a DELETE trigger. A table, connection or column the checker
 * cannot resolve, or a query that errors, proves nothing about the record and
 * answers false.
 *
 * A secret is an orphan only when BOTH hold:
 *
 *  - the linked record (`uid`) no longer exists, deleted rows included;
 *  - no row of the linked table still holds the identifier in the linked
 *    field (for a FlexForm link: no FlexForm value of that column contains
 *    it).
 *
 * The second condition covers records whose uid differs from the link while
 * they still reference the secret: a published workspace version (core
 * hard-deletes the version row and moves its values onto the live uid), a
 * translation sharing a non-translatable field, a copy.
 */
final class OrphanReferenceChecker
{
    /**
     * Lower-cased column names per table, read once per cleanup run.
     *
     * @var array<string, list<string>>
     */
    private array $columns = [];

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    public function isOrphaned(OrphanReference $reference, string $identifier): bool
    {
        $context = [
            'table'      => $reference->table,
            'field'      => $reference->field,
            'uid'        => $reference->uid,
            'identifier' => $identifier,
        ];

        try {
            $unresolvable = $this->unresolvableReason($reference, $identifier);
            if ($unresolvable !== null) {
                $this->logger->warning('Orphan reference ' . $unresolvable . '; keeping the secret', $context);

                return false;
            }

            return !$this->recordExists($reference) && !$this->identifierIsReferenced($reference, $identifier);
        } catch (Throwable $e) {
            $this->logger->warning(
                'Orphan reference could not be resolved; keeping the secret',
                $context + ['error' => $e->getMessage()],
            );

            return false;
        }
    }

    /**
     * Why the reference cannot be checked, or null when it can.
     */
    private function unresolvableReason(OrphanReference $reference, string $identifier): ?string
    {
        $reason = null;

        if ($reference->field === '' || $identifier === '') {
            $reason = 'names no field';
        } elseif (!$this->connectionPool->getConnectionForTable($reference->table)->createSchemaManager()->tablesExist([$reference->table])) {
            $reason = 'names an unknown table';
        } elseif (!in_array(strtolower($reference->field), $this->columnsOf($reference->table), true)) {
            // Checked explicitly: SQLite reads an unknown double-quoted
            // identifier as a string literal, so the holder query would
            // answer "no row holds it" instead of failing.
            $reason = 'names an unknown field';
        }

        return $reason;
    }

    /**
     * @return list<string>
     */
    private function columnsOf(string $table): array
    {
        if (!isset($this->columns[$table])) {
            $columns = $this->connectionPool->getConnectionForTable($table)->createSchemaManager()->listTableColumns($table);

            $this->columns[$table] = array_map(strtolower(...), array_map(strval(...), array_keys($columns)));
        }

        return $this->columns[$table];
    }

    private function recordExists(OrphanReference $reference): bool
    {
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

        return $count > 0;
    }

    /**
     * Does any row of the linked table, deleted rows included, still hold the
     * identifier in the linked field?
     */
    private function identifierIsReferenced(OrphanReference $reference, string $identifier): bool
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($reference->table);
        $queryBuilder->getRestrictions()->removeAll();

        $condition = $reference->flexForm
            ? $queryBuilder->expr()->like(
                $reference->field,
                $queryBuilder->createNamedParameter('%' . $queryBuilder->escapeLikeWildcards($identifier) . '%'),
            )
            : $queryBuilder->expr()->eq($reference->field, $queryBuilder->createNamedParameter($identifier));

        $count = $queryBuilder
            ->count('*')
            ->from($reference->table)
            ->where($condition)
            ->executeQuery()
            ->fetchOne();

        return $count > 0;
    }
}
