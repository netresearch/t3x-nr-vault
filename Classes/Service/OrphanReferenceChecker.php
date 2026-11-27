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
use TYPO3\CMS\Core\Database\ConnectionPool;

use function array_keys;
use function in_array;
use function strtolower;
use function trim;

/**
 * Decides whether a linked secret is an orphan: the one question both orphan
 * cleanups (`OrphanCleanupTask`, `vault:cleanup-orphans`) ask before they
 * delete.
 *
 * A secret is an orphan when no row of the linked table, deleted rows
 * included, holds its identifier in the linked field (for a FlexForm link: no
 * FlexForm value of that column contains it). Whether the linked uid still
 * exists does not matter: a published workspace version moves the identifier
 * to the live uid, a translation shares it, and a discarded version leaves a
 * live record that never held it.
 *
 * Fails CLOSED. Only a lookup that succeeds and finds no holder may answer
 * true, because true is a DELETE trigger. A table, connection or column the
 * checker cannot resolve, or a query that errors, proves nothing and answers
 * false; such references are kept in {@see self::getUnresolvedReferences()}
 * and logged.
 */
final class OrphanReferenceChecker
{
    /**
     * Lower-cased column names per table, read once per cleanup run.
     *
     * @var array<string, list<string>>
     */
    private array $columns = [];

    /** @var list<array{identifier: string, table: string, field: string, uid: int, reason: string}> */
    private array $unresolved = [];

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    public function isOrphaned(OrphanReference $reference, string $identifier): bool
    {
        try {
            $unresolvable = $this->unresolvableReason($reference, $identifier);
            if ($unresolvable !== null) {
                $this->keep($reference, $identifier, $unresolvable);

                return false;
            }

            return !$this->identifierIsReferenced($reference, $identifier);
        } catch (Throwable $e) {
            $this->keep($reference, $identifier, 'could not be resolved: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * The references this checker kept because it could not check them.
     *
     * @return list<array{identifier: string, table: string, field: string, uid: int, reason: string}>
     */
    public function getUnresolvedReferences(): array
    {
        return $this->unresolved;
    }

    private function keep(OrphanReference $reference, string $identifier, string $reason): void
    {
        $entry = [
            'identifier' => $identifier,
            'table'      => $reference->table,
            'field'      => $reference->field,
            'uid'        => $reference->uid,
            'reason'     => $reason,
        ];

        $this->unresolved[] = $entry;
        $this->logger->warning(
            'Orphan reference {table}.{field} (uid {uid}) of secret {identifier} {reason}; keeping the secret',
            $entry,
        );
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
            $names = [];
            // DBAL keys the list by the lower-cased, platform-QUOTED name:
            // a reserved word arrives as `key` (MySQL) or "key" (SQLite,
            // PostgreSQL). Strip the quotes to compare with the plain name.
            foreach (array_keys($this->connectionPool->getConnectionForTable($table)->createSchemaManager()->listTableColumns($table)) as $quoted) {
                $names[] = strtolower(trim((string) $quoted, '`"[]'));
            }

            $this->columns[$table] = $names;
        }

        return $this->columns[$table];
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
