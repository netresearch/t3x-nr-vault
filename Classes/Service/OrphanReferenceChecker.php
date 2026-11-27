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
use function in_array;
use function is_string;
use function min;
use function str_contains;
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
 * Queries per run, for N secrets in T tables: one table and one column
 * introspection per table, one primary-key read per secret (the linked row
 * nearly always holds its own secret), and only when that row does not: one
 * load of the column's values per (table, field) for a plain field, or one
 * LIKE count per secret for a FlexForm field, whose XML cannot be matched
 * from a loaded value set without parsing every document.
 *
 * Fails CLOSED. Only a lookup that succeeds and finds no holder may answer
 * true, because true is a DELETE trigger. A table, connection or column the
 * checker cannot resolve, or a query that errors, proves nothing and answers
 * false; such references are kept in {@see self::getUnresolvedReferences()}
 * and logged.
 */
final class OrphanReferenceChecker implements OrphanReferenceCheckerInterface
{
    /** @var array<string, bool> */
    private array $tables = [];

    /**
     * Lower-cased column names per table.
     *
     * @var array<string, list<string>>
     */
    private array $columns = [];

    /**
     * The non-empty values of a plain field, as a set, per "table.field".
     *
     * @var array<string, array<string, true>>
     */
    private array $heldValues = [];

    /** @var list<array{identifier: string, table: string, field: string, uid: int, reason: string}> */
    private array $unresolved = [];

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    public function reset(): void
    {
        $this->tables     = [];
        $this->columns    = [];
        $this->heldValues = [];
        $this->unresolved = [];
    }

    public function deletionCutoff(int $retentionDays, int $now): int
    {
        $retentionCutoff = $retentionDays > 0 ? $now - ($retentionDays * 86400) : PHP_INT_MAX;

        return min($retentionCutoff, $now - self::MINIMUM_AGE_SECONDS);
    }

    public function isOrphaned(OrphanReference $reference, string $identifier): bool
    {
        try {
            $unresolvable = $this->unresolvableReason($reference, $identifier);
            if ($unresolvable !== null) {
                $this->keep($reference, $identifier, $unresolvable);

                return false;
            }

            return !$this->linkedRowHolds($reference, $identifier) && !$this->anyRowHolds($reference, $identifier);
        } catch (Throwable $e) {
            $this->keep($reference, $identifier, 'could not be resolved: ' . $e->getMessage());

            return false;
        }
    }

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
        } elseif (!$this->tableExists($reference->table)) {
            $reason = 'names an unknown table';
        } elseif (!in_array(strtolower($reference->field), $this->columnsOf($reference->table), true)) {
            // Checked explicitly: SQLite reads an unknown double-quoted
            // identifier as a string literal, so the holder query would
            // answer "no row holds it" instead of failing.
            $reason = 'names an unknown field';
        }

        return $reason;
    }

    private function tableExists(string $table): bool
    {
        return $this->tables[$table] ??= $this->connectionPool->getConnectionForTable($table)
            ->createSchemaManager()
            ->tablesExist([$table]);
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
     * The cheap check first: does the linked row itself hold the identifier?
     */
    private function linkedRowHolds(OrphanReference $reference, string $identifier): bool
    {
        if (!in_array('uid', $this->columnsOf($reference->table), true)) {
            return false;
        }

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($reference->table);
        $queryBuilder->getRestrictions()->removeAll();

        $value = $queryBuilder
            ->select($reference->field)
            ->from($reference->table)
            ->where(
                $queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($reference->uid, Connection::PARAM_INT)),
            )
            ->executeQuery()
            ->fetchOne();

        if (!is_string($value)) {
            return false;
        }

        return $reference->flexForm ? str_contains($value, $identifier) : $value === $identifier;
    }

    /**
     * Does any row of the linked table, deleted rows included, hold the
     * identifier in the linked field?
     */
    private function anyRowHolds(OrphanReference $reference, string $identifier): bool
    {
        if (!$reference->flexForm) {
            return isset($this->heldValuesOf($reference->table, $reference->field)[$identifier]);
        }

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($reference->table);
        $queryBuilder->getRestrictions()->removeAll();

        $count = $queryBuilder
            ->count('*')
            ->from($reference->table)
            ->where($queryBuilder->expr()->like(
                $reference->field,
                $queryBuilder->createNamedParameter('%' . $queryBuilder->escapeLikeWildcards($identifier) . '%'),
            ))
            ->executeQuery()
            ->fetchOne();

        return $count > 0;
    }

    /**
     * @return array<string, true>
     */
    private function heldValuesOf(string $table, string $field): array
    {
        $key = $table . '.' . $field;
        if (!isset($this->heldValues[$key])) {
            $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
            $queryBuilder->getRestrictions()->removeAll();

            $values = $queryBuilder
                ->select($field)
                ->distinct()
                ->from($table)
                ->where($queryBuilder->expr()->neq($field, $queryBuilder->createNamedParameter('')))
                ->executeQuery()
                ->fetchFirstColumn();

            $set = [];
            foreach ($values as $value) {
                if (is_string($value)) {
                    $set[$value] = true;
                }
            }

            $this->heldValues[$key] = $set;
        }

        return $this->heldValues[$key];
    }
}
