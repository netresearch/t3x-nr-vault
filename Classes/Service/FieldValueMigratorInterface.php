<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use Doctrine\DBAL\Schema\Column;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Moves plaintext column values into the vault for `vault:migrate-field` and
 * the backend migration wizard.
 *
 * @internal the seam the migration command and the migration wizard use
 */
interface FieldValueMigratorInterface
{
    /**
     * The column of the table, looked up on the table's own connection, or
     * null when the table has no such column.
     */
    public function findColumn(string $table, string $field): ?Column;

    /**
     * Why the column cannot hold an identifier of the given length, or null
     * when it can.
     */
    public function columnProblem(Column $column, int $identifierLength): ?string;

    /**
     * Rows whose key column shares its value with another row, or null when
     * the database gave no usable answer.
     */
    public function countRowsWithDuplicateKey(string $table, string $keyField): ?int;

    /**
     * Let the query select hidden and time-restricted rows, which hold
     * plaintext secrets too, but not deleted ones: the deleted restriction
     * (TCA ctrl.delete) stays, and a table without TCA that has a `deleted`
     * column is filtered on it.
     */
    public function restrictToMigratableRows(QueryBuilder $queryBuilder, string $table): void;

    /**
     * Whether a secret holds the identifier, disabled secrets included.
     */
    public function identifierInUse(string $identifier): bool;

    /**
     * Store the value under the identifier and write the identifier into the
     * row whose key column holds the key and whose field still holds the
     * value. Returns null on success, otherwise what happened to the row and
     * the secret.
     */
    public function migrate(
        string $table,
        string $field,
        string $keyField,
        string $key,
        string $value,
        string $identifier,
    ): ?string;
}
