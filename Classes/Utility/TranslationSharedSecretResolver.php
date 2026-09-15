<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Utility;

use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Which records share a vault secret with which.
 *
 * A column the TCA marks `l10n_mode = exclude` is not translatable: TYPO3 keeps
 * every translation's value identical to the default-language record's. For a
 * vault reference that makes the SECRET shared — the translation must hold the
 * same identifier, because a clone would fork the credential and rotating one
 * side would silently leave the other on the old secret.
 *
 * Both DataHandler hooks need the same three answers to act on that: is this
 * column shared, is this record a translation, and does another live record
 * still reference this secret. They are resolved here once, so the rule cannot
 * drift between the TCA path ({@see \Netresearch\NrVault\Hook\DataHandlerHook})
 * and the FlexForm path ({@see \Netresearch\NrVault\Hook\FlexFormVaultHook}).
 */
final readonly class TranslationSharedSecretResolver
{
    public function __construct(
        private ConnectionPool $connectionPool,
        private VaultFieldResolver $vaultFieldResolver,
    ) {}

    /**
     * Whether translations share this column's value with the default-language
     * record.
     */
    public function isSharedColumn(string $table, string $column): bool
    {
        return $this->vaultFieldResolver->isTranslationSharedColumn($table, $column);
    }

    /**
     * The uid of the default-language record a write belongs to, or 0 when the
     * record is not a translation.
     *
     * A record being localized carries the pointer in the same field array; an
     * ordinary update of an existing translation does not, so it is read from
     * the persisted row.
     *
     * @param array<string, mixed> $fieldArray
     */
    public function resolveParentUid(string $table, string|int $id, array $fieldArray): int
    {
        $parentField = $this->vaultFieldResolver->getTranslationParentField($table);
        if ($parentField === null) {
            return 0;
        }

        /** @var mixed $submitted */
        $submitted = $fieldArray[$parentField] ?? null;
        if (is_numeric($submitted)) {
            return (int) $submitted;
        }

        if (!is_numeric($id)) {
            return 0;
        }

        $stored = $this->readColumn($table, (int) $id, $parentField);

        return is_numeric($stored) ? (int) $stored : 0;
    }

    /**
     * Whether the persisted record is a translation of another one.
     */
    public function isTranslation(string $table, int $uid): bool
    {
        return $this->resolveParentUid($table, $uid, []) > 0;
    }

    /**
     * Read a single column of a record, bypassing every restriction.
     */
    public function readColumn(string $table, int $uid, string $column): ?string
    {
        if ($uid <= 0) {
            return null;
        }

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        /** @var mixed $value */
        $value = $queryBuilder
            ->select($column)
            ->from($table)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return \is_string($value) || is_numeric($value) ? (string) $value : null;
    }

    /**
     * Whether a live record other than $uid holds this identifier as the whole
     * value of $column — the shape a TCA vault field stores it in.
     */
    public function isValueReferencedElsewhere(
        string $table,
        string $column,
        string $identifier,
        int $uid,
    ): bool {
        $queryBuilder = $this->liveRecordsOtherThan($table, $uid);
        $queryBuilder->andWhere(
            $queryBuilder->expr()->eq($column, $queryBuilder->createNamedParameter($identifier)),
        );

        return $this->hasRow($queryBuilder);
    }

    /**
     * Whether a live record other than $uid carries this identifier somewhere
     * inside $column — the shape a FlexForm field stores it in, where the
     * identifier sits in a `vDEF` node of the serialised XML and no equality
     * comparison can find it.
     */
    public function isIdentifierEmbeddedElsewhere(
        string $table,
        string $column,
        string $identifier,
        int $uid,
    ): bool {
        $queryBuilder = $this->liveRecordsOtherThan($table, $uid);
        $pattern = '%' . $queryBuilder->escapeLikeWildcards($identifier) . '%';
        $queryBuilder->andWhere(
            $queryBuilder->expr()->like($column, $queryBuilder->createNamedParameter($pattern)),
        );

        return $this->hasRow($queryBuilder);
    }

    /**
     * A counting query over every record of $table that is neither $uid nor
     * soft-deleted.
     */
    private function liveRecordsOtherThan(string $table, int $uid): QueryBuilder
    {
        /** @var array<string, array{ctrl?: array{delete?: string}}> $tca */
        $tca = $GLOBALS['TCA'] ?? [];
        $deleteField = $tca[$table]['ctrl']['delete'] ?? null;

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();
        $queryBuilder
            ->count('uid')
            ->from($table)
            ->where(
                $queryBuilder->expr()->neq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)),
            );

        if (\is_string($deleteField) && $deleteField !== '') {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq($deleteField, $queryBuilder->createNamedParameter(0, Connection::PARAM_INT)),
            );
        }

        return $queryBuilder;
    }

    private function hasRow(QueryBuilder $queryBuilder): bool
    {
        /** @var mixed $count */
        $count = $queryBuilder->executeQuery()->fetchOne();

        return is_numeric($count) && (int) $count > 0;
    }
}
