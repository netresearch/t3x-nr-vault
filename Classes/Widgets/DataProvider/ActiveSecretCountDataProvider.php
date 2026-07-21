<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Widgets\DataProvider;

use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Dashboard\Widgets\NumberWithIconDataProviderInterface;

/**
 * Data provider for the "Vault secrets" NumberWithIcon dashboard widget.
 *
 * Counts active secrets in tx_nrvault_secret with a single aggregate query.
 * "Active" means neither soft-deleted nor hidden; the flags are filtered
 * explicitly (restrictions removed) so the count does not silently change
 * with TCA enable-column configuration.
 */
final readonly class ActiveSecretCountDataProvider implements NumberWithIconDataProviderInterface
{
    private const TABLE = 'tx_nrvault_secret';

    public function __construct(
        private ConnectionPool $connectionPool,
    ) {}

    public function getNumber(): int
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable(self::TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $count = $queryBuilder
            ->count('uid')
            ->from(self::TABLE)
            ->where(
                $queryBuilder->expr()->eq(
                    'deleted',
                    $queryBuilder->createNamedParameter(0, Connection::PARAM_INT),
                ),
                $queryBuilder->expr()->eq(
                    'hidden',
                    $queryBuilder->createNamedParameter(0, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }
}
