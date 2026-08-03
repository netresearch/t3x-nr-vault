<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Traits;

use TYPO3\TestingFramework\Core\Functional\FunctionalTestCase;

/**
 * Reads a `tx_nrvault_secret` row as it actually stands, restrictions and all
 * removed — the level at which "which columns did that write touch" is a
 * question with an answer. Tests that assert on availability must not go
 * through a restriction-honouring query: a disabled record is invisible to
 * one, so the assertion would read nothing instead of the row it means to
 * inspect.
 *
 * @phpstan-require-extends FunctionalTestCase
 */
trait SecretRowTrait
{
    /**
     * @return array<string, mixed> The full row, keyed by column name
     */
    private function readSecretRow(string $identifier): array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tx_nrvault_secret');
        $queryBuilder->getRestrictions()->removeAll();

        $row = $queryBuilder
            ->select('*')
            ->from('tx_nrvault_secret')
            ->where(
                $queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)),
            )
            ->executeQuery()
            ->fetchAssociative();

        self::assertIsArray($row, 'No tx_nrvault_secret row for ' . $identifier);

        return $row;
    }
}
