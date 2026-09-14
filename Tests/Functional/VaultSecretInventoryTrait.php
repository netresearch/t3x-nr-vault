<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional;

use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\IdentifierValidator;
use TYPO3\CMS\Core\Database\Connection;

/**
 * Counts what a DataHandler operation left in the vault.
 *
 * A record operation that duplicates a record (copy, localize, …) must add
 * exactly one secret per filled vault field of the new record. Assertions on
 * the copied record alone cannot see a secret nothing references any more, nor
 * one whose plaintext is another record's vault identifier — both are states
 * only an inventory of the whole vault reveals.
 */
trait VaultSecretInventoryTrait
{
    /**
     * Identifiers of all secrets that are not deleted, in creation order.
     *
     * @return list<string>
     */
    protected function activeSecretIdentifiers(): array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tx_nrvault_secret');
        $queryBuilder->getRestrictions()->removeAll();

        $rows = $queryBuilder
            ->select('identifier')
            ->from('tx_nrvault_secret')
            ->where($queryBuilder->expr()->eq('deleted', $queryBuilder->createNamedParameter(0, Connection::PARAM_INT)))
            ->orderBy('uid')
            ->executeQuery()
            ->fetchFirstColumn();

        $identifiers = [];
        foreach ($rows as $identifier) {
            self::assertIsString($identifier);
            $identifiers[] = $identifier;
        }

        return $identifiers;
    }

    protected function countAuditRows(string $action): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable('tx_nrvault_audit_log');

        return (int) $queryBuilder
            ->count('uid')
            ->from('tx_nrvault_audit_log')
            ->where($queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action)))
            ->executeQuery()
            ->fetchOne();
    }

    /**
     * How many stored secrets carry a vault identifier as their plaintext.
     *
     * That is what a record's stored reference turns into when a nested
     * DataHandler pass mistakes the duplicated identifier for a freshly typed
     * secret: the value is not the user's secret at all.
     */
    protected function countSecretsHoldingAVaultIdentifier(): int
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $count = 0;

        foreach ($this->activeSecretIdentifiers() as $identifier) {
            $value = $vaultService->retrieve($identifier);
            if (\is_string($value) && IdentifierValidator::looksLikeVaultIdentifier($value)) {
                ++$count;
            }
        }

        return $count;
    }
}
