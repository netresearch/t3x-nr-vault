<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Crypto;

use Netresearch\NrVault\Crypto\EnvelopeRotationContext;
use Netresearch\NrVault\Crypto\ForeignEnvelopeRotatorInterface;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Joins master-key rotation for the envelopes this consumer keeps in its own
 * table. Rows that are not sealed envelopes are left alone.
 */
final readonly class PayloadEnvelopeRotator implements ForeignEnvelopeRotatorInterface
{
    public const IDENTIFIER = 'nr_vault_consumer_fixture: sealed payloads';

    public const TABLE = 'tx_nrvaultconsumerfixture_payload';

    public function __construct(
        private ConnectionPool $connectionPool,
    ) {}

    public function getIdentifier(): string
    {
        return self::IDENTIFIER;
    }

    /**
     * @return list<string>
     */
    public function getTables(): array
    {
        return [self::TABLE];
    }

    public function countEnvelopes(): int
    {
        return $this->connectionPool->getConnectionForTable(self::TABLE)->count('uid', self::TABLE, []);
    }

    public function rewrapAll(EnvelopeRotationContext $context): int
    {
        $connection = $this->connectionPool->getConnectionForTable(self::TABLE);
        $rewrapped = 0;
        foreach ($connection->select(['uid', 'sealed'], self::TABLE)->fetchAllAssociative() as $row) {
            $sealed = \is_string($row['sealed'] ?? null) ? $row['sealed'] : '';
            $uid = is_numeric($row['uid'] ?? null) ? (int) $row['uid'] : 0;
            if (!$context->isSealed($sealed)) {
                continue;
            }

            $connection->update(self::TABLE, ['sealed' => $context->rewrap($sealed, 'payload-' . $uid)], ['uid' => $uid]);
            ++$rewrapped;
        }

        return $rewrapped;
    }
}
