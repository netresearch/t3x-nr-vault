<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Crypto;

use Netresearch\NrVault\Crypto\EnvelopeCodecInterface;
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

    /**
     * The additional authenticated data every payload of this consumer is
     * sealed under. `EnvelopeCodecInterface::seal()` asks for a stable,
     * per-purpose label rather than a per-row one, so a row that moves still
     * opens.
     */
    public const ENVELOPE_CONTEXT = 'nr_vault_consumer_fixture:payload';

    public function __construct(
        private ConnectionPool $connectionPool,
        private EnvelopeCodecInterface $envelopeCodec,
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

    /**
     * Sealed envelopes only — the same rows `rewrapAll()` re-wraps.
     *
     * A plain count of the table would report rows written before this
     * consumer started sealing, which `rewrapAll()` skips. The rotation
     * command compares the two numbers and rolls back when it re-wraps fewer
     * than were inventoried, so an implementation whose count is wider than
     * its work makes every rotation fail.
     */
    public function countEnvelopes(): int
    {
        $connection = $this->connectionPool->getConnectionForTable(self::TABLE);
        $sealed = 0;
        foreach ($connection->select(['sealed'], self::TABLE)->fetchAllAssociative() as $row) {
            if ($this->envelopeCodec->isSealed(\is_string($row['sealed'] ?? null) ? $row['sealed'] : '')) {
                ++$sealed;
            }
        }

        return $sealed;
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

            $connection->update(
                self::TABLE,
                ['sealed' => $context->rewrap($sealed, self::ENVELOPE_CONTEXT)],
                ['uid' => $uid],
            );
            ++$rewrapped;
        }

        return $rewrapped;
    }
}
