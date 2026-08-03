<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Traits\SecretRowTrait;
use PHPUnit\Framework\Attributes\Test;

/**
 * What a value write does to the columns it does not own.
 *
 * `store()` rebuilds the whole `Secret` aggregate from its inputs and the
 * record it read, and `Secret::toDatabaseRow()` writes every scalar column on
 * the resulting UPDATE. A field the rebuild forgets is therefore not left
 * alone — it is overwritten with the constructor default. Three columns are
 * owned by other paths and can only ever be carried here:
 *
 *  - `last_rotated_at`, written by `rotate()`,
 *  - `read_count` and `last_read_at`, written by the read path's
 *    `incrementReadCount()`.
 *
 * The consequence of losing them is not cosmetic. A rotated secret that reads
 * back as never rotated is what rotation-age reporting, the module's Reads /
 * Last read columns and the orphan-cleanup heuristics consult — the numbers an
 * audit asks for. Nothing in the write path fails when they reset, which is
 * exactly why the guard has to live at this level: a real service against a
 * real database, reading the row as it stands.
 */
final class SecretAccountingTest extends AbstractVaultFunctionalTestCase
{
    use SecretRowTrait;

    /** Admin, so the gates pass and the tests are about the write scope only. */
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_permissions.csv';

    /**
     * The full sequence in one test on purpose: the three columns are lost by
     * one and the same omission, and asserting them apart would let a partial
     * fix look complete.
     */
    #[Test]
    public function storingANewValuePreservesTheAccountingAPriorRotationAndReadLeftBehind(): void
    {
        $vault = $this->getVaultService();
        $vault->store('accounting_preserved', 'first-value');

        // Reads first, so the counters start non-zero and a reset to the
        // column default is distinguishable from a value they were always
        // going to have.
        self::assertSame('first-value', $vault->retrieve('accounting_preserved'));
        self::assertSame('first-value', $vault->retrieve('accounting_preserved'));

        $vault->rotate('accounting_preserved', 'second-value', 'scheduled rotation');

        $before = $this->readSecretRow('accounting_preserved');
        self::assertSame(2, (int) $before['read_count'], 'Precondition: both reads were counted.');
        self::assertGreaterThan(0, (int) $before['last_read_at'], 'Precondition: the reads set a timestamp.');
        self::assertGreaterThan(0, (int) $before['last_rotated_at'], 'Precondition: the rotation was recorded.');

        $vault->store('accounting_preserved', 'third-value');

        $after = $this->readSecretRow('accounting_preserved');

        self::assertSame('third-value', $vault->retrieve('accounting_preserved'), 'The write itself must have landed.');
        self::assertSame(
            (int) $before['read_count'],
            (int) $after['read_count'],
            'Writing a value must not reset how often the secret was read.',
        );
        self::assertSame(
            (int) $before['last_read_at'],
            (int) $after['last_read_at'],
            'Writing a value must not reset when the secret was last read.',
        );
        self::assertSame(
            (int) $before['last_rotated_at'],
            (int) $after['last_rotated_at'],
            'Writing a value is not a rotation, and must not report the secret as never rotated.',
        );
    }

    /**
     * The counterpart. Carrying from `$existing` is only correct because there
     * is nothing to carry on a create — a fresh record starts at zero rather
     * than inheriting whatever a same-named predecessor accumulated.
     */
    #[Test]
    public function creatingASecretStartsItsAccountingAtZero(): void
    {
        $this->getVaultService()->store('accounting_fresh', 'the-plaintext');

        $row = $this->readSecretRow('accounting_fresh');

        self::assertSame(0, (int) $row['read_count']);
        self::assertSame(0, (int) $row['last_read_at']);
        self::assertSame(0, (int) $row['last_rotated_at']);
    }

    private function getVaultService(): VaultServiceInterface
    {
        return $this->get(VaultServiceInterface::class);
    }
}
