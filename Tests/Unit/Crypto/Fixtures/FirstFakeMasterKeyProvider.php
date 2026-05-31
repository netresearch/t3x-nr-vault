<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Crypto\Fixtures;

/**
 * Test-only concrete provider whose cached raw key is 0xAA repeated.
 */
final class FirstFakeMasterKeyProvider extends AbstractFakeMasterKeyProvider
{
    public function getIdentifier(): string
    {
        return 'fake-first';
    }

    protected function rawKeyByte(): string
    {
        return "\xAA";
    }
}
