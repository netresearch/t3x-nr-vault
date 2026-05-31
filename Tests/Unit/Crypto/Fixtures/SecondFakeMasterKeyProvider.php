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
 * Second test-only concrete provider whose cached raw key is 0xBB repeated;
 * used to prove cache slots are isolated per concrete class.
 */
final class SecondFakeMasterKeyProvider extends AbstractFakeMasterKeyProvider
{
    public function getIdentifier(): string
    {
        return 'fake-second';
    }

    protected function rawKeyByte(): string
    {
        return "\xBB";
    }
}
