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

use Netresearch\NrVault\Crypto\AbstractMasterKeyProvider;
use SensitiveParameter;

/**
 * Shared skeleton for the test-only providers that exercise the
 * request-lifetime caching contract in {@see AbstractMasterKeyProvider}
 * (ADR-020). Concrete subclasses supply only their distinguishing identifier
 * and the single raw-key byte; the caching behaviour under test lives entirely
 * in the production base class.
 *
 * `loadRawKey()` counts its invocations via {@see $loadCount} so a test can
 * assert the raw key is loaded at most once while cached.
 */
abstract class AbstractFakeMasterKeyProvider extends AbstractMasterKeyProvider
{
    public int $loadCount = 0;

    public function isAvailable(): bool
    {
        return true;
    }

    public function storeMasterKey(#[SensitiveParameter] string $key): void {}

    public function generateMasterKey(): string
    {
        return str_repeat($this->rawKeyByte(), 32);
    }

    protected function loadRawKey(): string
    {
        ++$this->loadCount;

        return str_repeat($this->rawKeyByte(), 32);
    }

    /**
     * The single byte repeated 32 times to form this provider's raw key.
     * Distinct per concrete subclass so cache isolation is observable.
     */
    abstract protected function rawKeyByte(): string;
}
