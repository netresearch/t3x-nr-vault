<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Crypto;

use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use SensitiveParameter;

/**
 * A master-key source that wraps the configured provider and counts how often
 * the key is requested, so the test sees the vault's crypto path use it.
 */
final class RecordingMasterKeyProvider implements MasterKeyProviderInterface
{
    public int $keyRequests = 0;

    public function __construct(
        private readonly MasterKeyProviderInterface $inner,
    ) {}

    public function getIdentifier(): string
    {
        return $this->inner->getIdentifier();
    }

    public function isAvailable(): bool
    {
        return $this->inner->isAvailable();
    }

    public function getMasterKey(): string
    {
        ++$this->keyRequests;

        return $this->inner->getMasterKey();
    }

    public function storeMasterKey(#[SensitiveParameter] string $key): void
    {
        $this->inner->storeMasterKey($key);
    }

    public function generateMasterKey(): string
    {
        return $this->inner->generateMasterKey();
    }

    /**
     * Holds no key of its own; the wrapped provider's cache is cleared through
     * its own class.
     */
    public static function clearCachedKey(): void {}
}
