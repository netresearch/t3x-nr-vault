<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\ExtensionPoints;

use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use SensitiveParameter;

/**
 * A master-key provider written the way a consuming extension writes one:
 * against the published interface only. It holds a generated key in memory
 * and has no request-lifetime cache to clear.
 */
final class SampleMasterKeyProvider implements MasterKeyProviderInterface
{
    private string $key;

    public function __construct()
    {
        $this->key = sodium_crypto_secretbox_keygen();
    }

    public function getIdentifier(): string
    {
        return 'sample';
    }

    public function isAvailable(): bool
    {
        return true;
    }

    public function getMasterKey(): string
    {
        return $this->key;
    }

    public function storeMasterKey(#[SensitiveParameter] string $key): void
    {
        $this->key = $key;
    }

    public function generateMasterKey(): string
    {
        return sodium_crypto_secretbox_keygen();
    }

    public static function clearCachedKey(): void {}
}
