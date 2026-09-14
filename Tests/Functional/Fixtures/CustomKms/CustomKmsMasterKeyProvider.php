<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\CustomKms;

use Netresearch\NrVault\Crypto\AbstractMasterKeyProvider;
use SensitiveParameter;

/**
 * The master key provider a consuming extension would ship.
 *
 * It stands in for a cloud KMS or HSM bridge: it claims an identifier no
 * shipped provider uses, and it is reached only because
 * `EXT:vault_custom_provider` tags it `nr_vault.master_key_provider` in its own
 * `Configuration/Services.yaml`. Nothing in nr-vault names this class.
 *
 * It extends {@see AbstractMasterKeyProvider} on purpose — that is the
 * documented route for a custom provider, and inheriting it is what proves the
 * ADR-020 request-lifetime caching and wiping contract is reusable from
 * outside the package rather than private to the built-in providers.
 *
 * The key is derived rather than stored, so the fixture carries no key literal
 * while still being deterministic enough for the test to compare against.
 */
final class CustomKmsMasterKeyProvider extends AbstractMasterKeyProvider
{
    public const IDENTIFIER = 'acme_kms';

    private const KEY_LENGTH = 32;

    /**
     * Obviously synthetic input for the derivation below. Not a secret, and
     * never a key by itself.
     */
    private const DERIVATION_SOURCE = 'nr-vault functional fixture: pretend KMS';

    private const DERIVATION_INFO = 'nr-vault-custom-kms-fixture';

    /**
     * The key this provider hands out, for the test to compare against.
     */
    public static function expectedKey(): string
    {
        return hash_hkdf('sha256', self::DERIVATION_SOURCE, self::KEY_LENGTH, self::DERIVATION_INFO);
    }

    public function getIdentifier(): string
    {
        return self::IDENTIFIER;
    }

    public function isAvailable(): bool
    {
        return true;
    }

    public function storeMasterKey(#[SensitiveParameter] string $key): void {}

    public function generateMasterKey(): string
    {
        return random_bytes(self::KEY_LENGTH);
    }

    protected function loadRawKey(): string
    {
        return self::expectedKey();
    }
}
