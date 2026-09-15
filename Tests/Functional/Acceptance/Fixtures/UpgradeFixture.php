<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Acceptance\Fixtures;

/**
 * What the v0.16.0 upgrade data sets were sealed with, shared by the generator
 * (`UpgradeFixtureGenerator.php.dist`) and UpgradeFromPreviousReleaseTest.
 *
 * The master key is derived from a fixed label at runtime, so the committed
 * ciphertext can be opened by the test and no key literal sits in the
 * repository. Every plaintext is synthetic.
 */
final class UpgradeFixture
{
    public const MASTER_KEY_LABEL = 'nr-vault acceptance upgrade fixture master key';

    public const READER_GROUP = 10;

    /** Secrets in `upgrade_long_lived_v0.16.0.csv`, by identifier. */
    public const LONG_LIVED_PLAINTEXTS = [
        'legacy_v1_reader_tier' => 'legacy-v1-plaintext-sealed-before-0-9-0',
        'modern_reader_tier' => 'modern-plaintext-sealed-by-0-16-0',
        'modern_owned_by_reader' => 'owned-plaintext-sealed-by-0-16-0',
        'modern_rotated' => 'rotated-plaintext-sealed-by-0-16-0',
    ];

    /** Secrets in `upgrade_plain_v0.16.0.csv`, by identifier. */
    public const PLAIN_PLAINTEXTS = [
        'modern_reader_tier' => 'modern-plaintext-sealed-by-0-16-0',
        'modern_owned_by_reader' => 'owned-plaintext-sealed-by-0-16-0',
        'modern_rotated' => 'rotated-plaintext-sealed-by-0-16-0',
    ];

    public static function masterKey(): string
    {
        return hash('sha256', self::MASTER_KEY_LABEL, true);
    }
}
