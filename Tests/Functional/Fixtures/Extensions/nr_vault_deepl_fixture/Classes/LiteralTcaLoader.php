<?php

/* Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\DeepL;

/**
 * Fixture-only cache: Core can compile TCA repeatedly in one PHP process.
 */
final class LiteralTcaLoader
{
    /** @var array<array-key, mixed> */
    private static array $configuration;

    /**
     * @return array<array-key, mixed>
     */
    public static function load(): array
    {
        self::$configuration ??= require_once \dirname(__DIR__, 6) . '/Documentation/Usage/_tca-deepl-config.php';

        return self::$configuration;
    }
}
