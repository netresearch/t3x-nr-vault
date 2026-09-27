<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\TCA;

use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;

/**
 * TYPO3 v14 removed `ctrl.searchFields` (#106972) and its TCA migration logs a
 * deprecation for every table that still sets it, so the base TCA must not set
 * it. The v13-only override that does is covered by the functional
 * SecretSearchScopeTest on a TYPO3 v13 run.
 */
#[CoversNothing]
final class SecretTcaSearchFieldsTest extends TestCase
{
    #[Test]
    public function baseTcaDoesNotSetSearchFields(): void
    {
        $tca = require \dirname(__DIR__, 3) . '/Configuration/TCA/tx_nrvault_secret.php';
        self::assertIsArray($tca);
        self::assertIsArray($tca['ctrl']);

        self::assertArrayNotHasKey('searchFields', $tca['ctrl']);
    }
}
