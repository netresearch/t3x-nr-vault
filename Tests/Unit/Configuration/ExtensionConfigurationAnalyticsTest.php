<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Configuration;

use Netresearch\NrVault\Configuration\ExtensionConfiguration;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration as Typo3ExtensionConfiguration;

#[CoversClass(ExtensionConfiguration::class)]
#[AllowMockObjectsWithoutExpectations]
final class ExtensionConfigurationAnalyticsTest extends TestCase
{
    #[Test]
    public function returnsConfiguredThresholds(): void
    {
        $config = $this->makeConfig([
            'staleNeverReadDays' => '15',
            'staleNotReadDays' => '45',
            'staleNeverRotatedDays' => '200',
        ]);

        self::assertSame(15, $config->getStaleNeverReadDays());
        self::assertSame(45, $config->getStaleNotReadDays());
        self::assertSame(200, $config->getStaleNeverRotatedDays());
    }

    #[Test]
    public function fallsBackToDefaultsWhenAbsentOrNonNumeric(): void
    {
        $config = $this->makeConfig(['staleNeverReadDays' => 'oops']);

        self::assertSame(30, $config->getStaleNeverReadDays());
        self::assertSame(90, $config->getStaleNotReadDays());
        self::assertSame(180, $config->getStaleNeverRotatedDays());
    }

    /**
     * @param array<string, mixed> $values
     */
    private function makeConfig(array $values): ExtensionConfiguration
    {
        $typo3Config = $this->createMock(Typo3ExtensionConfiguration::class);
        $typo3Config->method('get')->with('nr_vault')->willReturn($values);

        return new ExtensionConfiguration($typo3Config);
    }
}
