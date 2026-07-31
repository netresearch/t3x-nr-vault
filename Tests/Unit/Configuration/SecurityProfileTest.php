<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Configuration;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(SecurityProfile::class)]
final class SecurityProfileTest extends TestCase
{
    #[Test]
    public function standardIsNotHardened(): void
    {
        self::assertFalse(SecurityProfile::Standard->isHardened());
    }

    #[Test]
    public function hardenedIsHardened(): void
    {
        self::assertTrue(SecurityProfile::Hardened->isHardened());
    }

    #[Test]
    public function profilesAreBackedByStableConfigurationValues(): void
    {
        self::assertSame('standard', SecurityProfile::Standard->value);
        self::assertSame('hardened', SecurityProfile::Hardened->value);
    }

    #[Test]
    public function unknownValueIsNotAProfile(): void
    {
        self::assertNull(SecurityProfile::tryFrom('military-grade'));
    }
}
