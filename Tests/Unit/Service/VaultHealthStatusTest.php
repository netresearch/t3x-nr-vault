<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service;

use Netresearch\NrVault\Service\VaultHealthStatus;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * The status object is the whole boundary between the health probe and the
 * presentation layer, so what it can carry is a security property, not a
 * detail: four operational values, all of them named, and no free-form text
 * field an exception message could be poured into.
 */
#[CoversClass(VaultHealthStatus::class)]
final class VaultHealthStatusTest extends TestCase
{
    #[Test]
    public function exposesTheProbeResultAsReadOnlyData(): void
    {
        $status = new VaultHealthStatus(
            masterKeyAvailable: true,
            masterKeyProvider: 'file',
            encryptionWorking: true,
            hasIssues: false,
        );

        self::assertTrue($status->masterKeyAvailable);
        self::assertSame('file', $status->masterKeyProvider);
        self::assertTrue($status->encryptionWorking);
        self::assertFalse($status->hasIssues);
    }

    #[Test]
    public function carriesNothingBeyondTheFourProbeValues(): void
    {
        self::assertSame(
            ['masterKeyAvailable', 'masterKeyProvider', 'encryptionWorking', 'hasIssues'],
            array_keys(get_object_vars(new VaultHealthStatus(
                masterKeyAvailable: false,
                masterKeyProvider: '',
                encryptionWorking: false,
                hasIssues: true,
            ))),
        );
    }
}
