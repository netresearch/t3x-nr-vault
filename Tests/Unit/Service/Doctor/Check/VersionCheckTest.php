<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\Check\VersionCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Information\Typo3Version;

/**
 * A unit process has no package manager, so `ExtensionManagementUtility::extPath()`
 * cannot resolve and `ext_emconf.php` is unreadable here. That is exactly the
 * degraded path this test asserts: version metadata is the one area where being
 * unable to look must warn rather than crash, because a `check.crashed` critical
 * over unreadable provenance data would block a deployment for nothing.
 *
 * The happy path — real emconf, real core version, both controls passing — is
 * covered by `Tests/Functional/Command/VaultDoctorCommandTest`, where a real
 * bootstrap exists. The range comparison itself is covered exhaustively by
 * {@see Typo3VersionRangeTest}.
 */
#[CoversClass(VersionCheck::class)]
final class VersionCheckTest extends TestCase
{
    use DoctorFindingTrait;

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = new VersionCheck(new Typo3Version());

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    #[Test]
    public function emitsBothVersionControls(): void
    {
        $findings = (new VersionCheck(new Typo3Version()))
            ->run($this->doctorContext(SecurityProfile::Standard));

        self::assertSame(
            ['version.extension', 'version.typo3_supported'],
            $this->findingIds($findings),
        );
    }

    #[Test]
    public function anUnreadableEmConfWarnsRatherThanCrashing(): void
    {
        $findings = (new VersionCheck(new Typo3Version()))
            ->run($this->doctorContext(SecurityProfile::Hardened));

        $this->assertFindingSeverity(FindingSeverity::Warning, $findings, 'version.extension');
        $this->assertFindingSeverity(FindingSeverity::Warning, $findings, 'version.typo3_supported');
    }

    /**
     * Even in the degraded path the running core version has to reach the report:
     * it is the provenance line a reader of a three-month-old report needs.
     */
    #[Test]
    public function theRunningCoreVersionIsReportedEvenWithoutEmConf(): void
    {
        $finding = $this->findingById(
            (new VersionCheck(new Typo3Version()))->run($this->doctorContext(SecurityProfile::Standard)),
            'version.typo3_supported',
        );

        self::assertSame((new Typo3Version())->getVersion(), $finding->details['typo3Version']);
    }
}
