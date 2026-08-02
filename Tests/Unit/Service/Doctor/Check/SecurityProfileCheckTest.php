<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Service\Doctor\Check\SecurityProfileCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(SecurityProfileCheck::class)]
final class SecurityProfileCheckTest extends TestCase
{
    use DoctorFindingTrait;

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = $this->check(SecurityProfile::Standard, false);

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    #[Test]
    public function aValidProfileWithAConsistentOverrideFlagPassesEverything(): void
    {
        $findings = $this->check(SecurityProfile::Standard, false)
            ->run($this->doctorContext(SecurityProfile::Standard));

        self::assertSame(['profile.valid', 'profile.admin_override'], $this->findingIds($findings));
        foreach ($findings as $finding) {
            self::assertTrue($finding->isPass(), $finding->id . ': ' . $finding->summary);
        }
    }

    /**
     * `getSecurityProfile()` throws on an unknown value rather than degrading to
     * standard. That fail-closed behaviour is right, and this check is what turns
     * the resulting outage into a message an operator can act on.
     */
    #[Test]
    public function anUnknownProfileStringIsCritical(): void
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getSecurityProfile')
            ->willThrowException(ConfigurationException::invalidSecurityProfile('paranoid'));
        $configuration->method('isAdminOverrideDisabled')->willReturn(false);

        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            (new SecurityProfileCheck($configuration))->run($this->doctorContext(SecurityProfile::Standard)),
            'profile.valid',
        );

        self::assertStringContainsString('paranoid', $finding->risk);
    }

    /**
     * The dangerous mismatch: the flag is set, the configuration screen reads as
     * though the admin bypass were gone, and every admin still holds everything.
     */
    #[Test]
    public function disableAdminOverrideSetUnderTheStandardProfileIsAnInertFlagWarning(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(SecurityProfile::Standard, true)
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'profile.admin_override',
        );

        self::assertStringContainsString('no effect', $finding->summary);
        self::assertTrue($finding->details['disableAdminOverride']);
    }

    #[Test]
    public function theHardenedProfileWithoutTheFlagWarnsThatTheOverrideIsStillLive(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(SecurityProfile::Hardened, false)
                ->run($this->doctorContext(SecurityProfile::Hardened)),
            'profile.admin_override',
        );

        self::assertStringContainsString('still in place', $finding->summary);
        self::assertStringContainsString('break-glass', $finding->remediation);
    }

    #[Test]
    public function theHardenedProfileWithTheFlagPasses(): void
    {
        $finding = $this->findingById(
            $this->check(SecurityProfile::Hardened, true)
                ->run($this->doctorContext(SecurityProfile::Hardened)),
            'profile.admin_override',
        );

        self::assertTrue($finding->isPass(), $finding->summary);
    }

    /**
     * `--profile=hardened` on a standard installation must report the mismatch
     * the operator would get AFTER switching, which is the point of the dry run:
     * with the flag unset, hardening would leave the override live.
     */
    #[Test]
    public function theTargetProfileDecidesTheOverrideVerdictNotTheConfiguredOne(): void
    {
        $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(SecurityProfile::Standard, false)->run(
                $this->doctorContextTargeting(SecurityProfile::Hardened, SecurityProfile::Standard),
            ),
            'profile.admin_override',
        );
    }

    private function check(SecurityProfile $profile, bool $overrideDisabled): SecurityProfileCheck
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getSecurityProfile')->willReturn($profile);
        $configuration->method('isAdminOverrideDisabled')->willReturn($overrideDisabled);

        return new SecurityProfileCheck($configuration);
    }
}
