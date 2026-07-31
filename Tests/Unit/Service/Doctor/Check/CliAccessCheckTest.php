<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\Check\CliAccessCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(CliAccessCheck::class)]
final class CliAccessCheckTest extends TestCase
{
    use DoctorFindingTrait;

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = $this->check(false);

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    /**
     * Off is the default and the safe state — and there is then no group scope to
     * assess, so only one control is emitted rather than a vacuous pass.
     */
    #[Test]
    public function disabledCliAccessEmitsOnlyThePassingAccessControl(): void
    {
        $findings = $this->check(false)->run($this->doctorContext(SecurityProfile::Hardened));

        self::assertSame(['cli.access'], $this->findingIds($findings));
        self::assertTrue($findings[0]->isPass());
    }

    /**
     * A deployment pipeline that stores credentials needs this switch, so calling
     * it a defect under the standard profile would be noise.
     */
    #[Test]
    public function enabledCliAccessPassesUnderTheStandardProfile(): void
    {
        $finding = $this->findingById(
            $this->check(true, [42])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.access',
        );

        self::assertTrue($finding->isPass());
    }

    #[Test]
    public function enabledCliAccessIsAWarningUnderTheHardenedProfile(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(true, [42])->run($this->doctorContext(SecurityProfile::Hardened)),
            'cli.access',
        );

        self::assertStringContainsString('TechnicalActorContext', $finding->remediation);
    }

    #[Test]
    public function anEmptyGroupListWhileCliAccessIsOnIsAWarning(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(true, [])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.access_groups',
        );

        self::assertSame(0, $finding->details['cliAccessGroupCount']);
    }

    /**
     * `getCliAccessGroups()` maps unparseable configuration values to 0, and group
     * uid 0 does not exist — counting those would report a scoped grant where the
     * configuration actually holds junk.
     */
    #[Test]
    public function groupUidZeroDoesNotCountAsAScopedGrant(): void
    {
        $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(true, [0, 0])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.access_groups',
        );
    }

    #[Test]
    public function aScopedGroupListPasses(): void
    {
        $finding = $this->findingById(
            $this->check(true, [3, 7])->run($this->doctorContext(SecurityProfile::Standard)),
            'cli.access_groups',
        );

        self::assertTrue($finding->isPass());
        self::assertSame(2, $finding->details['cliAccessGroupCount']);
    }

    /**
     * @param list<int> $groups
     */
    private function check(bool $allowed, array $groups = []): CliAccessCheck
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('isCliAccessAllowed')->willReturn($allowed);
        $configuration->method('getCliAccessGroups')->willReturn($groups);

        return new CliAccessCheck($configuration);
    }
}
