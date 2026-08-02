<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\Check\EnvironmentCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use Netresearch\NrVault\Tests\Unit\Traits\EnvironmentSandboxTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(EnvironmentCheck::class)]
final class EnvironmentCheckTest extends TestCase
{
    use DoctorFindingTrait;
    use EnvironmentSandboxTrait;

    protected function setUp(): void
    {
        parent::setUp();

        // Environment is a static singleton the unit bootstrap leaves
        // uninitialised, and getContext() throws until something initialises it.
        $this->setUpEnvironmentSandbox('Testing');

        // The check reads $TYPO3_CONF_VARS[BE] directly; backupGlobals is on for
        // the unit suite, so a per-test value cannot leak into a sibling.
        $GLOBALS['TYPO3_CONF_VARS']['BE'] = [];
    }

    protected function tearDown(): void
    {
        $this->tearDownEnvironmentSandbox();

        parent::tearDown();
    }

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = new EnvironmentCheck();

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    /**
     * Exactly two controls, and no more: everything else worth knowing about the
     * host (real TLS termination, HSTS, proxy behaviour) needs a view of the edge
     * that a CLI process behind it does not have, and a guessed finding is one an
     * operator learns to ignore.
     */
    #[Test]
    public function emitsOnlyTheTwoControlsItCanCheckReliably(): void
    {
        $findings = (new EnvironmentCheck())->run($this->doctorContext(SecurityProfile::Standard));

        self::assertSame(
            ['environment.production_context', 'environment.backend_lock_ssl'],
            $this->findingIds($findings),
        );
    }

    /**
     * A non-production context is the normal state of a developer machine, so
     * reporting it outside the hardened profile would be noise.
     */
    #[Test]
    public function aNonProductionContextPassesUnderTheStandardProfile(): void
    {
        $finding = $this->findingById(
            (new EnvironmentCheck())->run($this->doctorContext(SecurityProfile::Standard)),
            'environment.production_context',
        );

        self::assertTrue($finding->isPass());
        self::assertSame('Testing', $finding->details['applicationContext']);
    }

    #[Test]
    public function aNonProductionContextIsAWarningUnderTheHardenedProfile(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            (new EnvironmentCheck())->run($this->doctorContext(SecurityProfile::Hardened)),
            'environment.production_context',
        );

        self::assertStringContainsString('TYPO3_CONTEXT=Production', $finding->remediation);
        self::assertSame('Testing', $finding->details['applicationContext']);
    }

    #[Test]
    public function aProductionContextPassesUnderTheHardenedProfile(): void
    {
        $this->setEnvironmentApplicationContext('Production');

        $finding = $this->findingById(
            (new EnvironmentCheck())->run($this->doctorContext(SecurityProfile::Hardened)),
            'environment.production_context',
        );

        self::assertTrue($finding->isPass());
        self::assertSame('Production', $finding->details['applicationContext']);
    }

    /**
     * Profile-independent: the reveal endpoint returns secret plaintext to a
     * browser, so an unencrypted backend session leaks it whatever profile is set.
     */
    #[Test]
    public function anUnsetLockSslIsAWarningUnderEitherProfile(): void
    {
        foreach (SecurityProfile::cases() as $profile) {
            $this->assertFindingSeverity(
                FindingSeverity::Warning,
                (new EnvironmentCheck())->run($this->doctorContext($profile)),
                'environment.backend_lock_ssl',
            );
        }
    }

    #[Test]
    public function anEnabledLockSslPasses(): void
    {
        $GLOBALS['TYPO3_CONF_VARS']['BE']['lockSSL'] = true;

        $finding = $this->findingById(
            (new EnvironmentCheck())->run($this->doctorContext(SecurityProfile::Hardened)),
            'environment.backend_lock_ssl',
        );

        self::assertTrue($finding->isPass());
    }

    /**
     * A missing or unexpectedly-shaped configuration section must read as "not
     * configured" — the direction that produces the finding rather than hiding it.
     */
    #[Test]
    public function anAbsentBackendConfigurationSectionReadsAsNotConfigured(): void
    {
        unset($GLOBALS['TYPO3_CONF_VARS']);

        $this->assertFindingSeverity(
            FindingSeverity::Warning,
            (new EnvironmentCheck())->run($this->doctorContext(SecurityProfile::Standard)),
            'environment.backend_lock_ssl',
        );
    }
}
