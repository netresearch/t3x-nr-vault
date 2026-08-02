<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Controller;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Controller\SecurityStatusProvider;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\DoctorReport;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\VaultDoctorServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

#[CoversClass(SecurityStatusProvider::class)]
final class SecurityStatusProviderTest extends TestCase
{
    #[Test]
    public function exposesTheProfileBadgeAndPassRatio(): void
    {
        $view = $this->provider(
            $this->report([
                Finding::pass('a.one', 'ok'),
                Finding::pass('a.two', 'ok'),
                Finding::warning('a.three', 'meh', 'risk', 'fix'),
            ], SecurityProfile::Hardened),
            granted: true,
        )->forView();

        self::assertTrue($view['available']);
        self::assertSame('hardened', $view['profile']);
        self::assertSame(2, $view['passed']);
        self::assertSame(3, $view['total']);
        self::assertFalse($view['auditReady']);
        self::assertSame('warning', $view['severity']);
        self::assertSame('warning', $view['context']);
        self::assertSame(0, $view['criticalCount']);
        self::assertSame(1, $view['warningCount']);
    }

    /**
     * The gate this class exists for: the finding list names the installation's
     * concrete weak points and the file to edit, so it belongs to the permission
     * that already governs vault configuration.
     */
    #[Test]
    public function findingDetailIsWithheldWithoutTheVaultConfigurePermission(): void
    {
        $view = $this->provider(
            $this->report([
                Finding::pass('a.one', 'ok'),
                Finding::critical('audit.external_sink', 'no sink', 'no evidence', 'enable a sink'),
            ]),
            granted: false,
        )->forView();

        self::assertFalse($view['detailed']);
        self::assertSame([], $view['findings']);

        // The counts stay visible: knowing THAT something is open is enough to
        // escalate, and hiding it would leave the panel silently reassuring.
        self::assertSame(1, $view['criticalCount']);
        self::assertSame(1, $view['passed']);
        self::assertSame(2, $view['total']);
        self::assertFalse($view['auditReady']);
    }

    #[Test]
    public function findingDetailIsShownWithTheVaultConfigurePermission(): void
    {
        $view = $this->provider(
            $this->report([
                Finding::pass('a.one', 'ok'),
                Finding::critical(
                    id: 'audit.external_sink',
                    summary: 'no sink',
                    risk: 'no external evidence',
                    remediation: 'enable auditSinkFileEnabled',
                    docsUrl: 'https://example.org/docs',
                ),
                Finding::warning('cli.access', 'cli on', 'shell reads secrets', 'disable it'),
            ]),
            granted: true,
        )->forView();

        self::assertTrue($view['detailed']);
        self::assertSame(
            ['audit.external_sink', 'cli.access'],
            array_column($view['findings'], 'id'),
        );

        $first = $view['findings'][0];
        self::assertSame('critical', $first['severity']);
        self::assertSame('danger', $first['context']);
        self::assertSame('no external evidence', $first['risk']);
        self::assertSame('enable auditSinkFileEnabled', $first['remediation']);
        self::assertSame('https://example.org/docs', $first['docsUrl']);
    }

    #[Test]
    public function thePermissionCheckedIsVaultConfigure(): void
    {
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->expects(self::once())
            ->method('isGranted')
            ->with(VaultPermission::VaultConfigure)
            ->willReturn(true);

        $doctor = self::createStub(VaultDoctorServiceInterface::class);
        $doctor->method('run')->willReturn($this->report([Finding::pass('a.one', 'ok')]));

        (new SecurityStatusProvider($doctor, $accessControl))->forView();
    }

    #[Test]
    public function aCleanReportIsReportedAsAuditReady(): void
    {
        $view = $this->provider($this->report([Finding::pass('a.one', 'ok')]), granted: true)->forView();

        self::assertTrue($view['auditReady']);
        self::assertSame('success', $view['context']);
        self::assertSame([], $view['findings']);
    }

    /**
     * "We could not check" must not render as "there is nothing to report" — the
     * panel returns a complete shape flagged unavailable so the partial shows a
     * warning rather than a blank box.
     */
    #[Test]
    public function aDoctorThatCannotRunYieldsAnUnavailableShapeWithEveryKeyPresent(): void
    {
        $doctor = self::createStub(VaultDoctorServiceInterface::class);
        $doctor->method('run')->willThrowException(new RuntimeException('container is broken'));

        $accessControl = self::createStub(AccessControlServiceInterface::class);
        $accessControl->method('isGranted')->willReturn(true);

        $view = (new SecurityStatusProvider($doctor, $accessControl))->forView();

        self::assertFalse($view['available']);
        self::assertFalse($view['auditReady']);
        self::assertFalse($view['detailed']);
        self::assertSame('warning', $view['context']);
        self::assertSame(
            [
                'available', 'profile', 'auditReady', 'severity', 'context',
                'passed', 'total', 'criticalCount', 'warningCount', 'detailed', 'findings',
            ],
            array_keys($view),
        );
    }

    private function provider(DoctorReport $report, bool $granted): SecurityStatusProvider
    {
        $doctor = self::createStub(VaultDoctorServiceInterface::class);
        $doctor->method('run')->willReturn($report);

        $accessControl = self::createStub(AccessControlServiceInterface::class);
        $accessControl->method('isGranted')->willReturn($granted);

        return new SecurityStatusProvider($doctor, $accessControl);
    }

    /**
     * @param list<Finding> $findings
     */
    private function report(
        array $findings,
        SecurityProfile $profile = SecurityProfile::Standard,
    ): DoctorReport {
        return new DoctorReport(
            context: DoctorContext::forConfiguredProfile($profile),
            findings: $findings,
        );
    }
}
