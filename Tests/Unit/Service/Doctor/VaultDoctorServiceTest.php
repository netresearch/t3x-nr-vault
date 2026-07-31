<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor;

use ArrayIterator;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Exception\ConfigurationException;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Service\Doctor\ReadinessCheckInterface;
use Netresearch\NrVault\Service\Doctor\VaultDoctorService;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Log\NullLogger;
use RuntimeException;

#[CoversClass(VaultDoctorService::class)]
final class VaultDoctorServiceTest extends TestCase
{
    #[Test]
    public function collectsFindingsFromEveryApplicableCheck(): void
    {
        $report = $this->service(
            SecurityProfile::Standard,
            $this->check('a', [Finding::pass('a.one', 'ok')]),
            $this->check('b', [Finding::pass('b.one', 'ok'), Finding::pass('b.two', 'ok')]),
        )->run();

        self::assertSame(3, $report->totalControls());
        self::assertSame(3, $report->passedControls());
        self::assertSame(0, $report->exitCode());
        self::assertTrue($report->isAuditReady());
    }

    /**
     * A check that declares itself inapplicable must not be counted at all —
     * neither as a pass nor in the denominator. Counting it as passed would
     * inflate "N of M controls passed" with controls that were never evaluated.
     */
    #[Test]
    public function skipsChecksThatDoNotApplyToTheTargetProfile(): void
    {
        $applicable = $this->check('a', [Finding::pass('a.one', 'ok')]);
        $inapplicable = $this->check('b', [Finding::pass('b.one', 'ok')], appliesTo: false);

        $report = $this->service(SecurityProfile::Standard, $applicable, $inapplicable)->run();

        self::assertSame(1, $report->totalControls());
        self::assertSame(['a.one'], array_column($report->toArray()['findings'], 'id'));
    }

    /**
     * The load-bearing containment property: a crashing check must cost its own
     * area, never the rest of the report — and it must be LOUDER than a failing
     * check, because an operator reads silence as a pass.
     */
    #[Test]
    public function aCrashingCheckBecomesACriticalFindingAndTheRunContinues(): void
    {
        $crashing = self::createStub(ReadinessCheckInterface::class);
        $crashing->method('getId')->willReturn('exploding');
        $crashing->method('appliesTo')->willReturn(true);
        $crashing->method('run')->willThrowException(new RuntimeException('sink registry unreachable'));

        $report = $this->service(
            SecurityProfile::Standard,
            $crashing,
            $this->check('survivor', [Finding::pass('survivor.one', 'ok')]),
        )->run();

        self::assertSame(2, $report->totalControls());
        self::assertSame(2, $report->exitCode());

        $crash = $report->findingsOfSeverity(FindingSeverity::Critical)[0];
        self::assertSame('check.crashed', $crash->id);
        self::assertStringContainsString('exploding', $crash->summary);
        self::assertStringContainsString('sink registry unreachable', $crash->summary);
        self::assertSame('exploding', $crash->details['check']);

        // The healthy check still reported.
        self::assertCount(1, $report->findingsOfSeverity(FindingSeverity::Pass));
    }

    #[Test]
    public function warningsOnlyAggregateToExitCodeOne(): void
    {
        $report = $this->service(
            SecurityProfile::Standard,
            $this->check('a', [
                Finding::pass('a.one', 'ok'),
                Finding::warning('a.two', 'meh', 'risk', 'fix'),
            ]),
        )->run();

        self::assertSame(1, $report->exitCode());
        self::assertSame(FindingSeverity::Warning, $report->highestSeverity());
        self::assertFalse($report->isAuditReady());
    }

    /**
     * Worst-severity-wins: a long list of passes must never average a critical
     * finding away, or the gate becomes a scoreboard instead of a gate.
     */
    #[Test]
    public function oneCriticalOutweighsAnyNumberOfPasses(): void
    {
        $findings = [Finding::critical('a.bad', 'broken', 'risk', 'fix')];
        for ($i = 0; $i < 20; $i++) {
            $findings[] = Finding::pass('a.ok' . $i, 'ok');
        }

        $report = $this->service(SecurityProfile::Standard, $this->check('a', $findings))->run();

        self::assertSame(2, $report->exitCode());
        self::assertSame(20, $report->passedControls());
        self::assertSame(21, $report->totalControls());
    }

    #[Test]
    public function withoutATargetProfileTheConfiguredProfileIsAsserted(): void
    {
        $report = $this->service(SecurityProfile::Hardened, $this->check('a', []))->run();

        self::assertSame(SecurityProfile::Hardened, $report->context->profile);
        self::assertFalse($report->context->isProfileOverridden());
    }

    /**
     * `--profile=hardened` on a standard installation must change what is
     * asserted while still reporting what is actually configured — otherwise a
     * passing dry run reads as proof that hardening is already live.
     */
    #[Test]
    public function anExplicitTargetProfileIsAssertedAndTheConfiguredOneIsRetained(): void
    {
        $report = $this->service(SecurityProfile::Standard, $this->check('a', []))
            ->run(SecurityProfile::Hardened);

        self::assertSame(SecurityProfile::Hardened, $report->context->profile);
        self::assertSame(SecurityProfile::Standard, $report->context->configuredProfile);
        self::assertTrue($report->context->isProfileOverridden());
    }

    /**
     * An unknown profile string makes `getSecurityProfile()` throw. The run must
     * still produce a report — the invalid value is itself reported by
     * SecurityProfileCheck, and burying that under hardened-only findings would
     * hide the actual problem.
     */
    #[Test]
    public function anUnresolvableConfiguredProfileFallsBackToStandardWithoutCrashing(): void
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getSecurityProfile')
            ->willThrowException(ConfigurationException::invalidSecurityProfile('paranoid'));

        $service = new VaultDoctorService(
            new ArrayIterator([$this->check('a', [Finding::pass('a.one', 'ok')])]),
            $configuration,
            new NullLogger(),
        );

        $report = $service->run();

        self::assertSame(SecurityProfile::Standard, $report->context->profile);
        self::assertSame(SecurityProfile::Standard, $report->context->configuredProfile);
        self::assertSame(0, $report->exitCode());
    }

    /**
     * Checks receive the target profile, not the configured one — that is what
     * makes the `--profile` dry run meaningful.
     */
    #[Test]
    public function checksAreAskedAboutTheTargetProfileNotTheConfiguredOne(): void
    {
        $check = $this->createMock(ReadinessCheckInterface::class);
        $check->method('getId')->willReturn('a');
        $check->expects(self::once())
            ->method('appliesTo')
            ->with(SecurityProfile::Hardened)
            ->willReturn(true);
        $check->method('run')->willReturnCallback(
            static function (DoctorContext $context): array {
                self::assertTrue($context->isHardened());
                self::assertSame(SecurityProfile::Standard, $context->configuredProfile);

                return [];
            },
        );

        $this->service(SecurityProfile::Standard, $check)->run(SecurityProfile::Hardened);
    }

    private function service(
        SecurityProfile $configuredProfile,
        ReadinessCheckInterface ...$checks,
    ): VaultDoctorService {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getSecurityProfile')->willReturn($configuredProfile);

        return new VaultDoctorService(new ArrayIterator($checks), $configuration, new NullLogger());
    }

    /**
     * @param list<Finding> $findings
     */
    private function check(string $id, array $findings, bool $appliesTo = true): ReadinessCheckInterface
    {
        $check = self::createStub(ReadinessCheckInterface::class);
        $check->method('getId')->willReturn($id);
        $check->method('appliesTo')->willReturn($appliesTo);
        $check->method('run')->willReturn($findings);

        return $check;
    }
}
