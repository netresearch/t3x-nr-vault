<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Netresearch\NrVault\Command\VaultDoctorCommand;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\DoctorReport;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\VaultDoctorServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The exit code is the contract, so it carries most of the assertions here: this
 * command is meant to be the last step of a deployment pipeline, where nothing
 * reads the prose.
 */
#[CoversClass(VaultDoctorCommand::class)]
final class VaultDoctorCommandTest extends TestCase
{
    #[Test]
    public function aCleanReportExitsZero(): void
    {
        $tester = $this->tester($this->report([Finding::pass('a.ok', 'all good')]));

        self::assertSame(0, $tester->execute([]));
        self::assertStringContainsString('audit-ready', $tester->getDisplay());
    }

    #[Test]
    public function warningsOnlyExitOne(): void
    {
        $tester = $this->tester($this->report([
            Finding::pass('a.ok', 'all good'),
            Finding::warning('a.warn', 'CLI access is on', 'shell reads secrets', 'disable allowCliAccess'),
        ]));

        self::assertSame(1, $tester->execute([]));

        $display = $tester->getDisplay();
        self::assertStringContainsString('a.warn', $display);
        self::assertStringContainsString('1 warning(s)', $display);
    }

    #[Test]
    public function anyCriticalExitsTwo(): void
    {
        $tester = $this->tester($this->report([
            Finding::pass('a.ok', 'all good'),
            Finding::critical('audit.external_sink', 'no sink', 'no evidence', 'enable a sink'),
        ]));

        self::assertSame(2, $tester->execute([]));
        self::assertStringContainsString('NOT audit-ready', $tester->getDisplay());
    }

    /**
     * Remediation text is a shell command an operator copies, so it must reach the
     * output verbatim rather than being wrapped into a table cell.
     */
    #[Test]
    public function theTextReportCarriesTheRiskRemediationAndDocsLink(): void
    {
        $tester = $this->tester($this->report([
            Finding::critical(
                id: 'audit.external_sink',
                summary: 'no external audit sink',
                risk: 'the trail exists only in the database it protects',
                remediation: 'enable auditSinkFileEnabled, then run vendor/bin/typo3 vault:audit-anchor',
                docsUrl: 'https://example.org/docs/sinks',
            ),
        ]));

        $tester->execute([]);
        $display = $tester->getDisplay();

        self::assertStringContainsString('the trail exists only in the database it protects', $display);
        self::assertStringContainsString('vault:audit-anchor', $display);
        self::assertStringContainsString('https://example.org/docs/sinks', $display);
    }

    /**
     * The JSON contract: stable ids, the summary block a gate reads, and the exit
     * code inside the payload so a wrapper that swallows the process code can
     * still act on it.
     */
    #[Test]
    public function jsonOutputIsStableAndMachineReadable(): void
    {
        $tester = $this->tester($this->report(
            [
                Finding::pass('provider.configured', 'file provider configured'),
                Finding::critical(
                    id: 'audit.external_sink',
                    summary: 'no sink',
                    risk: 'no evidence',
                    remediation: 'enable a sink',
                    docsUrl: 'https://example.org/docs',
                    details: ['reasonCode' => 'NO_EXTERNAL_SINK'],
                ),
            ],
            profile: SecurityProfile::Hardened,
        ));

        self::assertSame(2, $tester->execute(['--format' => 'json']));

        $payload = $this->decode($tester->getDisplay());

        self::assertSame('hardened', $payload['profile']);
        self::assertSame(2, $payload['exitCode']);
        self::assertFalse($payload['auditReady']);
        self::assertSame(['total' => 2, 'pass' => 1, 'warning' => 0, 'critical' => 1], $payload['summary']);

        $findings = $payload['findings'];
        self::assertIsArray($findings);
        self::assertSame(['provider.configured', 'audit.external_sink'], array_column($findings, 'id'));

        $sinkFinding = $findings[1];
        self::assertIsArray($sinkFinding);
        self::assertIsArray($sinkFinding['details']);
        self::assertSame('NO_EXTERNAL_SINK', $sinkFinding['details']['reasonCode']);
    }

    #[Test]
    public function jsonOutputOfACleanReportStillExitsZero(): void
    {
        $tester = $this->tester($this->report([Finding::pass('a.ok', 'all good')]));

        self::assertSame(0, $tester->execute(['--format' => 'json']));

        $payload = $this->decode($tester->getDisplay());
        self::assertTrue($payload['auditReady']);
        self::assertSame(0, $payload['exitCode']);
    }

    #[Test]
    public function theProfileOptionSelectsTheTargetProfile(): void
    {
        $doctor = $this->createMock(VaultDoctorServiceInterface::class);
        $doctor->expects(self::once())
            ->method('run')
            ->with(SecurityProfile::Hardened)
            ->willReturn($this->report([Finding::pass('a.ok', 'ok')]));

        $tester = new CommandTester(new VaultDoctorCommand($doctor));

        self::assertSame(0, $tester->execute(['--profile' => 'hardened']));
    }

    #[Test]
    public function withoutTheProfileOptionTheConfiguredProfileIsUsed(): void
    {
        $doctor = $this->createMock(VaultDoctorServiceInterface::class);
        $doctor->expects(self::once())
            ->method('run')
            ->with(null)
            ->willReturn($this->report([Finding::pass('a.ok', 'ok')]));

        $tester = new CommandTester(new VaultDoctorCommand($doctor));
        $tester->execute([]);
    }

    /**
     * A dry run against another profile must state which profile is actually
     * configured, or a passing `--profile=hardened` reads as proof that hardening
     * is already live.
     */
    #[Test]
    public function anOverriddenProfileIsMarkedAsNotChangingConfiguration(): void
    {
        $tester = $this->tester(new DoctorReport(
            context: new DoctorContext(
                profile: SecurityProfile::Hardened,
                configuredProfile: SecurityProfile::Standard,
            ),
            findings: [Finding::pass('a.ok', 'ok')],
        ));

        $tester->execute([]);
        $display = $tester->getDisplay();

        self::assertStringContainsString('hardened', $display);
        self::assertStringContainsString('NOT changed', $display);
    }

    /**
     * An unusable `--profile` value must not be readable as "checked and fine",
     * so it lands on the same non-zero code as a critical finding.
     */
    #[Test]
    public function anUnknownProfileValueIsRejectedWithoutRunningAnyCheck(): void
    {
        $doctor = $this->createMock(VaultDoctorServiceInterface::class);
        $doctor->expects(self::never())->method('run');

        $tester = new CommandTester(new VaultDoctorCommand($doctor));
        // INVALID is 2, the same code a critical finding produces: a gate handed
        // an unusable profile value must not be readable as "checked and fine".
        self::assertSame(Command::INVALID, $tester->execute(['--profile' => 'paranoid']));
        self::assertStringContainsString('paranoid', $tester->getDisplay());
    }

    #[Test]
    public function anUnknownProfileValueIsAlsoReportedInJson(): void
    {
        $doctor = self::createStub(VaultDoctorServiceInterface::class);
        $tester = new CommandTester(new VaultDoctorCommand($doctor));

        self::assertSame(2, $tester->execute(['--profile' => 'paranoid', '--format' => 'json']));

        $payload = $this->decode($tester->getDisplay());
        self::assertSame(2, $payload['exitCode']);
        self::assertIsString($payload['error']);
        self::assertStringContainsString('paranoid', $payload['error']);
    }

    /**
     * A gate that cannot run must never look like a gate that found nothing —
     * the same stance vault:audit-verify takes.
     */
    #[Test]
    public function aDoctorThatCannotRunExitsTwo(): void
    {
        $doctor = self::createStub(VaultDoctorServiceInterface::class);
        $doctor->method('run')->willThrowException(new RuntimeException('container is broken'));

        $tester = new CommandTester(new VaultDoctorCommand($doctor));

        self::assertSame(2, $tester->execute([]));
        self::assertStringContainsString('container is broken', $tester->getDisplay());
    }

    #[Test]
    public function aDoctorThatCannotRunReportsTheFailureInJsonToo(): void
    {
        $doctor = self::createStub(VaultDoctorServiceInterface::class);
        $doctor->method('run')->willThrowException(new RuntimeException('container is broken'));

        $tester = new CommandTester(new VaultDoctorCommand($doctor));

        self::assertSame(2, $tester->execute(['--format' => 'json']));

        $payload = $this->decode($tester->getDisplay());
        self::assertSame(2, $payload['exitCode']);
        self::assertIsString($payload['error']);
        self::assertStringContainsString('container is broken', $payload['error']);
    }

    #[Test]
    public function theControlRatioIsReported(): void
    {
        $tester = $this->tester($this->report([
            Finding::pass('a.one', 'ok'),
            Finding::pass('a.two', 'ok'),
            Finding::warning('a.three', 'meh', 'risk', 'fix'),
        ]));

        $tester->execute([]);

        self::assertStringContainsString('2 of 3', $tester->getDisplay());
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(string $json): array
    {
        $payload = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($payload);

        /** @var array<string, mixed> $payload */
        return $payload;
    }

    private function tester(DoctorReport $report): CommandTester
    {
        $doctor = self::createStub(VaultDoctorServiceInterface::class);
        $doctor->method('run')->willReturn($report);

        return new CommandTester(new VaultDoctorCommand($doctor));
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
