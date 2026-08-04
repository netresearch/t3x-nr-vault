<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor;

use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\DoctorContext;
use Netresearch\NrVault\Service\Doctor\DoctorReport;
use Netresearch\NrVault\Service\Doctor\Finding;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(DoctorReport::class)]
#[CoversClass(DoctorContext::class)]
#[CoversClass(Finding::class)]
final class DoctorReportTest extends TestCase
{
    /**
     * The exit-code contract a CI gate is written against. Documented in
     * Developer/Commands.rst; if this table changes, that document is wrong.
     */
    #[Test]
    #[DataProvider('exitCodeProvider')]
    public function exitCodeIsTheWorstSeverityPresent(FindingSeverity $worst, int $expected): void
    {
        $findings = [Finding::pass('a.ok', 'ok')];
        if ($worst === FindingSeverity::Warning) {
            $findings[] = Finding::warning('a.warn', 'meh', 'risk', 'fix');
        }

        if ($worst === FindingSeverity::Critical) {
            $findings[] = Finding::warning('a.warn', 'meh', 'risk', 'fix');
            $findings[] = Finding::critical('a.crit', 'broken', 'risk', 'fix');
        }

        $report = $this->report($findings);

        self::assertSame($expected, $report->exitCode());
        self::assertSame($worst, $report->highestSeverity());
    }

    /**
     * @return iterable<string, array{FindingSeverity, int}>
     */
    public static function exitCodeProvider(): iterable
    {
        yield 'only passes' => [FindingSeverity::Pass, 0];
        yield 'warnings' => [FindingSeverity::Warning, 1];
        yield 'criticals' => [FindingSeverity::Critical, 2];
    }

    /**
     * An empty report exits 0 by construction. The doctor service never produces
     * one — every applicable check reports its passes too — but the aggregation
     * must still be total rather than throwing on the edge.
     */
    #[Test]
    public function anEmptyReportIsAuditReady(): void
    {
        $report = $this->report([]);

        self::assertSame(0, $report->exitCode());
        self::assertTrue($report->isAuditReady());
        self::assertSame(0, $report->totalControls());
    }

    /**
     * Criticals first: an operator scanning a long report must hit the blocking
     * findings before the advisory ones, and passes must not pad the list.
     */
    #[Test]
    public function problemsListCriticalsBeforeWarningsAndExcludePasses(): void
    {
        $report = $this->report([
            Finding::warning('a.warn', 'meh', 'risk', 'fix'),
            Finding::pass('a.ok', 'ok'),
            Finding::critical('a.crit', 'broken', 'risk', 'fix'),
            Finding::warning('b.warn', 'meh', 'risk', 'fix'),
        ]);

        self::assertSame(
            ['a.crit', 'a.warn', 'b.warn'],
            array_map(static fn (Finding $f): string => $f->id, $report->problems()),
        );
    }

    #[Test]
    public function countsSeparatePassesFromProblems(): void
    {
        $report = $this->report([
            Finding::pass('a.ok', 'ok'),
            Finding::pass('b.ok', 'ok'),
            Finding::critical('a.crit', 'broken', 'risk', 'fix'),
        ]);

        self::assertSame(3, $report->totalControls());
        self::assertSame(2, $report->passedControls());
        self::assertFalse($report->isAuditReady());
    }

    /**
     * The JSON shape is external API — CI gates and monitoring rules parse it.
     */
    #[Test]
    public function theSerialisedFormCarriesTheContractFields(): void
    {
        $report = new DoctorReport(
            context: new DoctorContext(
                profile: SecurityProfile::Hardened,
                configuredProfile: SecurityProfile::Standard,
            ),
            findings: [
                Finding::pass('a.ok', 'fine'),
                Finding::critical(
                    id: 'audit.external_sink',
                    summary: 'no sink',
                    risk: 'no external evidence',
                    remediation: 'enable a sink',
                    docsUrl: 'https://example.org/docs',
                    details: ['reasonCode' => 'NO_EXTERNAL_SINK'],
                ),
            ],
        );

        $payload = $report->toArray();

        self::assertSame('hardened', $payload['profile']);
        self::assertSame('standard', $payload['configuredProfile']);
        self::assertTrue($payload['profileOverridden']);
        self::assertFalse($payload['auditReady']);
        self::assertSame('critical', $payload['highestSeverity']);
        self::assertSame(2, $payload['exitCode']);
        self::assertSame(['total' => 2, 'pass' => 1, 'warning' => 0, 'critical' => 1], $payload['summary']);

        $sinkFinding = $payload['findings'][1];
        self::assertSame('audit.external_sink', $sinkFinding['id']);
        self::assertSame('critical', $sinkFinding['severity']);
        self::assertSame('enable a sink', $sinkFinding['remediation']);
        self::assertSame('https://example.org/docs', $sinkFinding['docsUrl']);
        self::assertSame(['reasonCode' => 'NO_EXTERNAL_SINK'], $sinkFinding['details']);

        // Passing controls stay in the payload so "N of M" needs no second source.
        self::assertSame('a.ok', $payload['findings'][0]['id']);
        self::assertSame('', $payload['findings'][0]['risk']);
    }

    /**
     * Escalation keeps every text field, which is what makes a
     * `--profile=hardened` dry run comparable to the live report.
     */
    #[Test]
    public function escalatingAFindingPreservesItsWording(): void
    {
        $warning = Finding::warning(
            id: 'audit.reads_logged',
            summary: 'reads are not logged',
            risk: 'no record of consumption',
            remediation: 'enable auditReads',
            docsUrl: 'https://example.org/docs',
            details: ['auditReads' => false],
        );

        $critical = $warning->escalatedTo(FindingSeverity::Critical);

        self::assertSame(FindingSeverity::Critical, $critical->severity);
        self::assertSame($warning->id, $critical->id);
        self::assertSame($warning->summary, $critical->summary);
        self::assertSame($warning->risk, $critical->risk);
        self::assertSame($warning->remediation, $critical->remediation);
        self::assertSame($warning->docsUrl, $critical->docsUrl);
        self::assertSame($warning->details, $critical->details);
    }

    #[Test]
    public function escalatingToTheSameSeverityReturnsTheSameInstance(): void
    {
        $warning = Finding::warning('a.warn', 'meh', 'risk', 'fix');

        self::assertSame($warning, $warning->escalatedTo(FindingSeverity::Warning));
    }

    #[Test]
    public function aContextForTheConfiguredProfileIsNotOverridden(): void
    {
        $context = DoctorContext::forConfiguredProfile(SecurityProfile::Hardened);

        self::assertFalse($context->isProfileOverridden());
        self::assertTrue($context->isHardened());
        self::assertSame(SecurityProfile::Hardened, $context->configuredProfile);
    }

    /**
     * @param list<Finding> $findings
     */
    private function report(array $findings): DoctorReport
    {
        return new DoctorReport(
            context: DoctorContext::forConfiguredProfile(SecurityProfile::Standard),
            findings: $findings,
        );
    }
}
