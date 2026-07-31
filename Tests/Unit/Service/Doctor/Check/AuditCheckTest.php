<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use Netresearch\NrVault\Audit\Anchor\AnchorReaderInterface;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\Check\AuditCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(AuditCheck::class)]
final class AuditCheckTest extends TestCase
{
    use DoctorFindingTrait;

    /**
     * Highest audit uid used by the default fixture chain.
     *
     * Deliberately above the 1000-entry window so the default fixture exercises
     * the bounded tail rather than accidentally covering the whole chain.
     */
    private const CHAIN_TIP = 2500;

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = $this->check();

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    #[Test]
    public function aFullyConfiguredHardenedAuditTrailPassesEveryControl(): void
    {
        $findings = $this->check(
            sinks: ['file', 'syslog'],
            anchor: new ChainTipAnchor(
                sequence: self::CHAIN_TIP - 20,
                chainTip: 'tip',
                timestamp: 1_700_000_000,
                hmacEpoch: 3,
            ),
        )->run($this->doctorContext(SecurityProfile::Hardened));

        self::assertSame(
            [
                'audit.reads_logged',
                'audit.retention',
                'audit.hash_chain',
                'audit.external_sink',
                'audit.anchor',
                'audit.sink_delivery',
            ],
            $this->findingIds($findings),
        );
        foreach ($findings as $finding) {
            self::assertTrue($finding->isPass(), $finding->id . ': ' . $finding->summary);
        }
    }

    /**
     * Reads are the operation an audit trail exists for — a stolen credential is
     * read, not written. Hygiene under standard, a broken promise under hardened.
     */
    #[Test]
    public function disabledReadLoggingIsAWarningUnderStandardAndCriticalUnderHardened(): void
    {
        $standard = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(auditReads: false)->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.reads_logged',
        );

        $hardened = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check(auditReads: false)->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.reads_logged',
        );

        // Escalation must keep the wording so a --profile=hardened dry run is
        // directly comparable to the live standard-profile report.
        self::assertSame($standard->summary, $hardened->summary);
        self::assertSame($standard->risk, $hardened->risk);
        self::assertSame($standard->remediation, $hardened->remediation);
    }

    /**
     * 0 means "keep forever", which is the safest setting for an audit trail and
     * therefore a pass — not a missing value to complain about.
     */
    #[Test]
    #[DataProvider('retentionProvider')]
    public function retentionIsJudgedAgainstAnAnnualReviewCycle(int $days, FindingSeverity $expected): void
    {
        $findings = $this->check(retention: $days)->run($this->doctorContext(SecurityProfile::Standard));

        $finding = $this->assertFindingSeverity($expected, $findings, 'audit.retention');
        self::assertSame($days, $finding->details['retentionDays']);
    }

    /**
     * @return iterable<string, array{int, FindingSeverity}>
     */
    public static function retentionProvider(): iterable
    {
        yield 'forever' => [0, FindingSeverity::Pass];
        yield 'exactly one year' => [365, FindingSeverity::Pass];
        yield 'more than a year' => [730, FindingSeverity::Pass];
        yield 'under a year' => [90, FindingSeverity::Warning];
        yield 'one day short' => [364, FindingSeverity::Warning];
        yield 'negative' => [-1, FindingSeverity::Warning];
    }

    #[Test]
    public function anEmptyChainHasNothingToVerifyAndPasses(): void
    {
        $findings = $this->check(chainTip: 0)->run($this->doctorContext(SecurityProfile::Standard));

        $finding = $this->findingById($findings, 'audit.hash_chain');
        self::assertTrue($finding->isPass());
        self::assertSame(0, $finding->details['currentSequence']);
    }

    /**
     * The pass is bounded to the newest 1000 entries, so a passing finding must
     * say so and name the authoritative full-range verifier. A gate that silently
     * implied full coverage would be worse than one admitting its scope.
     */
    #[Test]
    public function theChainPassIsBoundedToTheNewestThousandEntries(): void
    {
        $auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $auditLogService->expects(self::once())
            ->method('verifyHashChain')
            ->with(self::CHAIN_TIP - 999)
            ->willReturn(HashChainVerificationResult::valid());

        $finding = $this->findingById(
            $this->check(auditLogService: $auditLogService)
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.hash_chain',
        );

        self::assertSame(self::CHAIN_TIP - 999, $finding->details['fromUid']);
        self::assertSame(self::CHAIN_TIP, $finding->details['toUid']);
        self::assertStringContainsString('vault:audit-verify', $finding->summary);
    }

    #[Test]
    public function aShortChainIsVerifiedFromUidOne(): void
    {
        $auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $auditLogService->expects(self::once())
            ->method('verifyHashChain')
            ->with(1)
            ->willReturn(HashChainVerificationResult::valid());

        $this->check(chainTip: 12, auditLogService: $auditLogService)
            ->run($this->doctorContext(SecurityProfile::Standard));
    }

    #[Test]
    public function aFailingChainIsCritical(): void
    {
        $findings = $this->check(
            chainResult: HashChainVerificationResult::invalid([17 => 'hash mismatch']),
        )->run($this->doctorContext(SecurityProfile::Standard));

        $finding = $this->assertFindingSeverity(FindingSeverity::Critical, $findings, 'audit.hash_chain');
        self::assertSame(1, $finding->details['errorCount']);
        self::assertStringContainsString('vault:audit-verify', $finding->remediation);
    }

    /**
     * A uid gap is already an error in the verifier's own verdict, so it lands as
     * critical here too — consistent with `vault:audit-verify`, which treats
     * UID_GAP as tamper evidence until a documented purge accounts for it.
     */
    #[Test]
    public function aUidGapIsCriticalAndTheGapSizeIsReported(): void
    {
        $findings = $this->check(
            chainResult: HashChainVerificationResult::invalid(
                errors: [20 => 'Audit log uid gap detected: missing uids 18..19'],
                missingUids: [18, 19],
            ),
        )->run($this->doctorContext(SecurityProfile::Standard));

        $finding = $this->assertFindingSeverity(FindingSeverity::Critical, $findings, 'audit.hash_chain');
        self::assertSame(2, $finding->details['missingUidCount']);
        self::assertStringContainsString('2 uid(s) missing', $finding->summary);
    }

    /**
     * The hardened profile's NO_EXTERNAL_SINK invariant: an audit trail that lives
     * only in the database it protects has no tamper evidence at all.
     */
    #[Test]
    public function noExternalSinkIsCriticalUnderHardened(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check(sinks: [])->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.external_sink',
        );

        self::assertSame('NO_EXTERNAL_SINK', $finding->details['reasonCode']);
    }

    /**
     * Under the standard profile sinks are documented as opt-in, so flagging a
     * default installation for having no SIEM would be noise — and noise is what
     * trains an operator to ignore the hardened finding when it matters.
     */
    #[Test]
    public function noExternalSinkPassesUnderTheStandardProfile(): void
    {
        $finding = $this->findingById(
            $this->check(sinks: [])->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.external_sink',
        );

        self::assertTrue($finding->isPass());
        self::assertSame('NO_EXTERNAL_SINK', $finding->details['reasonCode']);
    }

    #[Test]
    public function aMissingAnchorIsCriticalUnderHardenedAndPassesUnderStandard(): void
    {
        $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check(sinks: ['file'], withoutAnchor: true)
                ->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.anchor',
        );

        self::assertTrue($this->findingById(
            $this->check(withoutAnchor: true)->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.anchor',
        )->isPass());
    }

    /**
     * The one anchor comparison cheap enough for a page load: an append-only chain
     * cannot get shorter, so a current tip below the anchored sequence is the
     * signature of a truncate-and-rebuild.
     */
    #[Test]
    public function aChainShorterThanTheAnchoredSequenceIsCritical(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check(
                chainTip: 3,
                sinks: ['file'],
                anchor: new ChainTipAnchor(
                    sequence: 900,
                    chainTip: 'tip',
                    timestamp: 1_700_000_000,
                    hmacEpoch: 3,
                ),
            )->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.anchor',
        );

        self::assertSame('TABLE_RESET', $finding->details['reasonCode']);
        self::assertSame(900, $finding->details['anchoredSequence']);
        self::assertSame(3, $finding->details['currentSequence']);
    }

    #[Test]
    public function sinkDeliveryFailuresAreAWarningNamingTheSink(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(sinks: ['webhook'], sinkFailures: ['webhook' => 3])
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.sink_delivery',
        );

        self::assertSame(3, $finding->details['failureCount']);
        self::assertStringContainsString('webhook', $finding->summary);
    }

    /**
     * A check wired with a healthy audit configuration, overridable per test.
     *
     * @param list<string> $sinks Enabled sink identifiers
     * @param array<string, int> $sinkFailures Per-sink delivery failures
     * @param ChainTipAnchor|null $anchor Anchor to compare against; null uses the
     *                                    healthy default (ignored when
     *                                    `$withoutAnchor` is true)
     * @param bool $withoutAnchor No anchor could be read at all
     */
    private function check(
        bool $auditReads = true,
        int $retention = 365,
        int $chainTip = self::CHAIN_TIP,
        ?HashChainVerificationResult $chainResult = null,
        array $sinks = ['file'],
        array $sinkFailures = [],
        ?ChainTipAnchor $anchor = null,
        bool $withoutAnchor = false,
        ?AuditLogServiceInterface $auditLogService = null,
    ): AuditCheck {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('isAuditReadsEnabled')->willReturn($auditReads);
        $configuration->method('getAuditLogRetention')->willReturn($retention);

        if (!$auditLogService instanceof AuditLogServiceInterface) {
            $stub = self::createStub(AuditLogServiceInterface::class);
            $stub->method('verifyHashChain')
                ->willReturn($chainResult ?? HashChainVerificationResult::valid());
            $auditLogService = $stub;
        }

        $registry = self::createStub(AuditSinkRegistryInterface::class);
        $registry->method('getEnabledSinkIdentifiers')->willReturn($sinks);
        $registry->method('hasExternalAuditSink')->willReturn($sinks !== []);
        $registry->method('getFailureCountsBySink')->willReturn($sinkFailures);
        $registry->method('getFailureCount')->willReturn(array_sum($sinkFailures));

        $anchorService = self::createStub(ChainTipAnchorServiceInterface::class);
        $anchorService->method('capture')->willReturn(new ChainTipAnchor(
            sequence: $chainTip,
            chainTip: $chainTip > 0 ? 'current-tip' : '',
            timestamp: 1_700_000_100,
            hmacEpoch: 3,
        ));

        $resolvedAnchor = $withoutAnchor
            ? null
            : ($anchor ?? new ChainTipAnchor(
                sequence: max(0, $chainTip - 20),
                chainTip: 'anchored-tip',
                timestamp: 1_700_000_000,
                hmacEpoch: 3,
            ));

        $anchorReader = self::createStub(AnchorReaderInterface::class);
        $anchorReader->method('readLatestAnchor')->willReturn($resolvedAnchor);
        $anchorReader->method('isAvailable')->willReturn(!$withoutAnchor);

        return new AuditCheck(
            $configuration,
            $auditLogService,
            $registry,
            $anchorService,
            $anchorReader,
        );
    }
}
