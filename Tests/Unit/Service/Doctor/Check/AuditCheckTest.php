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
use Netresearch\NrVault\Audit\AuditChainAnchor;
use Netresearch\NrVault\Audit\AuditChainAnchorLoad;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Audit\Sink\SinkDeliveryState;
use Netresearch\NrVault\Audit\Sink\SinkDeliveryStateRepositoryInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Service\Doctor\Check\AuditCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

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
                'audit.hmac_epoch',
                'audit.db_anchor',
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

    #[Test]
    public function aFailingSinkInThePersistedStateIsCriticalUnderHardened(): void
    {
        $findings = $this->check(
            sinks: ['webhook'],
            deliveryState: $this->deliveryStateWith([
                'webhook' => new SinkDeliveryState(
                    sinkIdentifier: 'webhook',
                    lastSuccessAt: time() - 600,
                    lastFailureAt: time() - 60,
                    consecutiveFailures: 4,
                    totalFailures: 4,
                    lastError: 'connection refused',
                ),
            ]),
        )->run($this->doctorContext(SecurityProfile::Hardened));

        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $findings,
            'audit.sink_state.webhook',
        );
        self::assertStringContainsString('connection refused', $finding->summary);
    }

    #[Test]
    public function aStaleLastSuccessfulDeliveryIsCriticalUnderHardenedAndAWarningUnderStandard(): void
    {
        $staleState = $this->deliveryStateWith([
            'file' => new SinkDeliveryState(
                sinkIdentifier: 'file',
                lastSuccessAt: time() - (48 * 3600),
            ),
        ]);

        $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check(sinks: ['file'], deliveryState: $staleState)
                ->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.sink_state.file',
        );

        $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(sinks: ['file'], deliveryState: $staleState)
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.sink_state.file',
        );
    }

    #[Test]
    public function aSinkThatNeverDeliveredIsAWarningUnderHardenedOnly(): void
    {
        // A freshly enabled sink has no history yet — under hardened that is
        // unproven external evidence (the remediation points at
        // --active-probes); under standard it is normal ramp-up.
        $pristine = $this->deliveryStateWith([]);

        $hardened = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(sinks: ['syslog'], deliveryState: $pristine)
                ->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.sink_state.syslog',
        );
        self::assertStringContainsString('--active-probes', $hardened->remediation);

        $standard = $this->findingById(
            $this->check(sinks: ['syslog'], deliveryState: $pristine)
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.sink_state.syslog',
        );
        self::assertTrue($standard->isPass());
    }

    #[Test]
    public function aRecentlyDeliveringSinkPasses(): void
    {
        $finding = $this->findingById(
            $this->check(
                sinks: ['file'],
                deliveryState: $this->deliveryStateWith([
                    'file' => new SinkDeliveryState(sinkIdentifier: 'file', lastSuccessAt: time() - 120),
                ]),
            )->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.sink_state.file',
        );

        self::assertTrue($finding->isPass());
    }

    /**
     * The lowest epoch that still keys the chain. Epoch 1 must pass, so a
     * relaxed `>= 1` boundary in the check cannot go unnoticed.
     */
    #[Test]
    public function theLowestKeyedEpochPasses(): void
    {
        $finding = $this->findingById(
            $this->check(epoch: 1)->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.hmac_epoch',
        );

        self::assertTrue($finding->isPass(), $finding->summary);
        self::assertSame(1, $finding->details['auditHmacEpoch']);
    }

    /**
     * Epoch 0 switches off three controls with one integer, and the standard
     * profile promises a tamper-evident chain just as much as the hardened one —
     * so this is critical in both, not an escalation.
     */
    #[DataProvider('keylessEpochProvider')]
    #[Test]
    public function aKeylessEpochIsCriticalUnderBothProfiles(int $epoch): void
    {
        foreach ([SecurityProfile::Standard, SecurityProfile::Hardened] as $profile) {
            $finding = $this->assertFindingSeverity(
                FindingSeverity::Critical,
                $this->check(epoch: $epoch)->run($this->doctorContext($profile)),
                'audit.hmac_epoch',
            );

            self::assertSame($epoch, $finding->details['auditHmacEpoch']);
        }
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function keylessEpochProvider(): iterable
    {
        yield 'zero' => [0];
        yield 'negative' => [-1];
    }

    /**
     * The finding is only actionable if it says WHICH controls went inert — an
     * operator reading "epoch is 0" alone has no reason to treat it as critical.
     */
    #[Test]
    public function theKeylessEpochFindingNamesAllThreeDisabledControls(): void
    {
        $finding = $this->findingById(
            $this->check(epoch: 0, anchorRequired: true)
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.hmac_epoch',
        );

        self::assertStringContainsString('SHA-256', $finding->risk);
        self::assertStringContainsString('downgrade', $finding->risk);
        self::assertStringContainsString('sys_registry', $finding->risk);
        self::assertStringContainsString('vault:audit-migrate-hmac', $finding->remediation);

        // The epoch finding carries the anchor requirement too: the two settings
        // are only readable as a contradiction when both values are in the JSON.
        self::assertTrue($finding->details['auditAnchorRequired']);
    }

    /**
     * `auditAnchorRequired` + epoch 0 is the silent contradiction: the store is
     * disabled, so verification returns `Disabled` before the requirement is
     * ever consulted and the strict-looking setting protects nothing.
     */
    #[Test]
    public function requiringTheAnchorAtEpochZeroIsReportedAsAContradiction(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check(epoch: 0, anchorRequired: true)
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.db_anchor',
        );

        self::assertStringContainsString('auditAnchorRequired', $finding->summary);
        self::assertStringContainsString('auditHmacEpoch', $finding->summary);
        self::assertSame(AuditChainAnchorStatus::Disabled->value, $finding->details['anchorStatus']);
        self::assertTrue($finding->details['auditAnchorRequired']);
    }

    /**
     * Without the requirement the disabled anchor is still not a pass: the
     * control was not evaluated, and a gate must not read that as satisfied.
     */
    #[Test]
    public function aDisabledAnchorWarnsThatTheControlWasNotEvaluated(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(epoch: 0)->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.db_anchor',
        );

        self::assertStringContainsString('auditHmacEpoch', $finding->summary);
        self::assertSame(0, $finding->details['auditHmacEpoch']);
    }

    /**
     * The case the doctor was blind to: at the default epoch the anchor row is
     * simply gone, and no bounded chain pass evaluates the anchor at all.
     */
    #[Test]
    public function aMissingAnchorOnAPopulatedChainIsAWarning(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(dbAnchorStatus: AuditChainAnchorStatus::Unanchored)
                ->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.db_anchor',
        );

        self::assertStringContainsString((string) self::CHAIN_TIP, $finding->summary);
    }

    /**
     * With the operator's "this install is anchored" assertion in place, an
     * absent anchor is a removed anchor — and ordinary audit writes deliberately
     * refuse to re-arm it, so it does not heal on its own.
     */
    #[Test]
    public function aMissingAnchorIsCriticalWhenItIsRequired(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Critical,
            $this->check(anchorRequired: true, dbAnchorStatus: AuditChainAnchorStatus::Unanchored)
                ->run($this->doctorContext(SecurityProfile::Standard)),
            'audit.db_anchor',
        );

        self::assertStringContainsString('vault:audit --reset-anchor', $finding->remediation);
    }

    /**
     * A chain with no rows has nothing to anchor yet, and the anchor arms itself
     * on the first audit write — flagging a fresh installation would train
     * operators to ignore the finding that matters.
     */
    #[Test]
    public function aMissingAnchorOnAnEmptyChainPasses(): void
    {
        $finding = $this->findingById(
            $this->check(chainTip: 0, dbAnchorStatus: AuditChainAnchorStatus::Unanchored)
                ->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.db_anchor',
        );

        self::assertTrue($finding->isPass(), $finding->summary);
        self::assertSame(0, $finding->details['currentSequence']);
    }

    /**
     * Two connections is a deployment fact no vault-side action fixes, so it
     * stays a warning even under the requirement — otherwise the gate demands
     * something the operator cannot do from here.
     */
    #[Test]
    public function aSplitConnectionStaysAWarningEvenWhenTheAnchorIsRequired(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(
                anchorRequired: true,
                dbAnchorStatus: AuditChainAnchorStatus::Unanchored,
                sharesConnection: false,
            )->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.db_anchor',
        );

        self::assertStringContainsString('different database connections', $finding->summary);
    }

    /**
     * A present-but-unauthentic anchor is never the pre-anchor state, so it is
     * critical regardless of profile and of `auditAnchorRequired` — the same
     * verdict `AuditLogService::verifyAnchor()` reaches.
     */
    #[Test]
    public function anUnreadableAnchorIsCriticalWhetherOrNotItIsRequired(): void
    {
        foreach ([true, false] as $required) {
            $finding = $this->assertFindingSeverity(
                FindingSeverity::Critical,
                $this->check(
                    anchorRequired: $required,
                    dbAnchorStatus: AuditChainAnchorStatus::Unreadable,
                )->run($this->doctorContext(SecurityProfile::Standard)),
                'audit.db_anchor',
            );

            self::assertStringContainsString('unreadable', $finding->summary);
        }
    }

    /**
     * A status `load()` cannot currently produce must not fall through to a
     * pass: a gate that never saw the value would read silence as health.
     */
    #[Test]
    public function anUnexpectedAnchorStatusIsReportedRatherThanPassed(): void
    {
        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check(dbAnchorStatus: AuditChainAnchorStatus::Violated)
                ->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.db_anchor',
        );

        self::assertSame(AuditChainAnchorStatus::Violated->value, $finding->details['anchorStatus']);
    }

    /**
     * A pass has to admit its scope: the MAC verifies, which is not the same as
     * the anchored ROW still carrying the anchored hash.
     */
    #[Test]
    public function aHealthyAnchorPassesAndNamesTheDeeperVerifier(): void
    {
        $finding = $this->findingById(
            $this->check()->run($this->doctorContext(SecurityProfile::Hardened)),
            'audit.db_anchor',
        );

        self::assertTrue($finding->isPass(), $finding->summary);
        self::assertStringContainsString('vault:audit-verify', $finding->summary);
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
     * @param int $epoch Configured `auditHmacEpoch`
     * @param bool $anchorRequired Configured `auditAnchorRequired`
     * @param AuditChainAnchorStatus|null $dbAnchorStatus Status the in-DB anchor
     *                                                    store reports; null
     *                                                    derives it from
     *                                                    `$epoch`, exactly as
     *                                                    the real store does
     * @param bool $sharesConnection Whether `sys_registry` resolves to the audit
     *                               connection
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
        ?SinkDeliveryStateRepositoryInterface $deliveryState = null,
        int $epoch = 3,
        bool $anchorRequired = false,
        ?AuditChainAnchorStatus $dbAnchorStatus = null,
        bool $sharesConnection = true,
    ): AuditCheck {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('isAuditReadsEnabled')->willReturn($auditReads);
        $configuration->method('getAuditLogRetention')->willReturn($retention);
        $configuration->method('getAuditSinkStaleDeliveryHours')->willReturn(24);
        $configuration->method('getAuditHmacEpoch')->willReturn($epoch);
        $configuration->method('isAuditAnchorRequired')->willReturn($anchorRequired);

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
            $this->anchorStore($epoch, $dbAnchorStatus, $sharesConnection),
            $this->connectionPool(),
            $deliveryState,
        );
    }

    /**
     * The in-DB anchor store, wired to report `$status`.
     *
     * When no status is given it is derived from the epoch the same way
     * `AuditChainAnchorStore::isEnabled()` does (`epoch >= 1`), so a test that
     * only lowers the epoch cannot accidentally assert against a store that
     * still claims to be armed.
     */
    private function anchorStore(
        int $epoch,
        ?AuditChainAnchorStatus $status,
        bool $sharesConnection,
    ): AuditChainAnchorStoreInterface {
        $status ??= $epoch >= 1 ? AuditChainAnchorStatus::Ok : AuditChainAnchorStatus::Disabled;

        $load = new AuditChainAnchorLoad(
            status: $status,
            anchor: $status === AuditChainAnchorStatus::Ok
                ? new AuditChainAnchor(self::CHAIN_TIP, str_repeat('a', 64), 1_700_000_000)
                : null,
            raw: $status === AuditChainAnchorStatus::Ok ? 'nrvault-audit-tip.v1|…' : '',
        );

        $store = self::createStub(AuditChainAnchorStoreInterface::class);
        $store->method('isEnabled')->willReturn($epoch >= 1);
        $store->method('sharesConnection')->willReturn($sharesConnection);
        $store->method('load')->willReturn($load);

        return $store;
    }

    private function connectionPool(): ConnectionPool
    {
        $pool = self::createStub(ConnectionPool::class);
        $pool->method('getConnectionForTable')->willReturn(self::createStub(Connection::class));

        return $pool;
    }

    /**
     * @param array<string, SinkDeliveryState> $states
     */
    private function deliveryStateWith(array $states): SinkDeliveryStateRepositoryInterface
    {
        $repository = self::createStub(SinkDeliveryStateRepositoryInterface::class);
        $repository->method('getState')->willReturnCallback(
            static fn (string $sink): SinkDeliveryState => $states[$sink] ?? new SinkDeliveryState(sinkIdentifier: $sink),
        );

        return $repository;
    }
}
