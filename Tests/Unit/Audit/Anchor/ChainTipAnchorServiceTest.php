<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Anchor;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Audit\Anchor\AnchorReaderInterface;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorService;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Event\AuditIntegrityAlertEvent;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use UnexpectedValueException;

/**
 * Unit tests for the branches of chain-tip anchoring that the functional suite
 * cannot drive.
 *
 * {@see \Netresearch\NrVault\Tests\Functional\Audit\ChainTipAnchorServiceTest}
 * owns the end-to-end evidence — a real chain, a real NDJSON sink, a real
 * truncate-and-reseed attack. What it cannot reach is the behaviour of the
 * service when its COLLABORATORS misbehave: a sink registry that accepts
 * nothing, a configuration that cannot resolve its own security profile, an
 * event listener that throws. Those are the paths that decide whether a failing
 * integrity check reports honestly or silently degrades, so they are driven here
 * with stubbed collaborators instead.
 */
#[CoversClass(ChainTipAnchorService::class)]
final class ChainTipAnchorServiceTest extends TestCase
{
    // -------------------------------------------------------------------------
    // publish()
    // -------------------------------------------------------------------------

    /**
     * An anchor nobody stored provides no table-reset protection whatsoever. The
     * service does not throw — the command/scheduler caller owns how loudly to
     * fail — but it must never look like success, so it returns 0 AND logs at
     * error level.
     */
    #[Test]
    public function publishingToZeroSinksReturnsZeroAndLogsAnError(): void
    {
        $registry = self::createStub(AuditSinkRegistryInterface::class);
        $registry->method('dispatchAnchor')->willReturn(0);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with(
                self::stringContains('zero external sinks'),
                ['sequence' => 12],
            );
        $logger->expects(self::never())->method('info');

        $subject = $this->createSubject(sinkRegistry: $registry, logger: $logger);

        self::assertSame(0, $subject->publish(new ChainTipAnchor(12, 'tip-12', 1_750_000_000, 3)));
    }

    /**
     * The accepted-sink count is passed through verbatim: the caller uses it to
     * report how much external evidence actually exists.
     */
    #[Test]
    public function publishingReturnsTheNumberOfSinksThatAcceptedTheAnchor(): void
    {
        $registry = self::createStub(AuditSinkRegistryInterface::class);
        $registry->method('dispatchAnchor')->willReturn(3);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('info')
            ->with(self::stringContains('published an audit chain anchor'), ['sequence' => 5, 'sinks' => 3]);
        $logger->expects(self::never())->method('error');

        $subject = $this->createSubject(sinkRegistry: $registry, logger: $logger);

        self::assertSame(3, $subject->publish(new ChainTipAnchor(5, 'tip-5', 1_750_000_000, 3)));
    }

    // -------------------------------------------------------------------------
    // capture()
    // -------------------------------------------------------------------------

    #[Test]
    public function captureBindsTheConfiguredEpochToTheChainTip(): void
    {
        $auditLogService = self::createStub(AuditLogServiceInterface::class);
        $auditLogService->method('getLatestHash')->willReturn('tip-9');

        $subject = $this->createSubject(
            auditLogService: $auditLogService,
            maxUid: 9,
            hmacEpoch: 4,
        );

        $anchor = $subject->capture();

        self::assertSame(9, $anchor->sequence);
        self::assertSame('tip-9', $anchor->chainTip);
        self::assertSame(4, $anchor->hmacEpoch);
    }

    /**
     * A chain whose tip cannot be read must not be anchored as if the tip were
     * the empty string of an empty chain — the anchor would then match anything.
     * The empty-anchor marker is what `compareWithAnchor()` refuses to use as a
     * baseline.
     */
    #[Test]
    public function captureOnAChainWithoutAReadableTipYieldsAnEmptyChainTip(): void
    {
        $auditLogService = self::createStub(AuditLogServiceInterface::class);
        $auditLogService->method('getLatestHash')->willReturn(null);

        $anchor = $this->createSubject(auditLogService: $auditLogService, maxUid: 7)->capture();

        self::assertSame(7, $anchor->sequence);
        self::assertSame('', $anchor->chainTip);
    }

    // -------------------------------------------------------------------------
    // Chain-error classification
    // -------------------------------------------------------------------------

    /**
     * An epoch downgrade is reported by the chain verifier as an error STRING, so
     * the report has to recognise it by its marker substring. Misclassifying it
     * as a generic hash mismatch would tell an operator to look for a rewritten
     * row when the real event was an algorithm downgrade.
     */
    #[Test]
    public function anEpochDowngradeErrorIsClassifiedAsEpochDowngradeNotHashMismatch(): void
    {
        $report = $this->createSubject(
            chainResult: HashChainVerificationResult::invalid([
                4 => 'HMAC key epoch downgrade detected: 3 -> 0 (possible algorithm-downgrade forgery)',
            ]),
        )->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::EpochDowngrade));
        self::assertFalse($report->hasReason(AuditIntegrityReason::HashMismatch));
    }

    /**
     * A broken chain commonly fails every row after the break. One finding per
     * ERRORING ROW would bury the signal under thousands of identical SIEM
     * alerts, so the rows collapse into a single finding carrying the count.
     */
    #[Test]
    public function manyEpochDowngradeRowsCollapseIntoOneFindingCarryingTheCount(): void
    {
        $errors = [];
        foreach ([11, 12, 13, 14] as $uid) {
            $errors[$uid] = 'HMAC key epoch downgrade detected: 3 -> 0 (possible algorithm-downgrade forgery)';
        }

        $report = $this->createSubject(chainResult: HashChainVerificationResult::invalid($errors))->verify();

        $downgrades = array_values(array_filter(
            $report->findings,
            static fn (AuditIntegrityAlert $finding): bool => $finding->reason === AuditIntegrityReason::EpochDowngrade,
        ));

        self::assertCount(1, $downgrades);
        self::assertSame(4, $downgrades[0]->context['affectedRows']);
        self::assertSame(11, $downgrades[0]->context['firstUid'], 'the earliest affected row locates the break');
        self::assertStringContainsString('4 row(s)', $downgrades[0]->detail);
    }

    /**
     * Both classes in one chain must both be reported — an operator needs to know
     * that rows were rewritten AND that the algorithm was relabelled.
     */
    #[Test]
    public function epochDowngradeAndHashMismatchRowsAreReportedSeparately(): void
    {
        $report = $this->createSubject(
            chainResult: HashChainVerificationResult::invalid([
                2 => 'HMAC key epoch downgrade detected: 3 -> 0 (possible algorithm-downgrade forgery)',
                5 => 'Entry hash mismatch - possible tampering',
            ]),
        )->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::EpochDowngrade));
        self::assertTrue($report->hasReason(AuditIntegrityReason::HashMismatch));
    }

    /**
     * The uid-gap error string duplicates the structured `missingUidCount`, which
     * is already reported as UID_GAP. Counting it twice would inflate the
     * hash-mismatch row count and invent a finding that is not there.
     */
    #[Test]
    public function theUidGapErrorStringIsNotCountedAgainAsAHashMismatch(): void
    {
        $report = $this->createSubject(
            chainResult: HashChainVerificationResult::invalid(
                [3 => 'Audit log uid gap detected: missing uids 2..2 (chain could have been tampered by deletion + previous_hash patch)'],
                [],
                [2],
                1,
            ),
        )->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::UidGap));
        self::assertFalse($report->hasReason(AuditIntegrityReason::HashMismatch));
    }

    /**
     * An error message the classifier does not recognise still has to appear:
     * degrading to a generic hash finding keeps a future verifier message
     * visible, where dropping it would hide a real chain error.
     */
    #[Test]
    public function anUnrecognisedChainErrorDegradesToAHashMismatchRatherThanDisappearing(): void
    {
        $report = $this->createSubject(
            chainResult: HashChainVerificationResult::invalid([9 => 'Something the verifier learned to say later']),
        )->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::HashMismatch));
        self::assertFalse($report->isValid());
    }

    // -------------------------------------------------------------------------
    // External-sink requirement
    // -------------------------------------------------------------------------

    /**
     * Under the hardened profile the audit trail must exist somewhere other than
     * the database it protects. No usable sink means no anchor can ever be
     * published, so a full table reset would be undetectable.
     */
    #[Test]
    public function theHardenedProfileWithoutAnyUsableSinkReportsNoExternalSink(): void
    {
        $registry = self::createStub(AuditSinkRegistryInterface::class);
        $registry->method('hasExternalAuditSink')->willReturn(false);

        $report = $this->createSubject(
            sinkRegistry: $registry,
            profile: SecurityProfile::Hardened,
        )->verify();

        $findings = array_values(array_filter(
            $report->findings,
            static fn (AuditIntegrityAlert $finding): bool => $finding->reason === AuditIntegrityReason::NoExternalSink,
        ));

        self::assertCount(1, $findings);
        self::assertSame('hardened', $findings[0]->context['profile']);
        self::assertStringContainsString('only in the database it is meant to protect', $findings[0]->detail);
        self::assertFalse($report->hasTamperEvidence(), 'a configuration gap is not tamper evidence');
    }

    /**
     * The standard profile treats external sinks as opt-in — flagging a default
     * installation for not having a SIEM would make the check noise.
     */
    #[Test]
    public function theStandardProfileWithoutAnyUsableSinkReportsNothing(): void
    {
        $registry = self::createStub(AuditSinkRegistryInterface::class);
        $registry->method('hasExternalAuditSink')->willReturn(false);

        $report = $this->createSubject(sinkRegistry: $registry)->verify();

        self::assertTrue($report->isValid());
        self::assertSame([], $report->getReasonCodes());
    }

    /**
     * A configuration value the profile enum cannot parse is a configuration
     * fault, not an integrity finding. It must not be swallowed into a
     * "valid chain" verdict silently — hence the error log — but it also must not
     * abort the rest of the verification.
     */
    #[Test]
    public function anUnresolvableSecurityProfileIsLoggedAndSkipsTheSinkCheckOnly(): void
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('getAuditHmacEpoch')->willReturn(3);
        $configuration->method('getSecurityProfile')
            ->willThrowException(new UnexpectedValueException('unknown profile "military-grade"', 1750000030));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with(
                self::stringContains('could not resolve the security profile'),
                ['error' => 'unknown profile "military-grade"'],
            );

        $report = $this->createSubject(
            configuration: $configuration,
            logger: $logger,
            chainResult: HashChainVerificationResult::invalid([1 => 'Entry hash mismatch - possible tampering']),
        )->verify();

        // The chain findings survive the configuration fault.
        self::assertTrue($report->hasReason(AuditIntegrityReason::HashMismatch));
        self::assertFalse($report->hasReason(AuditIntegrityReason::NoExternalSink));
    }

    // -------------------------------------------------------------------------
    // Finding dispatch
    // -------------------------------------------------------------------------

    #[Test]
    public function everyFindingIsDispatchedAsAnEvent(): void
    {
        $dispatched = [];
        $dispatcher = self::createStub(EventDispatcherInterface::class);
        $dispatcher->method('dispatch')->willReturnCallback(
            static function (object $event) use (&$dispatched): object {
                if ($event instanceof AuditIntegrityAlertEvent) {
                    $dispatched[] = $event->getAlert()->reason;
                }

                return $event;
            },
        );

        $registry = self::createStub(AuditSinkRegistryInterface::class);
        $registry->method('hasExternalAuditSink')->willReturn(false);

        $this->createSubject(
            sinkRegistry: $registry,
            eventDispatcher: $dispatcher,
            chainResult: HashChainVerificationResult::invalid([1 => 'Entry hash mismatch - possible tampering']),
            profile: SecurityProfile::Hardened,
        )->verify();

        self::assertSame(
            [AuditIntegrityReason::HashMismatch, AuditIntegrityReason::NoExternalSink],
            $dispatched,
        );
    }

    /**
     * A throwing listener must cost neither the remaining findings nor the report
     * itself: the integrity verdict is the whole point of the run, and a
     * misbehaving SIEM notifier must not be able to suppress it.
     */
    #[Test]
    public function aThrowingListenerDoesNotCostTheRemainingFindingsOrTheReport(): void
    {
        $seen = [];
        $dispatcher = self::createStub(EventDispatcherInterface::class);
        $dispatcher->method('dispatch')->willReturnCallback(
            static function (object $event) use (&$seen): object {
                if (!$event instanceof AuditIntegrityAlertEvent) {
                    return $event;
                }

                $seen[] = $event->getAlert()->reason;

                if ($event->getAlert()->reason === AuditIntegrityReason::HashMismatch) {
                    throw new RuntimeException('notifier exploded', 1750000031);
                }

                return $event;
            },
        );

        $registry = self::createStub(AuditSinkRegistryInterface::class);
        $registry->method('hasExternalAuditSink')->willReturn(false);

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with(
                self::stringContains('could not dispatch an audit integrity alert'),
                ['reason' => 'HASH_MISMATCH', 'error' => 'notifier exploded'],
            );

        $report = $this->createSubject(
            sinkRegistry: $registry,
            eventDispatcher: $dispatcher,
            logger: $logger,
            chainResult: HashChainVerificationResult::invalid([1 => 'Entry hash mismatch - possible tampering']),
            profile: SecurityProfile::Hardened,
        )->verify();

        self::assertSame(
            [AuditIntegrityReason::HashMismatch, AuditIntegrityReason::NoExternalSink],
            $seen,
            'the finding after the throwing one must still be dispatched',
        );
        self::assertFalse($report->isValid(), 'the report survives the listener failure');
    }

    // -------------------------------------------------------------------------
    // Anchor comparison against a non-shrinking chain
    // -------------------------------------------------------------------------

    /**
     * An anchor captured while the chain was still empty matches any chain, so it
     * is no baseline at all and must not be treated as one.
     */
    #[Test]
    public function anEmptyAnchorIsNotUsedAsAComparisonBaseline(): void
    {
        $anchorReader = self::createStub(AnchorReaderInterface::class);
        $anchorReader->method('readLatestAnchor')->willReturn(new ChainTipAnchor(0, '', 1_750_000_000, 3));

        $report = $this->createSubject(anchorReader: $anchorReader, maxUid: 5)->verify();

        self::assertTrue($report->isValid());
        self::assertSame([], $report->getReasonCodes());
    }

    /**
     * Growth past the anchor is normal operation. Only shrinkage, substitution or
     * epoch regression are findings.
     */
    #[Test]
    public function aChainThatGrewPastItsAnchorIsValid(): void
    {
        $anchorReader = self::createStub(AnchorReaderInterface::class);
        $anchorReader->method('readLatestAnchor')->willReturn(new ChainTipAnchor(2, 'tip-2', 1_750_000_000, 3));

        $report = $this->createSubject(
            anchorReader: $anchorReader,
            maxUid: 9,
            rowAtAnchor: ['entry_hash' => 'tip-2', 'hmac_key_epoch' => 3],
        )->verify();

        self::assertTrue($report->isValid(), 'findings: ' . implode(',', $report->getReasonCodes()));
        self::assertSame(9, $report->currentSequence);
    }

    /**
     * A row whose stored hash is not a string (a NULL column after a partial
     * write) must not compare equal to the anchored tip by collapsing to ''.
     */
    #[Test]
    public function anAnchoredRowWithoutAUsableHashIsReportedAsATableReset(): void
    {
        $anchorReader = self::createStub(AnchorReaderInterface::class);
        $anchorReader->method('readLatestAnchor')->willReturn(new ChainTipAnchor(2, 'tip-2', 1_750_000_000, 3));

        $report = $this->createSubject(
            anchorReader: $anchorReader,
            maxUid: 4,
            rowAtAnchor: ['entry_hash' => null, 'hmac_key_epoch' => 3],
        )->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::TableReset));
    }

    /**
     * A non-numeric epoch column degrades to 0, which is below any anchored
     * epoch — the fail-closed direction.
     */
    #[Test]
    public function anAnchoredRowWithoutAUsableEpochIsReportedAsAnEpochDowngrade(): void
    {
        $anchorReader = self::createStub(AnchorReaderInterface::class);
        $anchorReader->method('readLatestAnchor')->willReturn(new ChainTipAnchor(2, 'tip-2', 1_750_000_000, 3));

        $report = $this->createSubject(
            anchorReader: $anchorReader,
            maxUid: 4,
            rowAtAnchor: ['entry_hash' => 'tip-2', 'hmac_key_epoch' => 'not-a-number'],
        )->verify();

        self::assertTrue($report->hasReason(AuditIntegrityReason::EpochDowngrade));
    }

    /**
     * The shrinkage check. An append-only chain's highest uid cannot decrease, so
     * `current < anchored` is a truncate — and the finding has to name both
     * sequences and the capture time, because that is what an operator needs to
     * bound the window in which the rows disappeared.
     */
    #[Test]
    public function aChainShorterThanItsAnchorReportsATableResetNamingBothSequences(): void
    {
        $anchorReader = self::createStub(AnchorReaderInterface::class);
        $anchorReader->method('readLatestAnchor')->willReturn(new ChainTipAnchor(9, 'tip-9', 1_750_000_000, 3));

        $report = $this->createSubject(anchorReader: $anchorReader, maxUid: 2)->verify();

        $findings = array_values(array_filter(
            $report->findings,
            static fn (AuditIntegrityAlert $finding): bool => $finding->reason === AuditIntegrityReason::TableReset,
        ));

        self::assertCount(1, $findings);
        self::assertSame(2, $findings[0]->context['currentSequence']);
        self::assertSame(9, $findings[0]->context['anchoredSequence']);
        self::assertSame(1_750_000_000, $findings[0]->context['anchoredAt']);
        self::assertStringContainsString('2025-06-15 15:06:40 UTC', $findings[0]->detail);
        self::assertTrue($report->hasTamperEvidence());
    }

    /**
     * A reset that re-seeds MORE rows than were anchored passes the length check,
     * so the anchored row's absence is the only remaining evidence.
     */
    #[Test]
    public function aMissingAnchoredRowInALongerChainReportsATableReset(): void
    {
        $anchorReader = self::createStub(AnchorReaderInterface::class);
        $anchorReader->method('readLatestAnchor')->willReturn(new ChainTipAnchor(3, 'tip-3', 1_750_000_000, 3));

        $report = $this->createSubject(
            anchorReader: $anchorReader,
            maxUid: 11,
            rowAtAnchor: false,
        )->verify();

        $findings = array_values(array_filter(
            $report->findings,
            static fn (AuditIntegrityAlert $finding): bool => $finding->reason === AuditIntegrityReason::TableReset,
        ));

        self::assertCount(1, $findings);
        self::assertSame(3, $findings[0]->context['anchoredSequence']);
        self::assertSame(11, $findings[0]->context['currentSequence']);
        self::assertStringContainsString('no longer exists', $findings[0]->detail);
    }

    /**
     * Hardened profile, a usable sink, but no anchor yet: reset detection is not
     * in place, and the finding must say whether the anchor store is even
     * reachable so the operator knows whether to run `vault:audit-anchor` or to
     * fix the sink first.
     */
    #[Test]
    public function theHardenedProfileWithASinkButNoAnchorReportsNoExternalSink(): void
    {
        $anchorReader = self::createStub(AnchorReaderInterface::class);
        $anchorReader->method('readLatestAnchor')->willReturn(null);
        $anchorReader->method('isAvailable')->willReturn(false);

        $report = $this->createSubject(
            anchorReader: $anchorReader,
            profile: SecurityProfile::Hardened,
        )->verify();

        $findings = array_values(array_filter(
            $report->findings,
            static fn (AuditIntegrityAlert $finding): bool => $finding->reason === AuditIntegrityReason::NoExternalSink,
        ));

        self::assertCount(1, $findings);
        self::assertFalse($findings[0]->context['anchorAvailable']);
        self::assertStringContainsString('vault:audit-anchor', $findings[0]->detail);
    }

    /**
     * An empty audit table reports sequence 0 rather than failing on the absent
     * row — `vault:audit-verify` runs on fresh installations too.
     */
    #[Test]
    public function anEmptyChainReportsSequenceZero(): void
    {
        self::assertSame(0, $this->createSubject(maxUid: false)->verify()->currentSequence);
    }

    /**
     * @param mixed $maxUid Whatever `fetchOne()` returns for the highest uid
     * @param array<string, mixed>|false $rowAtAnchor Whatever `fetchAssociative()`
     *                                                returns for the anchored row
     */
    private function createSubject(
        ?AuditLogServiceInterface $auditLogService = null,
        ?AuditSinkRegistryInterface $sinkRegistry = null,
        ?AnchorReaderInterface $anchorReader = null,
        ?ExtensionConfigurationInterface $configuration = null,
        ?EventDispatcherInterface $eventDispatcher = null,
        ?LoggerInterface $logger = null,
        ?HashChainVerificationResult $chainResult = null,
        mixed $maxUid = 0,
        array|false $rowAtAnchor = false,
        int $hmacEpoch = 3,
        SecurityProfile $profile = SecurityProfile::Standard,
    ): ChainTipAnchorService {
        if (!$auditLogService instanceof AuditLogServiceInterface) {
            $stub = self::createStub(AuditLogServiceInterface::class);
            $stub->method('verifyHashChain')->willReturn($chainResult ?? HashChainVerificationResult::valid());
            $stub->method('getLatestHash')->willReturn('tip');
            $auditLogService = $stub;
        }

        if (!$configuration instanceof ExtensionConfigurationInterface) {
            $stub = self::createStub(ExtensionConfigurationInterface::class);
            $stub->method('getAuditHmacEpoch')->willReturn($hmacEpoch);
            $stub->method('getSecurityProfile')->willReturn($profile);
            $configuration = $stub;
        }

        if (!$sinkRegistry instanceof AuditSinkRegistryInterface) {
            $stub = self::createStub(AuditSinkRegistryInterface::class);
            $stub->method('hasExternalAuditSink')->willReturn(true);
            $stub->method('dispatchAnchor')->willReturn(1);
            $sinkRegistry = $stub;
        }

        return new ChainTipAnchorService(
            $this->createConnectionPool($maxUid, $rowAtAnchor),
            $auditLogService,
            $sinkRegistry,
            $anchorReader ?? self::createStub(AnchorReaderInterface::class),
            $configuration,
            $eventDispatcher ?? self::createStub(EventDispatcherInterface::class),
            $logger ?? new NullLogger(),
        );
    }

    /**
     * The service issues exactly two queries — the highest uid (`fetchOne()`) and
     * the anchored row (`fetchAssociative()`) — so one result double serves both.
     *
     * @param array<string, mixed>|false $rowAtAnchor
     */
    private function createConnectionPool(mixed $maxUid, array|false $rowAtAnchor): ConnectionPool
    {
        $result = self::createStub(Result::class);
        $result->method('fetchOne')->willReturn($maxUid);
        $result->method('fetchAssociative')->willReturn($rowAtAnchor);

        $queryBuilder = self::createStub(QueryBuilder::class);
        $queryBuilder->method('expr')->willReturn(self::createStub(ExpressionBuilder::class));
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->method('setMaxResults')->willReturnSelf();
        $queryBuilder->method('createNamedParameter')->willReturn('?');
        $queryBuilder->method('executeQuery')->willReturn($result);

        $connection = self::createStub(Connection::class);
        $connection->method('createQueryBuilder')->willReturn($queryBuilder);

        $connectionPool = self::createStub(ConnectionPool::class);
        $connectionPool->method('getConnectionForTable')->willReturn($connection);

        return $connectionPool;
    }
}
