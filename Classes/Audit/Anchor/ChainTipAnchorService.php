<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Anchor;

use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditIntegrityReport;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Event\AuditIntegrityAlertEvent;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Publishes chain-tip anchors and verifies the chain against them.
 *
 * ## The two checks that need external evidence
 *
 * `verifyHashChain()` proves internal consistency. It cannot detect a
 * `TRUNCATE TABLE tx_nrvault_audit_log` followed by fresh writes, because the
 * resulting chain is perfectly self-consistent — there is nothing left to
 * contradict it. Comparing against an anchor published earlier adds the two
 * missing facts:
 *
 *  1. **Shrinkage** — the chain is append-only, so its highest uid can never go
 *     down. `currentSequence < anchor->sequence` is a reset.
 *  2. **Substitution** — the row at the anchored sequence must still hash to the
 *     anchored tip. A different (or absent) hash there means the chain was
 *     rebuilt, even if it is now longer than the anchor.
 *
 * The anchored `hmacEpoch` gives a third check for free: an anchor witnesses the
 * protection level in force at capture time, so a chain relabelled downward is
 * detectable as `EPOCH_DOWNGRADE` even when every stored hash recomputes.
 *
 * ## Chain-error classification
 *
 * `HashChainVerificationResult` reports errors as human-readable strings keyed by
 * uid. UID gaps are read from its structured `missingUidCount`; the remaining
 * error strings are classified by the marker substrings below, with an
 * unrecognised error falling back to `HASH_MISMATCH`. The fallback is the safe
 * direction: an unclassified chain error is still a chain error, so a future
 * message added to the verifier degrades to a generic hash finding rather than
 * disappearing from the report.
 */
final readonly class ChainTipAnchorService implements ChainTipAnchorServiceInterface
{
    /**
     * Marker substring identifying an epoch-downgrade error emitted by
     * {@see AuditLogService::verifyHashChain()}.
     */
    private const ERROR_MARKER_EPOCH_DOWNGRADE = 'epoch downgrade detected';

    /**
     * Marker substring identifying a uid-gap error emitted by
     * {@see AuditLogService::verifyHashChain()}.
     */
    private const ERROR_MARKER_UID_GAP = 'uid gap detected';

    public function __construct(
        private ConnectionPool $connectionPool,
        private AuditLogServiceInterface $auditLogService,
        private AuditSinkRegistryInterface $sinkRegistry,
        private AnchorReaderInterface $anchorReader,
        private ExtensionConfigurationInterface $extensionConfiguration,
        private EventDispatcherInterface $eventDispatcher,
        private LoggerInterface $logger,
    ) {}

    public function capture(): ChainTipAnchor
    {
        $sequence = $this->fetchMaxUid();

        return new ChainTipAnchor(
            sequence: $sequence,
            chainTip: $sequence > 0 ? ($this->auditLogService->getLatestHash() ?? '') : '',
            timestamp: time(),
            hmacEpoch: $this->extensionConfiguration->getAuditHmacEpoch(),
        );
    }

    public function publish(ChainTipAnchor $anchor): int
    {
        $accepted = $this->sinkRegistry->dispatchAnchor($anchor);

        if ($accepted === 0) {
            // Not an exception: the caller (command / scheduler task) decides how
            // loudly to fail, and it has the operator context to say why. But it
            // must never look like success, so log it at error level here too.
            $this->logger->error(
                'nr-vault published an audit chain anchor to zero external sinks; '
                . 'the anchor provides no table-reset protection. Enable at least one audit sink.',
                ['sequence' => $anchor->sequence],
            );

            return 0;
        }

        $this->logger->info('nr-vault published an audit chain anchor.', [
            'sequence' => $anchor->sequence,
            'sinks' => $accepted,
        ]);

        return $accepted;
    }

    public function verify(): AuditIntegrityReport
    {
        $chainResult = $this->auditLogService->verifyHashChain();
        $currentSequence = $this->fetchMaxUid();
        $anchor = $this->anchorReader->readLatestAnchor();

        $findings = [
            ...$this->classifyChainErrors($chainResult),
            ...$this->compareWithAnchor($anchor, $currentSequence),
            ...$this->checkExternalSinkRequirement($anchor),
        ];

        $report = new AuditIntegrityReport(
            findings: $findings,
            chainValid: $chainResult->isValid(),
            currentSequence: $currentSequence,
            anchor: $anchor,
            warnings: $chainResult->warnings,
            epochCounts: $chainResult->epochCounts,
        );

        $this->dispatchFindings($report);

        return $report;
    }

    /**
     * Map hash-chain errors onto reason codes.
     *
     * One finding per reason code, not per erroring row: a broken chain commonly
     * fails every row after the break, and 10 000 identical alerts would bury the
     * signal in any SIEM. The affected-row count travels in the finding context.
     *
     * @return list<AuditIntegrityAlert>
     */
    private function classifyChainErrors(HashChainVerificationResult $result): array
    {
        $findings = [];

        if ($result->hasMissingUids()) {
            $findings[] = AuditIntegrityAlert::create(
                AuditIntegrityReason::UidGap,
                \sprintf(
                    'Audit chain has %d missing uid(s); rows were deleted from the chain.',
                    $result->missingUidCount,
                ),
                [
                    'missingUidCount' => $result->missingUidCount,
                    // Bounded sample: the full list can be up to 1000 entries and
                    // this value ends up in a syslog line and a webhook payload.
                    'missingUidSample' => implode(',', \array_slice($result->missingUids, 0, 20)),
                ],
            );
        }

        $epochDowngradeUids = [];
        $hashMismatchUids = [];

        foreach ($result->errors as $uid => $message) {
            $lower = strtolower($message);

            if (str_contains($lower, self::ERROR_MARKER_UID_GAP)) {
                // Already reported above from the structured missing-uid data.
                continue;
            }

            if (str_contains($lower, self::ERROR_MARKER_EPOCH_DOWNGRADE)) {
                $epochDowngradeUids[] = $uid;

                continue;
            }

            $hashMismatchUids[] = $uid;
        }

        if ($epochDowngradeUids !== []) {
            $findings[] = AuditIntegrityAlert::create(
                AuditIntegrityReason::EpochDowngrade,
                \sprintf(
                    'Audit chain HMAC epoch was downgraded on %d row(s); a weaker or keyless '
                    . 'verification algorithm was selected.',
                    \count($epochDowngradeUids),
                ),
                [
                    'affectedRows' => \count($epochDowngradeUids),
                    'firstUid' => $epochDowngradeUids[0],
                ],
            );
        }

        if ($hashMismatchUids !== []) {
            $findings[] = AuditIntegrityAlert::create(
                AuditIntegrityReason::HashMismatch,
                \sprintf('Audit chain hash verification failed on %d row(s).', \count($hashMismatchUids)),
                [
                    'affectedRows' => \count($hashMismatchUids),
                    'firstUid' => $hashMismatchUids[0],
                ],
            );
        }

        return $findings;
    }

    /**
     * Compare the live chain against the anchored snapshot.
     *
     * @return list<AuditIntegrityAlert>
     */
    private function compareWithAnchor(?ChainTipAnchor $anchor, int $currentSequence): array
    {
        if (!$anchor instanceof ChainTipAnchor || $anchor->isEmpty()) {
            // No baseline (or a baseline taken when the chain was still empty).
            // Absence of evidence is handled by checkExternalSinkRequirement();
            // there is nothing to compare here.
            return [];
        }

        // Check 1 — shrinkage. An append-only chain's highest uid cannot decrease.
        if ($currentSequence < $anchor->sequence) {
            return [
                AuditIntegrityAlert::create(
                    AuditIntegrityReason::TableReset,
                    \sprintf(
                        'Audit chain shrank: highest uid is %d but sequence %d was anchored on %s. '
                        . 'The audit table was truncated or rows were deleted wholesale.',
                        $currentSequence,
                        $anchor->sequence,
                        gmdate('Y-m-d H:i:s', $anchor->timestamp) . ' UTC',
                    ),
                    [
                        'currentSequence' => $currentSequence,
                        'anchoredSequence' => $anchor->sequence,
                        'anchoredAt' => $anchor->timestamp,
                    ],
                ),
            ];
        }

        $row = $this->fetchRowAt($anchor->sequence);

        // Check 2 — substitution. The anchored row must still be there, and must
        // still hash to the anchored tip.
        if ($row === null) {
            return [
                AuditIntegrityAlert::create(
                    AuditIntegrityReason::TableReset,
                    \sprintf(
                        'Anchored audit row %d no longer exists although the chain reaches uid %d; '
                        . 'the chain was rebuilt.',
                        $anchor->sequence,
                        $currentSequence,
                    ),
                    ['anchoredSequence' => $anchor->sequence, 'currentSequence' => $currentSequence],
                ),
            ];
        }

        $findings = [];

        // hash_equals() rather than !==: this compares an integrity tag, and the
        // project mandates constant-time comparison for those (AGENTS.md
        // Security Requirement #2).
        if (!hash_equals($anchor->chainTip, $row['entryHash'])) {
            $findings[] = AuditIntegrityAlert::create(
                AuditIntegrityReason::TableReset,
                \sprintf(
                    'Audit row %d hashes differently than anchored: the chain at that sequence is '
                    . 'not the chain that was anchored on %s.',
                    $anchor->sequence,
                    gmdate('Y-m-d H:i:s', $anchor->timestamp) . ' UTC',
                ),
                ['anchoredSequence' => $anchor->sequence, 'anchoredAt' => $anchor->timestamp],
            );
        }

        // Check 3 — epoch regression against external evidence. The in-chain
        // check only sees relabelling relative to other rows; the anchor sees it
        // relative to the level that was actually in force.
        if ($row['epoch'] < $anchor->hmacEpoch) {
            $findings[] = AuditIntegrityAlert::create(
                AuditIntegrityReason::EpochDowngrade,
                \sprintf(
                    'Audit row %d now reports HMAC epoch %d but epoch %d was anchored; the '
                    . 'verification algorithm was downgraded.',
                    $anchor->sequence,
                    $row['epoch'],
                    $anchor->hmacEpoch,
                ),
                [
                    'anchoredSequence' => $anchor->sequence,
                    'currentEpoch' => $row['epoch'],
                    'anchoredEpoch' => $anchor->hmacEpoch,
                ],
            );
        }

        return $findings;
    }

    /**
     * Under the hardened profile, missing external evidence is itself a finding.
     *
     * The standard profile treats sinks as opt-in, so it reports nothing here —
     * flagging a default installation for not having configured a SIEM would make
     * the check noise rather than signal.
     *
     * @return list<AuditIntegrityAlert>
     */
    private function checkExternalSinkRequirement(?ChainTipAnchor $anchor): array
    {
        try {
            $profile = $this->extensionConfiguration->getSecurityProfile();
        } catch (Throwable $e) {
            // An invalid profile value is a configuration fault the verifier must
            // not swallow into a "valid chain" verdict, but it is also not an
            // integrity finding. Log and skip this check.
            $this->logger->error(
                'nr-vault could not resolve the security profile while verifying audit integrity.',
                ['error' => $e->getMessage()],
            );

            return [];
        }

        if ($profile !== SecurityProfile::Hardened) {
            return [];
        }

        if (!$this->sinkRegistry->hasExternalAuditSink()) {
            return [
                AuditIntegrityAlert::create(
                    AuditIntegrityReason::NoExternalSink,
                    'Hardened profile requires at least one external audit sink, but none is enabled '
                    . 'and usable. The audit trail exists only in the database it is meant to protect, '
                    . 'and no chain-tip anchor can be published.',
                    ['profile' => $profile->value],
                ),
            ];
        }

        if (!$anchor instanceof ChainTipAnchor) {
            return [
                AuditIntegrityAlert::create(
                    AuditIntegrityReason::NoExternalSink,
                    'Hardened profile requires an external chain-tip anchor, but none could be read. '
                    . 'A full audit-table reset would be undetectable. Run vault:audit-anchor '
                    . '(or schedule the anchor task).',
                    ['anchorAvailable' => $this->anchorReader->isAvailable()],
                ),
            ];
        }

        return [];
    }

    /**
     * Dispatch every finding as a PSR-14 event so SIEM/notification listeners
     * fire even when nobody reads the CLI output.
     */
    private function dispatchFindings(AuditIntegrityReport $report): void
    {
        foreach ($report->findings as $finding) {
            try {
                $this->eventDispatcher->dispatch(new AuditIntegrityAlertEvent($finding));
            } catch (Throwable $e) {
                // A throwing listener must not cost us the remaining findings or
                // the report itself.
                $this->logger->error('nr-vault could not dispatch an audit integrity alert.', [
                    'reason' => $finding->reason->value,
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }

    /**
     * Highest uid in the audit table (0 = empty chain).
     */
    private function fetchMaxUid(): int
    {
        $result = $this->getQueryBuilder()
            ->select('uid')
            ->from(AuditLogService::TABLE_NAME)
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchOne();

        return is_numeric($result) ? (int) $result : 0;
    }

    /**
     * Read the entry hash and epoch of one audit row.
     *
     * @return array{entryHash: string, epoch: int}|null Null when the row is absent
     */
    private function fetchRowAt(int $uid): ?array
    {
        $queryBuilder = $this->getQueryBuilder();
        $row = $queryBuilder
            ->select('entry_hash', 'hmac_key_epoch')
            ->from(AuditLogService::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)),
            )
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        if ($row === false) {
            return null;
        }

        return [
            'entryHash' => \is_string($row['entry_hash'] ?? null) ? $row['entry_hash'] : '',
            'epoch' => is_numeric($row['hmac_key_epoch'] ?? null) ? (int) $row['hmac_key_epoch'] : 0,
        ];
    }

    private function getQueryBuilder(): QueryBuilder
    {
        return $this->connectionPool
            ->getConnectionForTable(AuditLogService::TABLE_NAME)
            ->createQueryBuilder();
    }
}
