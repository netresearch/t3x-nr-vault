<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Anchor;

use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingItem;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingOverlay;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingOverlayInterface;
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

use function array_slice;
use function count;
use function is_string;
use function sprintf;

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
    public function __construct(
        private ConnectionPool $connectionPool,
        private AuditLogServiceInterface $auditLogService,
        private AuditSinkRegistryInterface $sinkRegistry,
        private AnchorReaderInterface $anchorReader,
        private ExtensionConfigurationInterface $extensionConfiguration,
        private EventDispatcherInterface $eventDispatcher,
        private LoggerInterface $logger,
        private AuditFindingOverlayInterface $overlay,
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
            'sinks'    => $accepted,
        ]);

        return $accepted;
    }

    public function verify(): AuditIntegrityReport
    {
        $report = $this->inspect();

        $this->dispatchFindings($report);

        return $report;
    }

    public function inspect(): AuditIntegrityReport
    {
        $chainResult     = $this->auditLogService->verifyHashChain();
        $currentSequence = $this->fetchMaxUid();
        $anchor          = $this->anchorReader->readLatestAnchor();

        $chainItems   = $this->overlay->chainItems($chainResult);
        $anchorAlerts = $this->compareWithAnchor($anchor, $currentSequence);
        $anchorItems  = [];
        foreach ($anchorAlerts as $alert) {
            // Bound to the chain prefix the administrator saw, and covered only
            // once a fresh anchor exists (see requireFreshAnchor()).
            $anchorItems[] = new AuditFindingItem(
                (string) $alert->context['ackKey'],
                $alert->reason,
                0,
                0,
                $alert->detail,
                null,
                true,
                true,
            );
        }

        $items        = $this->requireFreshAnchor($this->overlay->apply([...$chainItems, ...$anchorItems], $chainResult));
        $acknowledged = [];
        foreach ($items as $item) {
            if ($item->isAcknowledged()) {
                $acknowledged[$item->key] = true;
            }
        }

        $openChain = array_values(array_filter(
            $chainItems,
            static fn (AuditFindingItem $item): bool => !isset($acknowledged[$item->key]),
        ));
        $openAnchor = array_values(array_filter(
            $anchorAlerts,
            static fn (AuditIntegrityAlert $alert): bool => !isset($acknowledged[(string) $alert->context['ackKey']]),
        ));

        $findings = [
            ...$this->classifyChainItems($openChain, $chainResult),
            ...$openAnchor,
            ...$this->checkExternalSinkRequirement($anchor),
        ];

        return new AuditIntegrityReport(
            findings: $findings,
            chainValid: $chainResult->isValid(),
            currentSequence: $currentSequence,
            anchor: $anchor,
            warnings: $chainResult->warnings,
            epochCounts: $chainResult->epochCounts,
            items: $items,
            tipHash: $currentSequence > 0 ? ($this->auditLogService->getLatestHash() ?? '') : '',
            anchorStatus: $chainResult->anchorStatus,
        );
    }

    /**
     * Withdraw the acknowledgement of an external-anchor finding unless an anchor
     * was published after the acknowledgement row was written.
     *
     * The reader returns the anchor with the highest SEQUENCE, which after a
     * restore is still the old one, so the finding keeps being raised; the fresh
     * anchor proves that a new baseline exists, and a replayed old anchor file
     * (without it) reopens the finding.
     *
     * @param list<AuditFindingItem> $items
     *
     * @return list<AuditFindingItem>
     */
    private function requireFreshAnchor(array $items): array
    {
        $result = [];
        foreach ($items as $item) {
            if ($item->requiresFreshAnchor && $item->acknowledgedBy !== null
                && !$this->anchorReader->hasAnchorSince($this->fetchCreationTime($item->acknowledgedBy))
            ) {
                $item = $item->withoutAcknowledgement();
            }

            $result[] = $item;
        }

        return $result;
    }

    private function fetchCreationTime(int $uid): int
    {
        $queryBuilder = $this->getQueryBuilder();
        $time         = $queryBuilder
            ->select('crdate')
            ->from(AuditLogService::TABLE_NAME)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return is_numeric($time) ? (int) $time : PHP_INT_MAX;
    }

    /**
     * Map the open chain items onto reason codes.
     *
     * One finding per reason code, not per erroring row: a broken chain commonly
     * fails every row after the break, and 10 000 identical alerts would bury the
     * signal in any SIEM. The affected-row count travels in the finding context.
     *
     * @param list<AuditFindingItem> $items
     *
     * @return list<AuditIntegrityAlert>
     */
    private function classifyChainItems(array $items, HashChainVerificationResult $result): array
    {
        $findings = [];
        $gaps     = [];
        $epoch    = [];
        $hash     = [];

        foreach ($items as $item) {
            match ($item->reason) {
                AuditIntegrityReason::UidGap         => $gaps[]  = $item,
                AuditIntegrityReason::EpochDowngrade => $epoch[] = $item,
                default                              => $hash[]  = $item,
            };
        }

        if ($gaps !== []) {
            $missing = 0;
            $sample  = [];
            foreach ($gaps as $gap) {
                $missing += $gap->rangeEnd - $gap->rangeStart + 1;
                for ($uid = $gap->rangeStart; $uid <= $gap->rangeEnd && count($sample) < 20; ++$uid) {
                    $sample[] = $uid;
                }
            }

            $findings[] = $this->uidGapAlert($missing, $sample);
        } elseif ($result->gaps === [] && $result->hasMissingUids()) {
            // A result built without structured gaps (older producers): fall
            // back to the totals it carries. Not acknowledgeable.
            $findings[] = $this->uidGapAlert($result->missingUidCount, array_slice($result->missingUids, 0, 20));
        }

        if ($epoch !== []) {
            $findings[] = AuditIntegrityAlert::create(
                AuditIntegrityReason::EpochDowngrade,
                sprintf(
                    'Audit chain HMAC epoch was downgraded on %d row(s); a weaker or keyless '
                    . 'verification algorithm was selected.',
                    count($epoch),
                ),
                [
                    'affectedRows' => count($epoch),
                    'firstUid'     => $epoch[0]->rangeStart,
                ],
            );
        }

        if ($hash !== []) {
            $findings[] = AuditIntegrityAlert::create(
                AuditIntegrityReason::HashMismatch,
                sprintf('Audit chain hash verification failed on %d row(s).', count($hash)),
                [
                    'affectedRows' => count($hash),
                    'firstUid'     => $hash[0]->rangeStart,
                ],
            );
        }

        return $findings;
    }

    /**
     * @param list<int> $sample
     */
    private function uidGapAlert(int $missingUidCount, array $sample): AuditIntegrityAlert
    {
        return AuditIntegrityAlert::create(
            AuditIntegrityReason::UidGap,
            sprintf('Audit chain has %d missing uid(s); rows were deleted from the chain.', $missingUidCount),
            [
                'missingUidCount' => $missingUidCount,
                // Bounded sample: the full list can be up to 1000 entries and
                // this value ends up in a syslog line and a webhook payload.
                'missingUidSample' => implode(',', $sample),
            ],
        );
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
                    sprintf(
                        'Audit chain shrank: highest uid is %d but sequence %d was anchored on %s. '
                        . 'The audit table was truncated or rows were deleted wholesale.',
                        $currentSequence,
                        $anchor->sequence,
                        gmdate('Y-m-d H:i:s', $anchor->timestamp) . ' UTC',
                    ),
                    [
                        'currentSequence'  => $currentSequence,
                        'anchoredSequence' => $anchor->sequence,
                        'anchoredAt'       => $anchor->timestamp,
                        'ackKey'           => $this->anchorKey(AuditIntegrityReason::TableReset, $anchor),
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
                    sprintf(
                        'Anchored audit row %d no longer exists although the chain reaches uid %d; '
                        . 'the chain was rebuilt.',
                        $anchor->sequence,
                        $currentSequence,
                    ),
                    [
                        'anchoredSequence' => $anchor->sequence,
                        'currentSequence'  => $currentSequence,
                        'ackKey'           => $this->anchorKey(AuditIntegrityReason::TableReset, $anchor),
                    ],
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
                sprintf(
                    'Audit row %d hashes differently than anchored: the chain at that sequence is '
                    . 'not the chain that was anchored on %s.',
                    $anchor->sequence,
                    gmdate('Y-m-d H:i:s', $anchor->timestamp) . ' UTC',
                ),
                [
                    'anchoredSequence' => $anchor->sequence,
                    'anchoredAt'       => $anchor->timestamp,
                    'ackKey'           => $this->anchorKey(AuditIntegrityReason::TableReset, $anchor),
                ],
            );
        }

        // Check 3 — epoch regression against external evidence. The in-chain
        // check only sees relabelling relative to other rows; the anchor sees it
        // relative to the level that was actually in force.
        if ($row['epoch'] < $anchor->hmacEpoch) {
            $findings[] = AuditIntegrityAlert::create(
                AuditIntegrityReason::EpochDowngrade,
                sprintf(
                    'Audit row %d now reports HMAC epoch %d but epoch %d was anchored; the '
                    . 'verification algorithm was downgraded.',
                    $anchor->sequence,
                    $row['epoch'],
                    $anchor->hmacEpoch,
                ),
                [
                    'anchoredSequence' => $anchor->sequence,
                    'currentEpoch'     => $row['epoch'],
                    'anchoredEpoch'    => $anchor->hmacEpoch,
                    'ackKey'           => $this->anchorKey(AuditIntegrityReason::EpochDowngrade, $anchor),
                ],
            );
        }

        return $findings;
    }

    /**
     * Identity of an anchor finding for acknowledgement: which anchor was
     * compared, how it differed, and what the chain held at that point.
     */
    private function anchorKey(AuditIntegrityReason $reason, ChainTipAnchor $anchor): string
    {
        // The anchor is the identity, not how the chain differs from it: after a
        // restore the same anchor reads as a shrunken, then as a substituted
        // chain. What stops a later incident from inheriting the acknowledgement
        // is the prefix binding of the item, not a state in the key.
        return AuditFindingOverlay::key(
            $reason->value,
            (string) $anchor->sequence,
            $anchor->chainTip,
            (string) $anchor->timestamp,
            (string) $anchor->hmacEpoch,
        );
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
                    'error'  => $e->getMessage(),
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
        $row          = $queryBuilder
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
            'entryHash' => is_string($row['entry_hash'] ?? null) ? $row['entry_hash'] : '',
            'epoch'     => is_numeric($row['hmac_key_epoch'] ?? null) ? (int) $row['hmac_key_epoch'] : 0,
        ];
    }

    private function getQueryBuilder(): QueryBuilder
    {
        return $this->connectionPool
            ->getConnectionForTable(AuditLogService::TABLE_NAME)
            ->createQueryBuilder();
    }
}
