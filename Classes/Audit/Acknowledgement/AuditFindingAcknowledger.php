<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Acknowledgement;

use Netresearch\NrVault\Audit\Anchor\AnchorReaderInterface;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\GenericContext;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function count;
use function in_array;
use function mb_strlen;

/**
 * Records an administrator's acknowledgement of integrity findings (ADR-055).
 *
 * Append-only: the only write is one chained audit row of its own action type.
 * Nothing is rewritten or deleted, and the flagged rows stay exactly as they are.
 * When the in-database tip anchor itself is part of the finding it is reset and
 * re-armed in the same transaction, the sequence `vault:audit --reset-anchor`
 * already uses; the external anchor is published afresh afterwards.
 */
final readonly class AuditFindingAcknowledger implements AuditFindingAcknowledgerInterface
{
    public const MAX_REASON_LENGTH = 1000;

    public const MAX_TICKET_LENGTH = 100;

    /**
     * Most findings one acknowledgement row carries (64 hex characters each in
     * its `context`). Beyond this the chain has been damaged wholesale and the
     * evidence export plus an investigation come before any acknowledgement.
     */
    public const MAX_FINDINGS = 200;

    private const PSEUDO_IDENTIFIER = '__audit_findings__';

    public function __construct(
        private ChainTipAnchorServiceInterface $anchorService,
        private AuditLogServiceInterface $auditLogService,
        private AuditChainAnchorStoreInterface $anchorStore,
        private AccessControlServiceInterface $accessControlService,
        private ExtensionConfigurationInterface $extensionConfiguration,
        private ConnectionPool $connectionPool,
        private AuditSinkRegistryInterface $sinkRegistry,
        private AnchorReaderInterface $anchorReader,
    ) {}

    public function acknowledge(
        string $displayedFingerprint,
        string $reason,
        string $ticket,
        int $originalUserUid,
    ): AcknowledgementOutcome {
        // Admin bypass seam, not a group-grantable permission: an acknowledgement
        // changes what the readiness check reports, so it stays with the people
        // who can already change the vault's configuration anyway.
        if (!$this->accessControlService->isCurrentActorAdmin()
            || !$this->accessControlService->isGranted(VaultPermission::AuditView)
        ) {
            return AcknowledgementOutcome::refused(AcknowledgementStatus::NotPermitted);
        }

        if ($this->extensionConfiguration->getAuditHmacEpoch() < AuditFindingOverlay::MIN_ACKNOWLEDGEMENT_EPOCH) {
            return AcknowledgementOutcome::refused(AcknowledgementStatus::EpochTooLow);
        }

        $reason = trim($reason);
        $ticket = trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', $ticket));
        if ($reason === '' || mb_strlen($reason) > self::MAX_REASON_LENGTH || mb_strlen($ticket) > self::MAX_TICKET_LENGTH) {
            return AcknowledgementOutcome::refused(AcknowledgementStatus::ReasonInvalid);
        }

        $report = $this->anchorService->inspect();
        $open   = $report->getOpenItems();
        if ($open === []) {
            return AcknowledgementOutcome::refused(AcknowledgementStatus::NothingToAcknowledge);
        }

        // The acknowledgement covers what the administrator was shown and nothing
        // else: a finding that appeared since, or one that disappeared, changes
        // the set and the request is refused.
        if (!hash_equals(AuditFindingItem::fingerprint($open), $displayedFingerprint)) {
            return AcknowledgementOutcome::refused(AcknowledgementStatus::Stale);
        }

        if (count($open) > self::MAX_FINDINGS) {
            return AcknowledgementOutcome::refused(AcknowledgementStatus::TooManyFindings);
        }

        // Only a finding about the in-database anchor itself calls for re-arming
        // it: the items without a row that are neither bound to a prefix nor tied
        // to the external anchor.
        $anchorItems = array_filter(
            $open,
            static fn (AuditFindingItem $item): bool => $item->rangeStart === 0 && !$item->prefixBound && !$item->requiresFreshAnchor,
        );
        $resetAnchor = $anchorItems !== [] && in_array($report->anchorStatus, [
            AuditChainAnchorStatus::Violated,
            AuditChainAnchorStatus::Unreadable,
            AuditChainAnchorStatus::Unanchored,
        ], true);

        // A finding against the external anchor counts as acknowledged only once a
        // fresh anchor exists. Without a sink none can be published, so refuse
        // before writing anything.
        $needsFreshAnchor = array_filter($open, static fn (AuditFindingItem $item): bool => $item->requiresFreshAnchor) !== [];
        if ($needsFreshAnchor && !$this->sinkRegistry->hasExternalAuditSink()) {
            return AcknowledgementOutcome::refused(AcknowledgementStatus::AnchorNotPublished);
        }

        $this->write($open, $reason, $ticket, $originalUserUid, $resetAnchor);

        // Start the new verified segment BEFORE reading the verdict back: an
        // external-anchor finding is resolved by the fresh anchor, not covered.
        $published = $this->publishAnchor();

        // The tip binding only holds when the row landed directly after the tip
        // it recorded. Read the verdict back instead of assuming it.
        $after = $this->anchorService->inspect();
        $keys  = array_map(static fn (AuditFindingItem $item): string => $item->key, $open);
        foreach ($after->items as $item) {
            if (!in_array($item->key, $keys, true) || $item->isAcknowledged()) {
                continue;
            }

            return AcknowledgementOutcome::refused(
                $item->requiresFreshAnchor && $published === 0 ? AcknowledgementStatus::AnchorNotPublished : AcknowledgementStatus::NotHonoured,
            );
        }

        return new AcknowledgementOutcome(AcknowledgementStatus::Acknowledged, count($open), $published);
    }

    /**
     * @param list<AuditFindingItem> $open
     */
    private function write(array $open, string $reason, string $ticket, int $originalUserUid, bool $resetAnchor): void
    {
        $connection  = $this->connectionPool->getConnectionForTable(AuditLogService::TABLE_NAME);
        $resetAnchor = $resetAnchor && $this->anchorStore->sharesConnection($connection);

        $ranges = [];
        $codes  = [];
        foreach ($open as $item) {
            $ranges[$item->rangeStart . '-' . $item->rangeEnd] = true;
            $codes[$item->reason->value]                       = true;
        }

        $connection->beginTransaction();

        try {
            if ($resetAnchor) {
                $this->anchorStore->reset($connection);
            }

            [$tipUid, $tipHash] = $this->readTip($connection);

            $this->auditLogService->log(
                self::PSEUDO_IDENTIFIER,
                AuditAction::AuditFindingsAcknowledged->value,
                true,
                null,
                $reason,
                null,
                null,
                GenericContext::fromArray(
                    findings: implode(',', array_map(static fn (AuditFindingItem $item): string => $item->key, $open)),
                    // The old chain tip: this row is chained directly after it.
                    tipHash: $tipHash,
                    tipUid: $tipUid,
                    codes: implode(',', array_keys($codes)),
                    ranges: mb_substr(implode(',', array_keys($ranges)), 0, 300),
                    count: count($open),
                    ticket: $ticket,
                    originalUserUid: $originalUserUid,
                    // Anchor records that exist now: the ones after this position are
                    // the anchors published after the acknowledgement.
                    anchorRecords: count($this->anchorReader->readAnchors()),
                    anchorReset: $resetAnchor,
                ),
            );

            if ($resetAnchor) {
                $this->anchorStore->arm($connection);
            }

            $connection->commit();
        } catch (Throwable $e) {
            $connection->rollBack();

            throw $e;
        }
    }

    /**
     * Uid and entry hash of the newest row, read together so the pair is one
     * observation of the chain tip.
     *
     * @return array{int, string}
     */
    private function readTip(Connection $connection): array
    {
        $row = $connection->createQueryBuilder()
            ->select('uid', 'entry_hash')
            ->from(AuditLogService::TABLE_NAME)
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        if ($row === false || !is_numeric($row['uid'] ?? null)) {
            return [0, ''];
        }

        return [(int) $row['uid'], is_string($row['entry_hash'] ?? null) ? $row['entry_hash'] : ''];
    }

    /**
     * Start the new verified segment: pin the tip, which is now the
     * acknowledgement row, outside the table. Best effort, because the
     * acknowledgement itself is already committed and honoured.
     */
    private function publishAnchor(): int
    {
        try {
            return $this->anchorService->publish($this->anchorService->capture());
        } catch (Throwable) {
            return 0;
        }
    }
}
