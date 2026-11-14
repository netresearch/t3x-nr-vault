<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Acknowledgement;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditChainAnchorStatus;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\GenericContext;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Throwable;
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

        $resetAnchor = in_array($report->anchorStatus, [
            AuditChainAnchorStatus::Violated,
            AuditChainAnchorStatus::Unreadable,
            AuditChainAnchorStatus::Unanchored,
        ], true);

        $this->write($open, $reason, $ticket, $originalUserUid, $report->currentSequence, $resetAnchor);

        // The tip binding only holds when the row landed directly after the tip
        // it recorded. Read the verdict back instead of assuming it.
        $after = $this->anchorService->inspect();
        $keys  = array_map(static fn (AuditFindingItem $item): string => $item->key, $open);
        foreach ($after->items as $item) {
            if (in_array($item->key, $keys, true) && !$item->isAcknowledged()) {
                return AcknowledgementOutcome::refused(AcknowledgementStatus::NotHonoured);
            }
        }

        return new AcknowledgementOutcome(AcknowledgementStatus::Acknowledged, count($open), $this->publishAnchor());
    }

    /**
     * @param list<AuditFindingItem> $open
     */
    private function write(array $open, string $reason, string $ticket, int $originalUserUid, int $tipUid, bool $resetAnchor): void
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
                    tipHash: $this->auditLogService->getLatestHash() ?? '',
                    tipUid: $tipUid,
                    codes: implode(',', array_keys($codes)),
                    ranges: mb_substr(implode(',', array_keys($ranges)), 0, 300),
                    count: count($open),
                    ticket: $ticket,
                    originalUserUid: $originalUserUid,
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
