<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Task;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;
use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Scheduler\Task\AbstractTask;

/**
 * Scheduler counterpart of `vault:audit-verify`.
 *
 * Verifies the audit hash chain and compares it against the last published
 * chain-tip anchor. Findings are dispatched as
 * {@see \Netresearch\NrVault\Event\AuditIntegrityAlertEvent} by the anchor
 * service itself, so SIEM and notification listeners fire from a scheduled run
 * exactly as they do from the CLI — nobody has to be watching the scheduler log.
 *
 * Configuration (TCA field on `tx_scheduler_task`):
 * - `nr_vault_tamper_only`: when set, the task only fails on tamper evidence
 *   (`HASH_MISMATCH`, `UID_GAP`, `TABLE_RESET`, `EPOCH_DOWNGRADE`) and treats
 *   configuration/delivery findings (`NO_EXTERNAL_SINK`, `SINK_FAILURE`) as
 *   warnings. Useful while external sinks are still being rolled out, so a
 *   pending SIEM integration does not mask a real tamper alarm behind a
 *   permanently red task.
 */
final class AuditVerifyTask extends AbstractTask
{
    /** Only fail the task on tamper evidence, not on configuration findings. */
    protected bool $tamperOnly = false;

    public function __construct(
        private readonly ?ChainTipAnchorServiceInterface $anchorService = null,
        private readonly ?LogManager $logManager = null,
    ) {
        parent::__construct();
    }

    /**
     * @return array<string, mixed>
     */
    public function getTaskParameters(): array
    {
        return [
            'nr_vault_tamper_only' => $this->tamperOnly ? 1 : 0,
        ];
    }

    /**
     * The scheduler hands over whatever the TCA record holds, so the parameter
     * stays as wide as the parent's untyped `array` rather than narrowing to
     * `array<string, mixed>` (which would break contravariance).
     *
     * @param array<array-key, mixed> $parameters
     */
    public function setTaskParameters(array $parameters): void
    {
        $this->tamperOnly = (bool) ($parameters['nr_vault_tamper_only'] ?? false);
    }

    public function execute(): bool
    {
        $logger = $this->getLogger();

        try {
            $report = $this->getAnchorService()->verify();
        } catch (Throwable $e) {
            // A verification that could not run must never report success.
            $logger->error('Vault audit integrity verification could not run', ['error' => $e->getMessage()]);

            return false;
        }

        if ($report->isValid()) {
            $logger->info('Vault audit integrity verified', [
                'sequence' => $report->currentSequence,
                'anchoredSequence' => $report->anchor?->sequence,
            ]);

            return true;
        }

        $codes = implode(',', $report->getReasonCodes());
        $context = [
            'reasonCodes' => $codes,
            'sequence' => $report->currentSequence,
            'tamperEvidence' => $report->hasTamperEvidence(),
        ];

        if ($report->hasTamperEvidence()) {
            $logger->critical('Vault audit integrity FAILED — possible tampering', $context);

            return false;
        }

        $logger->warning('Vault audit integrity findings without tamper evidence', $context);

        // tamperOnly => configuration/delivery findings are warnings, task passes.
        return $this->tamperOnly;
    }

    /**
     * Additional information shown in the scheduler module.
     */
    public function getAdditionalInformation(): string
    {
        return $this->tamperOnly
            ? 'Verifies the audit hash chain and external anchor (fails on tamper evidence only)'
            : 'Verifies the audit hash chain and external anchor (fails on any finding)';
    }

    private function getAnchorService(): ChainTipAnchorServiceInterface
    {
        return $this->anchorService ?? GeneralUtility::makeInstance(ChainTipAnchorServiceInterface::class);
    }

    private function getLogger(): LoggerInterface
    {
        if (!$this->logManager instanceof LogManager) {
            return new NullLogger();
        }

        return $this->logManager->getLogger(self::class);
    }
}
