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
 * Scheduler counterpart of `vault:audit-anchor`.
 *
 * Publishes the current audit chain tip to the external sinks on a schedule. The
 * interval IS the security parameter: entries written since the last anchor are
 * the window an attacker who truncates the audit table can still hide. Hourly is
 * a reasonable starting point; daily is the loosest defensible setting for a
 * vault under audit.
 *
 * The task FAILS (returns false) when no sink accepted the anchor — an anchoring
 * run that reached nothing outside the database provides no reset protection, and
 * a green scheduler entry would misreport that as working tamper evidence.
 *
 * Constructor arguments are nullable and lazily resolved via
 * `GeneralUtility::makeInstance()` because the scheduler unserializes task
 * objects without going through the DI container — the same pattern as
 * {@see OrphanCleanupTask}.
 */
final class AuditAnchorTask extends AbstractTask
{
    public function __construct(
        private readonly ?ChainTipAnchorServiceInterface $anchorService = null,
        private readonly ?LogManager $logManager = null,
    ) {
        parent::__construct();
    }

    public function execute(): bool
    {
        $logger = $this->getLogger();

        try {
            $anchorService = $this->getAnchorService();
            $anchor = $anchorService->capture();
            $published = $anchorService->publish($anchor);
        } catch (Throwable $e) {
            $logger->error('Vault audit anchoring failed', ['error' => $e->getMessage()]);

            return false;
        }

        if ($published === 0) {
            $logger->error('Vault audit anchoring reached no external sink', [
                'sequence' => $anchor->sequence,
            ]);

            return false;
        }

        $logger->info('Vault audit chain anchored', [
            'sequence' => $anchor->sequence,
            'sinks' => $published,
        ]);

        return true;
    }

    /**
     * Additional information shown in the scheduler module.
     */
    public function getAdditionalInformation(): string
    {
        try {
            $anchor = $this->getAnchorService()->capture();
        } catch (Throwable) {
            // The scheduler list view must render even when the vault is
            // misconfigured (missing master key, unavailable database).
            return 'Publishes the audit chain tip to the external audit sinks';
        }

        return \sprintf(
            'Publishes the audit chain tip to the external audit sinks (current sequence: %d)',
            $anchor->sequence,
        );
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
