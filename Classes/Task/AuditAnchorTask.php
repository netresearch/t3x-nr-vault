<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Task;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
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
 * Gated on `vault.configure`, the same permission the `vault:audit-anchor`
 * wrapper and `vault:audit --reset-anchor` assert. Publishing an anchor mutates
 * tamper evidence, and the permission has to follow the operation through every
 * entry point or the gate on the others is advisory: without this one, an actor
 * who may not run the command registers the task instead.
 *
 * On a default installation the gate is inert — :bash:`scheduler:run`
 * authenticates the `_cli_` administrator, who passes through the admin bypass.
 * It bites under `disableAdminOverride`, which is precisely the profile that
 * withdrew "administrator implies vault operator"; there the identity running
 * the scheduler needs a group carrying `tx_nrvault:vault.configure`. A refusal
 * fails the task loudly rather than skipping quietly: an anchoring run that did
 * not happen must never look like one that did.
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
        private readonly ?AccessControlServiceInterface $accessControlService = null,
    ) {
        parent::__construct();
    }

    public function execute(): bool
    {
        $logger = $this->getLogger();

        if (!$this->isGranted()) {
            $logger->error('Vault audit anchoring denied', [
                'missingPermission' => VaultPermission::VaultConfigure->value,
            ]);

            return false;
        }

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
        // The sequence is chain state, so it is withheld from a viewer the
        // operation itself would refuse. The list view still renders — an
        // operator who cannot see the detail must still be able to reach the
        // task to disable it.
        if (!$this->isGranted()) {
            return 'Publishes the audit chain tip to the external audit sinks';
        }

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

    private function isGranted(): bool
    {
        $accessControlService = $this->accessControlService
            ?? GeneralUtility::makeInstance(AccessControlServiceInterface::class);

        return $accessControlService->isGranted(VaultPermission::VaultConfigure);
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
