<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

use Exception;
use Netresearch\NrVault\Hook\Dto\PendingSecret;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Throwable;
use TYPO3\CMS\Core\Messaging\FlashMessage;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;

/**
 * Runs the shared delete/store/rotate persistence decision for a pending vault
 * secret and surfaces failures as backend flash messages.
 *
 * This collaborator removes the duplicated store/rotate/delete dispatch and the
 * byte-identical flash-message helper that previously lived in both
 * {@see DataHandlerHook} and {@see FlexFormVaultHook}. Hook-specific concerns
 * (DataHandler error logging, field rollback) stay in the hooks: the persister
 * returns the caught {@see Throwable} so the caller can log it, and invokes an
 * optional rollback callback before emitting the flash message.
 */
final readonly class PendingSecretPersister
{
    public function __construct(
        private VaultServiceInterface $vaultService,
        private FlashMessageService $flashMessageService,
    ) {}

    /**
     * Persist a pending secret: delete on empty value, store when new, rotate
     * otherwise.
     *
     * On success returns null. On failure runs $onFailure (if given), emits an
     * error flash message built by $failureMessage from the caught throwable,
     * and returns that throwable so the caller can perform hook-specific logging.
     *
     * @param array<string, mixed> $storeOptions Metadata passed to store() for new secrets
     * @param string $deleteReason Audit reason for the delete branch
     * @param string $rotateReason Audit reason for the rotate branch
     * @param callable(Throwable):string $failureMessage Builds the flash message body from the error
     * @param (callable():void)|null $onFailure Optional rollback hook run before the flash message
     */
    public function persist(
        PendingSecret $pending,
        array $storeOptions,
        string $deleteReason,
        string $rotateReason,
        callable $failureMessage,
        ?callable $onFailure = null,
    ): ?Throwable {
        try {
            if ($pending->value === '') {
                // Empty value means delete the secret — but only when one existed.
                // The extractor only emits an empty-value pending for an explicit
                // clear, which always carries the existing identifier; the
                // identifier (not the checksum, which the clear control blanks)
                // is the reliable "a secret existed" signal (issue #223).
                if ($pending->identifier !== '') {
                    $this->vaultService->delete($pending->identifier, $deleteReason);
                }
            } elseif ($pending->isNew) {
                $this->vaultService->store($pending->identifier, $pending->value, $storeOptions);
            } else {
                // Update existing - use rotate to maintain audit trail.
                $this->vaultService->rotate($pending->identifier, $pending->value, $rotateReason);
            }

            return null;
        } catch (Throwable $e) {
            if ($onFailure !== null) {
                $onFailure();
            }

            $this->addFlashMessage($failureMessage($e), 'Vault Error', ContextualFeedbackSeverity::ERROR);

            return $e;
        }
    }

    /**
     * Add a flash message visible to the backend user.
     */
    private function addFlashMessage(
        string $message,
        string $title,
        ContextualFeedbackSeverity $severity,
    ): void {
        try {
            $flashMessage = new FlashMessage($message, $title, $severity, true);
            $this->flashMessageService
                ->getMessageQueueByIdentifier()
                ->addMessage($flashMessage);
        } catch (Exception) {
            // Flash message service may not be available in all contexts (e.g., CLI)
        }
    }
}
