<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Throwable;
use TYPO3\CMS\Backend\Utility\BackendUtility;
use TYPO3\CMS\Core\DataHandling\DataHandler;

/**
 * DataHandler hook for tx_nrvault_secret TCA operations.
 *
 * Handles:
 * - Identifier immutability (prevent changes after creation)
 * - Secret encryption on save (secret_input field)
 * - Audit logging for metadata changes
 * - FormEngine integration with VaultService
 */
final class SecretTcaHook
{
    private const TABLE = 'tx_nrvault_secret';

    /**
     * Pending secrets to store after database operations.
     *
     * @var array<string, mixed> Map of temporary ID => secret value
     */
    private array $pendingSecrets = [];

    public function __construct(
        private readonly VaultServiceInterface $vaultService,
        private readonly AuditLogServiceInterface $auditService,
    ) {}

    /**
     * Called before database operations.
     * Prevents identifier changes on existing records.
     *
     * @param array<string, mixed> $fieldArray
     */
    public function processDatamap_preProcessFieldArray(
        array &$fieldArray,
        string $table,
        string|int $id,
        DataHandler $dataHandler,
    ): void {
        if ($table !== self::TABLE) {
            return;
        }

        // For existing records, prevent identifier changes
        if (!str_starts_with((string) $id, 'NEW') && isset($fieldArray['identifier'])) {
            // Get the original identifier
            $originalRecord = BackendUtility::getRecord(self::TABLE, (int) $id, 'identifier');
            $originalIdentifier = \is_string($originalRecord['identifier'] ?? null) ? $originalRecord['identifier'] : '';
            if ($originalRecord !== null && $fieldArray['identifier'] !== $originalIdentifier) {
                // Identifier change attempted - revert to original
                /** @phpstan-ignore method.internal */
                $dataHandler->log(
                    self::TABLE,
                    (int) $id,
                    2,
                    null,
                    1,
                    'Vault secret identifier cannot be changed after creation',
                );
                $fieldArray['identifier'] = $originalIdentifier;
            }
        }

        // Handle owner_uid - convert group format to simple uid
        if (isset($fieldArray['owner_uid']) && \is_string($fieldArray['owner_uid'])) {
            // Format from group field: "be_users_123" or just "123"
            $fieldArray['owner_uid'] = $this->extractUidFromGroupValue($fieldArray['owner_uid']);
        }

        // Handle scope_pid - convert group format to simple uid
        if (isset($fieldArray['scope_pid']) && \is_string($fieldArray['scope_pid']) && str_contains($fieldArray['scope_pid'], 'pages')) {
            $fieldArray['scope_pid'] = $this->extractUidFromGroupValue($fieldArray['scope_pid']);
        }

        // Handle secret_input field - extract secret value for later processing
        // The actual encryption happens in afterDatabaseOperations when we have the identifier
        if (isset($fieldArray['secret_input']) && $fieldArray['secret_input'] !== '') {
            // Store the secret temporarily keyed by record id
            $this->pendingSecrets[(string) $id] = $fieldArray['secret_input'];
        }

        // Always remove secret_input from fieldArray - it's not a real database column
        unset($fieldArray['secret_input']);
    }

    /**
     * Called after database operations.
     * Handles secret encryption and audit logging.
     *
     * @param array<string, mixed> $fieldArray
     */
    public function processDatamap_afterDatabaseOperations(
        string $status,
        string $table,
        string|int $id,
        array $fieldArray,
        DataHandler $dataHandler,
    ): void {
        if ($table !== self::TABLE) {
            return;
        }

        // Get actual UID for new records
        $uidRaw = $id;
        $originalId = (string) $id;
        if ($status === 'new') {
            $uidRaw = $dataHandler->substNEWwithIDs[$id] ?? $id;
        }
        $uid = is_numeric($uidRaw) ? (int) $uidRaw : 0;

        // Get the secret identifier for operations
        $record = BackendUtility::getRecord(self::TABLE, $uid, 'identifier,owner_uid,allowed_groups,scope_pid');
        if ($record === null) {
            return;
        }

        $identifier = \is_string($record['identifier'] ?? null) ? $record['identifier'] : '';
        $secretStored = false;

        // Handle pending secret encryption
        if (isset($this->pendingSecrets[$originalId])) {
            $secretValue = $this->pendingSecrets[$originalId];
            unset($this->pendingSecrets[$originalId]);

            // Ensure secretValue is a string
            if (!\is_string($secretValue)) {
                $secretValue = '';
            }

            if ($secretValue !== '') {
                try {
                    // Owner/group/scope ACL is persisted via the tx_nrvault_secret
                    // TCA columns (owner_uid, allowed_groups, scope_pid) by DataHandler
                    // itself, so no store() options are needed here. (Previously this
                    // passed ownerUid/allowedGroups/scopePid keys that VaultService
                    // never reads — they read owner/groups/scope_pid — so they were
                    // silently dropped; removed to avoid the impression they apply.)
                    if ($status === 'new') {
                        // New record - store the secret
                        $this->vaultService->store($identifier, $secretValue);
                        $secretStored = true;
                    } else {
                        // Existing record - rotate the secret
                        $this->vaultService->rotate($identifier, $secretValue);
                        $secretStored = true;
                    }
                } catch (Throwable $e) {
                    /** @phpstan-ignore method.internal */
                    $dataHandler->log(
                        self::TABLE,
                        $uid,
                        2,
                        null,
                        1,
                        'Failed to store secret: ' . $e->getMessage(),
                    );
                }
            }
        }

        // Determine what changed for audit context
        $changedFields = array_keys($fieldArray);
        if ($secretStored) {
            $changedFields[] = 'secret_input';
        }

        try {
            // Determine action type
            $action = 'metadata_update';
            if ($status === 'new') {
                $action = 'create';
            } elseif ($secretStored) {
                $action = 'rotate';
            }

            // Log the operation
            $this->auditService->log(
                $identifier,
                $action,
                true,
                null,
                'FormEngine edit: ' . implode(', ', $changedFields),
            );
        } catch (Throwable $e) {
            // Don't fail the save if audit logging fails
            /** @phpstan-ignore method.internal */
            $dataHandler->log(
                self::TABLE,
                $uid,
                2,
                null,
                1,
                'Audit logging failed: ' . $e->getMessage(),
            );
        }
    }

    /**
     * Called before record deletion.
     * Logs deletion to audit log.
     */
    public function processCmdmap_preProcess(
        string $command,
        string $table,
        string|int $id,
    ): void {
        if ($table !== self::TABLE || $command !== 'delete') {
            return;
        }

        $record = BackendUtility::getRecord(self::TABLE, (int) $id, 'identifier');
        if ($record === null) {
            return;
        }

        $recordIdentifier = \is_string($record['identifier'] ?? null) ? $record['identifier'] : '';
        if ($recordIdentifier === '') {
            return;
        }

        try {
            $this->auditService->log(
                $recordIdentifier,
                'delete',
                true,
                null,
                'Deleted via FormEngine',
            );
        } catch (Throwable) {
            // Don't fail the delete if audit logging fails
        }
    }

    /**
     * Extract UID from group field value format.
     *
     * @param string $value Value like "be_users_123" or "123"
     *
     * @return int The extracted UID
     */
    private function extractUidFromGroupValue(string $value): int
    {
        // Handle format: "table_uid" (e.g., "be_users_123")
        if (preg_match('/_(\d+)$/', $value, $matches)) {
            return (int) $matches[1];
        }

        // Handle simple numeric value
        return (int) $value;
    }
}
