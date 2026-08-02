<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

use Exception;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Hook\Dto\PendingSecret;
use Netresearch\NrVault\Service\VaultFieldPermission;
use Netresearch\NrVault\Service\VaultFieldPermissionService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Netresearch\NrVault\Utility\VaultFieldResolver;
use Throwable;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\DataHandling\DataHandler;

/**
 * DataHandler hook for vault secret TCA fields.
 *
 * Intercepts record save operations to store vault secrets
 * and handles record deletion to clean up secrets.
 *
 * Vault identifiers are UUIDs stored directly in the database field.
 * This allows:
 * - Direct use of field value as vault identifier
 * - Reuse of secrets across multiple records (future)
 * - Portability (identifiers don't depend on table/field/uid)
 */
final class DataHandlerHook
{
    /**
     * Pending secrets to be stored after database operations.
     *
     * @var array<string, array<string|int, array<string, PendingSecret>>>
     */
    private array $pendingSecrets = [];

    /** @var array<string, list<string>> Per-table cache of vault field names */
    private array $vaultFieldCache = [];

    /**
     * Record deletes (keyed by table) whose vault-secret cleanup failed in
     * processCmdmap_preProcess() and that must therefore be cancelled in
     * processCmdmap(): deleting the record while its secret survives would
     * orphan the secret AND hide the failed (possibly denied) vault delete
     * behind an apparently successful record removal. Entries are consumed
     * when the cancel is applied.
     *
     * @var array<string, array<int, true>>
     */
    private array $deniedDeletions = [];

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly VaultServiceInterface $vaultService,
        private readonly VaultFieldResolver $vaultFieldResolver,
        private readonly PendingSecretExtractor $pendingSecretExtractor,
        private readonly PendingSecretPersister $pendingSecretPersister,
        private readonly VaultFailureReporter $failureReporter,
        private readonly VaultFieldPermissionService $fieldPermissionService,
    ) {}

    /**
     * Called before database operations.
     * Extracts vault field values and generates UUIDs for new secrets.
     *
     * @param array<string, mixed> $fieldArray
     * @param DataHandler|null $dataHandler Passed by DataHandler::process_datamap();
     *                                      optional so the hook stays callable with
     *                                      the three documented arguments
     */
    public function processDatamap_preProcessFieldArray(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        array &$fieldArray,
        string $table,
        string|int $id,
        ?DataHandler $dataHandler = null,
    ): void {
        $vaultFieldNames = $this->getVaultFieldNames($table);

        foreach ($vaultFieldNames as $fieldName) {
            // Check if field is in the data being saved
            if (!isset($fieldArray[$fieldName])) {
                continue;
            }

            $pending = $this->pendingSecretExtractor->extract($fieldArray[$fieldName]);

            // Skip if empty and no existing value
            if (!$pending instanceof PendingSecret) {
                unset($fieldArray[$fieldName]);
                continue;
            }

            // A value change was submitted for this field - re-check the TSconfig
            // permission the FormEngine element only enforced in the markup.
            if (!$this->isFieldWritable($table, $fieldName)) {
                unset($fieldArray[$fieldName]);
                $this->logDeniedWrite($table, $id, $fieldName, $dataHandler);
                continue;
            }

            // Store pending secret for post-processing
            $this->pendingSecrets[$table][$id][$fieldName] = $pending;

            // Store UUID in the database field (empty string if clearing)
            $fieldArray[$fieldName] = $pending->value !== '' ? $pending->identifier : '';
        }
    }

    /**
     * Called after database operations.
     * Stores vault secrets with the generated UUIDs.
     *
     * @param array<string, mixed> $fieldArray
     */
    public function processDatamap_afterDatabaseOperations(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        string $status,
        string $table,
        string|int $id,
        array $fieldArray,
        DataHandler $dataHandler,
    ): void {
        // Get actual UID for new records
        $uidRaw = $id;
        if ($status === 'new') {
            $uidRaw = $dataHandler->substNEWwithIDs[$id] ?? $id;
        }
        $uid = is_numeric($uidRaw) ? (int) $uidRaw : 0;

        // Process pending secrets for this record
        $pendingForRecord = $this->pendingSecrets[$table][$id] ?? [];

        foreach ($pendingForRecord as $fieldName => $pending) {
            // Roll back the dangling UUID - clear the field so no orphan
            // reference remains. New records always clear (no prior value);
            // updates keep the prior identifier IFF a prior checksum was
            // captured (i.e. the old secret actually existed).
            $rollbackValue = '';
            if (!$pending->isNew && $pending->originalChecksum !== '') {
                $rollbackValue = $pending->identifier;
            }

            // Filled by the failure-message factory below when persist() catches.
            // Captured here so the flash message and the DataHandler log detail —
            // which core replays to the same user — carry the SAME correlation
            // reference for one failure, and neither carries the cause.
            $userMessage = '';

            $error = $this->pendingSecretPersister->persist(
                $pending,
                [
                    'table' => $table,
                    'field' => $fieldName,
                    'uid' => $uid,
                    'source' => 'tca_field',
                ],
                'TCA field cleared',
                'TCA field updated',
                function (Throwable $e) use ($table, $fieldName, $uid, $pending, &$userMessage): string {
                    $userMessage = $this->failureReporter->report($e, [
                        'table' => $table,
                        'field' => $fieldName,
                        'uid' => $uid,
                        'identifier' => $pending->identifier,
                        'operation' => 'tca_field',
                    ]);

                    return \sprintf(
                        'Vault storage failed for field "%s" on %s:%d: %s The field value has been rolled back.',
                        $fieldName,
                        $table,
                        $uid,
                        $userMessage,
                    );
                },
                function () use ($table, $uid, $fieldName, $rollbackValue): void {
                    $this->rollBackField($table, $uid, $fieldName, $rollbackValue);
                },
            );

            if ($error instanceof Throwable) {
                /** @phpstan-ignore method.internal */
                $dataHandler->log(
                    $table,
                    $uid,
                    $status === 'new' ? 1 : 2,
                    null,
                    1,
                    'Vault error for field "' . $fieldName . '": ' . $userMessage,
                );
            }
        }

        // Clean up pending secrets
        unset($this->pendingSecrets[$table][$id]);
    }

    /**
     * Called before record deletion.
     * Removes associated vault secrets.
     *
     * @param bool|array<string, mixed> $pasteUpdate TYPO3 core defaults this to `false`
     *                                               but reassigns it to `$value['update']`
     *                                               (an array) on the localize / copy-to-
     *                                               language path, so the type must accept
     *                                               both to avoid a TypeError before the
     *                                               command guard below runs.
     */
    public function processCmdmap_preProcess(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        string $command,
        string $table,
        string|int $id,
        mixed $value,
        DataHandler $dataHandler,
        bool|array $pasteUpdate,
    ): void {
        if ($command !== 'delete') {
            return;
        }

        $vaultFields = $this->getVaultFieldNames($table);
        if ($vaultFields === []) {
            return;
        }

        // Read current field values to get UUIDs
        $connection = $this->connectionPool
            ->getConnectionForTable($table);

        $record = $connection->select(
            $vaultFields,
            $table,
            ['uid' => (int) $id],
        )->fetchAssociative();

        if ($record === false) {
            return;
        }

        $uid = (int) $id;

        /** @var array<string, string> $identifiers field name => vault identifier */
        $identifiers = [];
        foreach ($vaultFields as $fieldName) {
            $vaultIdentifier = $record[$fieldName] ?? '';
            if (!\is_string($vaultIdentifier)) {
                continue;
            }
            if ($vaultIdentifier === '') {
                continue;
            }

            $identifiers[$fieldName] = $vaultIdentifier;
        }

        if ($identifiers === []) {
            return;
        }

        // Preflight: a vault delete is a HARD delete with no restore path, so a
        // partially applied multi-field cleanup cannot be compensated. Assert
        // every field's delete gate BEFORE removing the first secret — a record
        // whose second field is denied must lose neither secret.
        foreach ($identifiers as $fieldName => $vaultIdentifier) {
            try {
                $this->vaultService->assertDeletable($vaultIdentifier);
            } catch (Throwable $e) {
                $this->cancelRecordDeletion(
                    $table,
                    $uid,
                    $fieldName,
                    $vaultIdentifier,
                    $e,
                    $dataHandler,
                    'No secret of this record was deleted.',
                );

                return;
            }
        }

        $deletedCount = 0;
        foreach ($identifiers as $fieldName => $vaultIdentifier) {
            try {
                $this->vaultService->delete($vaultIdentifier, 'Record deleted');
                ++$deletedCount;
            } catch (SecretNotFoundException) {
                // Idempotent: the goal state — no secret under this identifier
                // — already holds, so a dangling reference must not make the
                // record undeletable forever.
                continue;
            } catch (Throwable $e) {
                // The preflight passed, so this is a failure the gates cannot
                // predict (audit write, vault outage, revoked in between).
                // Stop the loop: every further delete would enlarge the
                // unrecoverable damage while the record is preserved anyway.
                $this->cancelRecordDeletion(
                    $table,
                    $uid,
                    $fieldName,
                    $vaultIdentifier,
                    $e,
                    $dataHandler,
                    $deletedCount === 0
                        ? 'No secret of this record was deleted.'
                        : $deletedCount . ' secret(s) of preceding fields were already deleted and cannot be restored.',
                );

                return;
            }
        }
    }

    /**
     * Cancels a record delete whose vault-secret cleanup failed in
     * processCmdmap_preProcess(). Setting $commandIsProcessed = true makes
     * core skip its own deleteAction() (DataHandler runs this hook before the
     * command switch), so the record survives together with its secret.
     */
    public function processCmdmap(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        string $command,
        string $table,
        string|int $id,
        mixed $value,
        bool &$commandIsProcessed,
        DataHandler $dataHandler,
        mixed $pasteUpdate,
    ): void {
        if ($command !== 'delete') {
            return;
        }

        $uid = is_numeric($id) ? (int) $id : 0;
        if (($this->deniedDeletions[$table][$uid] ?? false) === true) {
            unset($this->deniedDeletions[$table][$uid]);
            $commandIsProcessed = true;
        }
    }

    /**
     * Called after record copy.
     * Copies vault secrets to the new record with new UUIDs.
     *
     * @param bool|array<string, mixed> $pasteUpdate TYPO3 core defaults this to `false`
     *                                               but reassigns it to `$value['update']`
     *                                               (an array) on the localize / copy-to-
     *                                               language path, so the type must accept
     *                                               both to avoid a TypeError before the
     *                                               command guard below runs.
     */
    public function processCmdmap_postProcess(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        string $command,
        string $table,
        string|int $id,
        mixed $value,
        DataHandler $dataHandler,
        bool|array $pasteUpdate,
    ): void {
        if ($command !== 'copy') {
            return;
        }

        /** @phpstan-ignore property.internal */
        $newIdRaw = $dataHandler->copyMappingArray[$table][$id] ?? null;
        if ($newIdRaw === null) {
            return;
        }
        $newId = is_numeric($newIdRaw) ? (int) $newIdRaw : 0;

        $vaultFields = $this->getVaultFieldNames($table);
        if ($vaultFields === []) {
            return;
        }

        // Read source record to get UUIDs
        $connection = $this->connectionPool
            ->getConnectionForTable($table);

        $sourceRecord = $connection->select(
            $vaultFields,
            $table,
            ['uid' => (int) $id],
        )->fetchAssociative();

        if ($sourceRecord === false) {
            return;
        }

        $updates = [];

        foreach ($vaultFields as $fieldName) {
            $sourceIdentifier = $sourceRecord[$fieldName] ?? '';
            if (!\is_string($sourceIdentifier)) {
                continue;
            }
            if ($sourceIdentifier === '') {
                continue;
            }

            $sourceValue = null;

            try {
                // Get source secret
                $sourceValue = $this->vaultService->retrieve($sourceIdentifier);
                if ($sourceValue === null) {
                    // Not a skippable field: leaving the DataHandler-duplicated
                    // source identifier in place is precisely the outcome this
                    // method must prevent, so treat it as a copy failure.
                    throw SecretNotFoundException::forIdentifier($sourceIdentifier);
                }

                // Generate new UUID for copied record
                $newIdentifier = IdentifierValidator::generateUuid();

                // Store as new secret
                $this->vaultService->store($newIdentifier, $sourceValue, [
                    'table' => $table,
                    'field' => $fieldName,
                    'uid' => $newId,
                    'source' => 'record_copy',
                    'copied_from' => $sourceIdentifier,
                ]);

                // Track update for the copied record
                $updates[$fieldName] = $newIdentifier;
            } catch (Throwable $e) {
                // Fail closed across ALL vault fields: DataHandler has already
                // duplicated the source identifiers into the copy, so anything
                // short of clearing them leaves the copy sharing the SOURCE
                // record's secrets — rotating the copy would mutate the source,
                // deleting the copy would destroy the source's secret.
                $this->abandonCopiedSecrets(
                    $connection,
                    $table,
                    $newId,
                    $vaultFields,
                    $updates,
                    $fieldName,
                    $sourceIdentifier,
                    $e,
                    $dataHandler,
                );

                return;
            } finally {
                // Scrub the decrypted plaintext from memory (success or failure).
                if ($sourceValue !== null && $sourceValue !== '') {
                    sodium_memzero($sourceValue);
                }
            }
        }

        // Update copied record with new UUIDs
        if ($updates !== []) {
            $connection->update($table, $updates, ['uid' => $newId]);
        }
    }

    /**
     * Fail closed on a record delete whose vault cleanup did not fully succeed:
     * remember the cancellation for {@see processCmdmap()}, log the cause
     * server-side and tell the editor the record was preserved.
     *
     * Deleting the record while a secret survives would orphan that secret AND
     * hide the failed (possibly denied) vault delete behind an apparently
     * successful record removal.
     */
    private function cancelRecordDeletion(
        string $table,
        int $uid,
        string $fieldName,
        string $vaultIdentifier,
        Throwable $error,
        DataHandler $dataHandler,
        string $scopeNotice,
    ): void {
        $userMessage = $this->failureReporter->report($error, [
            'table' => $table,
            'field' => $fieldName,
            'uid' => $uid,
            'identifier' => $vaultIdentifier,
            'operation' => 'delete',
        ]);

        $this->deniedDeletions[$table][$uid] = true;

        /** @phpstan-ignore method.internal */
        $dataHandler->log(
            $table,
            $uid,
            3,
            null,
            1,
            'Vault error during delete for field "' . $fieldName . '": ' . $userMessage
            . ' The record was preserved. ' . $scopeNotice,
        );
    }

    /**
     * Undo a partially completed record copy.
     *
     * Deletes every secret already cloned for this copy and blanks EVERY vault
     * field of the copied record — not only the ones that were cloned, because
     * the untouched ones still carry the source identifiers DataHandler
     * duplicated. The copy therefore ends up with no secrets at all instead of
     * silently aliasing the source's.
     *
     * The failure is logged as a system error (`error = 2`), one level above
     * the per-field warning the previous implementation emitted: the editor now
     * has to re-enter the secrets of the copy, which is not a detail they may
     * miss in a flash-message list.
     *
     * @param list<string> $vaultFields every vault field of the table
     * @param array<string, string> $clonedUpdates field name => identifier of the secrets cloned so far
     */
    private function abandonCopiedSecrets(
        Connection $connection,
        string $table,
        int $newId,
        array $vaultFields,
        array $clonedUpdates,
        string $failedField,
        string $sourceIdentifier,
        Throwable $error,
        DataHandler $dataHandler,
    ): void {
        foreach ($clonedUpdates as $clonedField => $clonedIdentifier) {
            try {
                $this->vaultService->delete($clonedIdentifier, 'Record copy rolled back');
            } catch (Throwable $compensationError) {
                // The clone is orphaned rather than dangerous (nothing
                // references it any more) — record it for the administrator and
                // keep rolling back the remaining fields.
                $this->failureReporter->report($compensationError, [
                    'table' => $table,
                    'field' => $clonedField,
                    'uid' => $newId,
                    'identifier' => $clonedIdentifier,
                    'operation' => 'copy_rollback',
                ]);
            }
        }

        $blanked = $this->blankVaultFields($connection, $table, $newId, $vaultFields);

        $userMessage = $this->failureReporter->report($error, [
            'table' => $table,
            'field' => $failedField,
            'uid' => $newId,
            'identifier' => $sourceIdentifier,
            'operation' => 'copy',
        ]);

        /** @phpstan-ignore method.internal */
        $dataHandler->log(
            $table,
            $newId,
            1,
            null,
            2,
            'Vault error during copy for field "' . $failedField . '": ' . $userMessage
            . ($blanked
                ? ' No secret was copied; all vault fields of the new record were cleared and must be filled in again.'
                : ' No secret was copied, but clearing the vault fields of the new record FAILED — it may still'
                    . ' reference the secrets of the source record and needs manual review.'),
        );
    }

    /**
     * Clear every vault field of a record.
     *
     * Best-effort: if this write fails the copy keeps the source identifiers —
     * the caller's DataHandler log entry states which of the two end states was
     * reached. There is nothing better to fall back to; the copy exists either
     * way.
     *
     * @param list<string> $vaultFields
     *
     * @return bool True when the fields were cleared, false when the write failed
     */
    private function blankVaultFields(Connection $connection, string $table, int $uid, array $vaultFields): bool
    {
        if ($uid <= 0 || $vaultFields === []) {
            return false;
        }

        try {
            $connection->update($table, array_fill_keys($vaultFields, ''), ['uid' => $uid]);

            return true;
        } catch (Exception) {
            return false;
        }
    }

    /**
     * Decide whether the current backend user may write this vault field.
     *
     * Mirrors the FormEngine decision in
     * {@see \Netresearch\NrVault\Form\Element\VaultSecretElement}: that element
     * renders the input `readonly` when TSconfig denies `edit` OR sets
     * `readOnly`, so both settings mean "not writable" here as well. Both paths
     * ask the same {@see VaultFieldPermissionService}, which resolves
     * `vault.permissions` from the page-0 TSconfig regardless of the record's
     * page - so renderer and write path always see the same configuration.
     *
     * Without a backend user there is no TSconfig subject at all (CLI imports,
     * scheduler tasks): those callers keep their previous behaviour, the vault's
     * own ACL still governs the resulting store/rotate/delete.
     */
    private function isFieldWritable(string $table, string $fieldName): bool
    {
        $backendUser = $GLOBALS['BE_USER'] ?? null;
        if (!$backendUser instanceof BackendUserAuthentication) {
            return true;
        }

        return $this->fieldPermissionService->isAllowed($table, $fieldName, VaultFieldPermission::Edit)
            && !$this->fieldPermissionService->isReadOnly($table, $fieldName);
    }

    /**
     * Record a discarded vault field value in the DataHandler log.
     *
     * The entry is written with an error severity, so the backend surfaces it
     * as a flash message via `DataHandler::printLogErrorMessages()` - the editor
     * must not silently lose the value they typed.
     */
    private function logDeniedWrite(
        string $table,
        string|int $id,
        string $fieldName,
        ?DataHandler $dataHandler,
    ): void {
        if (!$dataHandler instanceof DataHandler) {
            return;
        }

        $uid = is_numeric($id) ? (int) $id : 0;

        /** @phpstan-ignore method.internal */
        $dataHandler->log(
            $table,
            $uid,
            $uid === 0 ? 1 : 2,
            null,
            1,
            'Vault field "' . $fieldName . '" is not editable for this user (TSconfig vault.permissions): the submitted value was discarded and the stored secret left unchanged.',
        );
    }

    /**
     * Roll back a field value after a failed vault operation.
     *
     * For new secrets, clears the field (removes the dangling UUID).
     * For updates, keeps the existing identifier (the old secret still exists).
     */
    private function rollBackField(string $table, int $uid, string $fieldName, string $rollBackValue): void
    {
        if ($uid <= 0) {
            return;
        }

        try {
            $this->connectionPool
                ->getConnectionForTable($table)
                ->update($table, [$fieldName => $rollBackValue], ['uid' => $uid]);
        } catch (Exception) {
            // Best-effort rollback - if this also fails, the DataHandler log entry
            // from the caller already documents the problem
        }
    }

    /**
     * Get field names with vaultSecret renderType from TCA schema.
     *
     * Discovery is delegated to {@see VaultFieldResolver}; results are cached
     * per table for the lifetime of this hook instance.
     *
     * @return list<string>
     */
    private function getVaultFieldNames(string $table): array
    {
        return $this->vaultFieldCache[$table]
            ??= $this->vaultFieldResolver->getVaultFieldsForTable($table);
    }
}
