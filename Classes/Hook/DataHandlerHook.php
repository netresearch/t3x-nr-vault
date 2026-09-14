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
     * The DataHandler commands that duplicate a record.
     *
     * Every one of them writes the new record through a nested
     * `process_datamap()` pass in which the vault field carries the SOURCE
     * record's identifier as a plain string — indistinguishable from a freshly
     * typed secret. {@see processDatamap_preProcessFieldArray()} therefore
     * refuses to interpret such a value while one of these commands is running,
     * and {@see processCmdmap_postProcess()} clones the source secrets
     * afterwards, for every record the command duplicated.
     */
    private const DUPLICATION_COMMANDS = ['copy', 'localize', 'copyToLanguage', 'inlineLocalizeSynchronize'];

    /**
     * Pending secrets to be stored after database operations.
     *
     * @var array<string, array<string|int, array<string, PendingSecret>>>
     */
    private array $pendingSecrets = [];

    /**
     * The DataHandler instances that are currently between the
     * `processCmdmap_preProcess()` and `processCmdmap_postProcess()` call of a
     * duplicating command, each with the number of such commands in flight.
     *
     * Counted rather than flagged: a hook of another extension may run a nested
     * command inside one, and the inner command's postProcess must not end the
     * outer one's duplication context.
     *
     * This is the ONLY signal the datamap pass uses. Keying on "the value looks
     * like a vault identifier" instead would let any caller point a new record
     * at an existing secret by submitting its identifier, bypassing that
     * secret's access control.
     *
     * @var array<int, int> spl_object_id() of the DataHandler => commands in flight
     */
    private array $duplicationCommands = [];

    /** @var array<string, list<string>> Per-table cache of vault field names */
    private array $vaultFieldCache = [];

    /** @var array<string, list<string>> Per-table cache of vault fields shared with translations */
    private array $sharedVaultFieldCache = [];

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

            // The field is not translatable (`l10n_mode = exclude`) and this
            // record is a translation: its secret is the default-language
            // record's secret. Core's DataMapProcessor pushes the default
            // record's value into every translation's data map — as the stored
            // identifier on an ordinary update, and as the whole submitted
            // value when the default record's field is written — and both
            // shapes reach this hook under a translation's uid. The only
            // correct outcome is the identifier the DEFAULT record holds, read
            // from the database and never from the request, so nothing a caller
            // submits can point a translation at a foreign secret.
            $sharedIdentifier = $this->resolveSharedTranslationIdentifier($table, $fieldName, $id, $fieldArray);
            if ($sharedIdentifier !== null) {
                $fieldArray[$fieldName] = $sharedIdentifier;
                continue;
            }

            // A duplicating command (copy, localize, …) is running and this is
            // the nested pass that writes the new record: the value is the
            // SOURCE record's stored identifier, not a secret anybody typed.
            // Clear it — processCmdmap_postProcess() clones the source secret
            // into the new record afterwards. Keeping the identifier would let
            // the two records share one secret until then; storing it as a
            // value would create a secret whose plaintext is an identifier.
            if ($this->isRecordDuplicationPass($fieldArray[$fieldName], $id, $dataHandler)) {
                $fieldArray[$fieldName] = '';
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
        if (\in_array($command, self::DUPLICATION_COMMANDS, true)) {
            $handlerId = spl_object_id($dataHandler);
            $this->duplicationCommands[$handlerId] = ($this->duplicationCommands[$handlerId] ?? 0) + 1;
        }

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

        // A secret another live record still references is not this record's to
        // delete: a translation shares the default-language record's secret for
        // every `l10n_mode = exclude` field, so deleting the translation must
        // leave that secret — and the default record's credential — intact.
        foreach ($identifiers as $fieldName => $vaultIdentifier) {
            if ($this->isIdentifierReferencedElsewhere($table, $fieldName, $vaultIdentifier, $uid)) {
                unset($identifiers[$fieldName]);
            }
        }

        if ($identifiers === []) {
            return;
        }

        // Preflight: a vault delete cannot be undone through the vault (no
        // restore path), so a partially applied multi-field cleanup cannot be
        // compensated. Assert
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
     * Called after a record was duplicated.
     * Gives every new record its own clone of the source record's secrets.
     *
     * The command names one record, but a single command duplicates many: a
     * page copy duplicates the records on the page, a copy or localize carries
     * the inline children along (through `copyRecord_raw()`, which runs no
     * datamap hook at all), and a copy also duplicates the source's
     * translations. DataHandler records all of them in `copyMappingArray`, so
     * that map — not the command's own uid — is the list of records that need a
     * secret of their own.
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
        if (!\in_array($command, self::DUPLICATION_COMMANDS, true)) {
            return;
        }

        try {
            /** @phpstan-ignore property.internal */
            foreach ($dataHandler->copyMappingArray as $duplicatedTable => $idMap) {
                if (!\is_string($duplicatedTable) || !\is_array($idMap)) {
                    continue;
                }

                $vaultFields = $this->getVaultFieldNames($duplicatedTable);
                if ($vaultFields === []) {
                    continue;
                }

                $connection = $this->connectionPool->getConnectionForTable($duplicatedTable);

                /** @var mixed $newIdRaw */
                foreach ($idMap as $sourceIdRaw => $newIdRaw) {
                    $sourceUid = is_numeric($sourceIdRaw) ? (int) $sourceIdRaw : 0;
                    $newUid = is_numeric($newIdRaw) ? (int) $newIdRaw : 0;
                    if ($sourceUid <= 0 || $newUid <= 0) {
                        continue;
                    }

                    $this->cloneSecretsIntoDuplicate(
                        $connection,
                        $duplicatedTable,
                        $sourceUid,
                        $newUid,
                        $vaultFields,
                        $dataHandler,
                    );
                }
            }
        } finally {
            // Leaving the context set would make the datamap pass discard a
            // scalar vault value of a later, unrelated write in this request.
            $this->endDuplicationCommand($dataHandler);
        }
    }

    /**
     * Forget one duplicating command of this DataHandler.
     */
    private function endDuplicationCommand(DataHandler $dataHandler): void
    {
        $handlerId = spl_object_id($dataHandler);
        $remaining = ($this->duplicationCommands[$handlerId] ?? 0) - 1;

        if ($remaining > 0) {
            $this->duplicationCommands[$handlerId] = $remaining;

            return;
        }

        unset($this->duplicationCommands[$handlerId]);
    }

    /**
     * Decide whether a submitted vault field value is the nested pass of a
     * record duplication rather than a value a user entered.
     *
     * All three conditions must hold, and none of them is under the control of
     * a datamap caller:
     * - a duplicating command of THIS hook instance is currently running,
     * - the record is being created (`NEW…`), as every duplication does,
     * - the DataHandler is core's internal copy instance, which `getLocalTCE()`
     *   marks by disabling transformations.
     *
     * Array-shaped values are never duplication input: they are what the vault
     * FormEngine element submits.
     */
    private function isRecordDuplicationPass(mixed $value, string|int $id, ?DataHandler $dataHandler): bool
    {
        return $this->duplicationCommands !== []
            && !\is_array($value)
            && \is_string($id)
            && str_starts_with($id, 'NEW')
            && $dataHandler instanceof DataHandler
            && $dataHandler->dontProcessTransformations;
    }

    /**
     * Clone every vault secret of a source record into the record that was
     * duplicated from it.
     *
     * @param list<string> $vaultFields
     */
    private function cloneSecretsIntoDuplicate(
        Connection $connection,
        string $table,
        int $id,
        int $newId,
        array $vaultFields,
        DataHandler $dataHandler,
    ): void {
        $sourceRecord = $connection->select(
            $vaultFields,
            $table,
            ['uid' => $id],
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

            // The new record is a translation and this field is not
            // translatable: it holds the default-language record's identifier
            // on purpose. Cloning would fork the shared secret, so that
            // rotating the default record's credential would leave the
            // translation on the old one.
            if ($this->isSharedTranslationField($table, $fieldName, $newId)) {
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
     * The identifier a translation must hold for a vault field it shares with
     * its default-language record, or null when this is not such a case.
     *
     * @param array<string, mixed> $fieldArray
     */
    private function resolveSharedTranslationIdentifier(
        string $table,
        string $fieldName,
        string|int $id,
        array $fieldArray,
    ): ?string {
        if (!\in_array($fieldName, $this->getTranslationSharedFields($table), true)) {
            return null;
        }

        $parentUid = $this->resolveTranslationParentUid($table, $id, $fieldArray);
        if ($parentUid <= 0) {
            return null;
        }

        return $this->readColumn($table, $parentUid, $fieldName);
    }

    /**
     * The uid of the default-language record a write belongs to, or 0 when the
     * record is not a translation.
     *
     * A record being localized carries the pointer in the same field array; an
     * ordinary update of an existing translation does not, so it is read from
     * the persisted row.
     *
     * @param array<string, mixed> $fieldArray
     */
    private function resolveTranslationParentUid(string $table, string|int $id, array $fieldArray): int
    {
        $parentField = $this->vaultFieldResolver->getTranslationParentField($table);
        if ($parentField === null) {
            return 0;
        }

        /** @var mixed $submitted */
        $submitted = $fieldArray[$parentField] ?? null;
        if (is_numeric($submitted)) {
            return (int) $submitted;
        }

        if (!is_numeric($id)) {
            return 0;
        }

        $stored = $this->readColumn($table, (int) $id, $parentField);

        return is_numeric($stored) ? (int) $stored : 0;
    }

    /**
     * A shared field of a translated record keeps the default-language
     * record's identifier, so a duplication must not clone it: the clone would
     * fork the shared secret.
     */
    private function isSharedTranslationField(string $table, string $fieldName, int $uid): bool
    {
        return \in_array($fieldName, $this->getTranslationSharedFields($table), true)
            && $this->resolveTranslationParentUid($table, $uid, []) > 0;
    }

    /**
     * Whether a record other than $uid still references this secret in the same
     * field — a translation sharing its default record's secret, above all.
     */
    private function isIdentifierReferencedElsewhere(
        string $table,
        string $fieldName,
        string $identifier,
        int $uid,
    ): bool {
        /** @var array<string, array{ctrl?: array{delete?: string}}> $tca */
        $tca = $GLOBALS['TCA'] ?? [];
        $deleteField = $tca[$table]['ctrl']['delete'] ?? null;

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();
        $queryBuilder
            ->count('uid')
            ->from($table)
            ->where(
                $queryBuilder->expr()->eq($fieldName, $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->neq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)),
            );

        if (\is_string($deleteField) && $deleteField !== '') {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq($deleteField, $queryBuilder->createNamedParameter(0, Connection::PARAM_INT)),
            );
        }

        /** @var mixed $count */
        $count = $queryBuilder->executeQuery()->fetchOne();

        return is_numeric($count) && (int) $count > 0;
    }

    /**
     * Read a single column of a record, bypassing every restriction.
     */
    private function readColumn(string $table, int $uid, string $column): ?string
    {
        if ($uid <= 0) {
            return null;
        }

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        /** @var mixed $value */
        $value = $queryBuilder
            ->select($column)
            ->from($table)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return \is_string($value) || is_numeric($value) ? (string) $value : null;
    }

    /**
     * Vault fields of a table that translations share with the default-language
     * record, cached per table for the lifetime of this hook instance.
     *
     * @return list<string>
     */
    private function getTranslationSharedFields(string $table): array
    {
        return $this->sharedVaultFieldCache[$table]
            ??= $this->vaultFieldResolver->getTranslationSharedVaultFields($table);
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
