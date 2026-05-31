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
use Netresearch\NrVault\Utility\IdentifierValidator;
use Netresearch\NrVault\Utility\VaultFieldResolver;
use Throwable;
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

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly VaultServiceInterface $vaultService,
        private readonly VaultFieldResolver $vaultFieldResolver,
        private readonly PendingSecretExtractor $pendingSecretExtractor,
        private readonly PendingSecretPersister $pendingSecretPersister,
    ) {}

    /**
     * Called before database operations.
     * Extracts vault field values and generates UUIDs for new secrets.
     *
     * @param array<string, mixed> $fieldArray
     */
    public function processDatamap_preProcessFieldArray(
        array &$fieldArray,
        string $table,
        string|int $id,
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
    public function processDatamap_afterDatabaseOperations(
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
                static fn (Throwable $e): string => \sprintf(
                    'Vault storage failed for field "%s" on %s:%d: %s. The field value has been rolled back.',
                    $fieldName,
                    $table,
                    $uid,
                    $e->getMessage(),
                ),
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
                    'Vault error for field "' . $fieldName . '": ' . $error->getMessage(),
                );
            }
        }

        // Clean up pending secrets
        unset($this->pendingSecrets[$table][$id]);
    }

    /**
     * Called before record deletion.
     * Removes associated vault secrets.
     */
    public function processCmdmap_preProcess(
        string $command,
        string $table,
        string|int $id,
        mixed $value,
        DataHandler $dataHandler,
        bool $pasteUpdate,
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

        foreach ($vaultFields as $fieldName) {
            $vaultIdentifier = $record[$fieldName] ?? '';
            if (!\is_string($vaultIdentifier)) {
                continue;
            }
            if ($vaultIdentifier === '') {
                continue;
            }

            try {
                $this->vaultService->delete($vaultIdentifier, 'Record deleted');
            } catch (Throwable $e) {
                /** @phpstan-ignore method.internal */
                $dataHandler->log(
                    $table,
                    (int) $id,
                    3,
                    null,
                    1,
                    'Vault error during delete for field "' . $fieldName . '": ' . $e->getMessage(),
                );
            }
        }
    }

    /**
     * Called after record copy.
     * Copies vault secrets to the new record with new UUIDs.
     */
    public function processCmdmap_postProcess(
        string $command,
        string $table,
        string|int $id,
        mixed $value,
        DataHandler $dataHandler,
        bool $pasteUpdate,
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
                    continue;
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
                /** @phpstan-ignore method.internal */
                $dataHandler->log(
                    $table,
                    $newId,
                    1,
                    null,
                    1,
                    'Vault error during copy for field "' . $fieldName . '": ' . $e->getMessage(),
                );
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
