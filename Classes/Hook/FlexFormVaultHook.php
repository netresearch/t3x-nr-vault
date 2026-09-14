<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

use Exception;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Hook\Dto\FlexFormPendingSecret;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Throwable;
use TYPO3\CMS\Core\Configuration\FlexForm\FlexFormTools;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Information\Typo3Version;
use TYPO3\CMS\Core\Messaging\FlashMessage;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Schema\TcaSchema;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * DataHandler hook for vault secrets in FlexForm fields.
 *
 * Processes FlexForm XML to detect and handle vault secret fields.
 * Works alongside the regular DataHandlerHook for standard TCA fields.
 *
 * Vault identifiers are UUIDs stored in the FlexForm XML.
 */
final class FlexFormVaultHook
{
    /**
     * The DataHandler commands that duplicate a record.
     *
     * Mirrors {@see DataHandlerHook::DUPLICATION_COMMANDS}: a FlexForm field is
     * duplicated by exactly the same commands, and its vault identifiers travel
     * inside the copied XML.
     */
    private const DUPLICATION_COMMANDS = ['copy', 'localize', 'copyToLanguage', 'inlineLocalizeSynchronize'];

    /** @var array<string, array<string|int, list<FlexFormPendingSecret>>> */
    private array $pendingFlexSecrets = [];

    /**
     * The DataHandler instances currently running a duplicating command, each
     * with the number of such commands in flight.
     *
     * @see DataHandlerHook::$duplicationCommands for why this is counted and
     *      why the command context — never the shape of the submitted value —
     *      is what the datamap pass keys on
     *
     * @var array<int, int> spl_object_id() of the DataHandler => commands in flight
     */
    private array $duplicationCommands = [];

    /**
     * Whether the datamap pass currently being processed writes a duplicated
     * record. Set for the duration of one `processDatamap_preProcessFieldArray()`
     * call instead of threaded through the FlexForm traversal.
     */
    private bool $inDuplicationPass = false;

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly TcaSchemaFactory $tcaSchemaFactory,
        private readonly VaultServiceInterface $vaultService,
        private readonly FlexFormTools $flexFormTools,
        private readonly FlashMessageService $flashMessageService,
        private readonly VaultFailureReporter $failureReporter,
    ) {}

    /**
     * Called before database operations.
     * Scans FlexForm fields for vault secrets.
     *
     * @param array<string, mixed> $fieldArray
     */
    public function processDatamap_preProcessFieldArray(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        array &$fieldArray,
        string $table,
        string|int $id,
        ?DataHandler $dataHandler = null,
    ): void {
        if (!$this->tcaSchemaFactory->has($table)) {
            return;
        }

        $schema = $this->tcaSchemaFactory->get($table);

        $this->inDuplicationPass = $this->duplicationCommands !== []
            && \is_string($id)
            && str_starts_with($id, 'NEW')
            && $dataHandler instanceof DataHandler
            && $dataHandler->dontProcessTransformations;

        try {
            $this->processFlexFields($fieldArray, $table, $id, $schema);
        } finally {
            $this->inDuplicationPass = false;
        }
    }

    /**
     * Called after database operations.
     * Stores vault secrets with the correct record UID for FlexForm fields.
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

        // Process pending FlexForm secrets
        $pendingForRecord = $this->pendingFlexSecrets[$table][$id] ?? [];

        foreach ($pendingForRecord as $secretData) {
            $this->storeFlexFormSecret($secretData, $table, $uid, $dataHandler);
        }

        // Clean up
        unset($this->pendingFlexSecrets[$table][$id]);
    }

    /**
     * Called before record deletion.
     * Parses FlexForm XML to find vault identifiers and deletes the corresponding secrets.
     * Only acts on hard delete (not soft-delete/recycle).
     *
     * @param array<string, mixed> $recordToDelete
     */
    public function processCmdmap_deleteAction(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        string $table,
        int $id,
        array $recordToDelete,
        bool &$recordWasDeleted,
        DataHandler $dataHandler,
    ): void {
        if (!$this->isHardDelete($table)) {
            return;
        }

        $flexFieldNames = $this->getFlexFieldNames($table);
        if ($flexFieldNames === []) {
            return;
        }

        foreach ($flexFieldNames as $flexFieldName) {
            $xmlValue = $recordToDelete[$flexFieldName] ?? '';
            if (!\is_string($xmlValue)) {
                continue;
            }

            if ($xmlValue === '') {
                continue;
            }

            $identifiers = $this->extractVaultIdentifiersFromXml($xmlValue);

            foreach ($identifiers as $identifier) {
                try {
                    $this->vaultService->delete($identifier, 'Record deleted');
                } catch (Throwable $e) {
                    $userMessage = $this->failureReporter->report($e, [
                        'table' => $table,
                        'flexField' => $flexFieldName,
                        'uid' => $id,
                        'identifier' => $identifier,
                        'operation' => 'flexform_delete',
                    ]);

                    /** @phpstan-ignore method.internal */
                    $dataHandler->log(
                        $table,
                        $id,
                        3,
                        null,
                        1,
                        'Vault error during delete for FlexForm field: ' . $userMessage,
                    );
                }
            }
        }
    }

    /**
     * Called before a command is executed.
     *
     * Remembers that a duplicating command is running, which is the only signal
     * {@see processVaultSecretValue()} accepts for "this identifier was copied
     * here by DataHandler".
     *
     * `$pasteUpdate` is typed `mixed` because TYPO3 core reassigns its `false`
     * default to `$value['update']` (an array) on the localize / copy-to-
     * language path.
     */
    public function processCmdmap_preProcess(// NOSONAR: TYPO3 DataHandler hook method name (fixed API contract)
        string $command,
        string $table,
        string|int $id,
        mixed $value,
        DataHandler $dataHandler,
        mixed $pasteUpdate,
    ): void {
        if (\in_array($command, self::DUPLICATION_COMMANDS, true)) {
            $handlerId = spl_object_id($dataHandler);
            $this->duplicationCommands[$handlerId] = ($this->duplicationCommands[$handlerId] ?? 0) + 1;
        }
    }

    /**
     * Called after a record was duplicated.
     * Gives every duplicated record its own clones of the source record's
     * FlexForm secrets.
     *
     * Like the TCA path, the command names one record while `copyMappingArray`
     * lists all of them — including inline children, which core duplicates
     * through `copyRecord_raw()` without running a single datamap hook, so
     * their XML still carries the source record's identifiers verbatim.
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

                $flexFieldNames = $this->getFlexFieldNames($duplicatedTable);
                if ($flexFieldNames === []) {
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

                    $this->cloneFlexSecretsIntoDuplicate(
                        $connection,
                        $duplicatedTable,
                        $sourceUid,
                        $newUid,
                        $flexFieldNames,
                        $dataHandler,
                    );
                }
            }
        } finally {
            $handlerId = spl_object_id($dataHandler);
            $remaining = ($this->duplicationCommands[$handlerId] ?? 0) - 1;

            if ($remaining > 0) {
                $this->duplicationCommands[$handlerId] = $remaining;
            } else {
                unset($this->duplicationCommands[$handlerId]);
            }
        }
    }

    /**
     * Process every FlexForm field of the submitted field array.
     *
     * @param array<string, mixed> $fieldArray
     */
    private function processFlexFields(
        array &$fieldArray,
        string $table,
        string|int $id,
        TcaSchema $schema,
    ): void {
        /** @var array<string, mixed>|null $recordRow */
        $recordRow = null;

        foreach ($schema->getFields() as $field) {
            $fieldConfig = $field->getConfiguration();

            // Check for FlexForm type fields
            $configType = $fieldConfig['type'] ?? '';
            if (!\is_string($configType)) {
                continue;
            }

            if ($configType !== 'flex') {
                continue;
            }

            $fieldName = $field->getName();

            // Check if this FlexForm field is being saved
            if (!isset($fieldArray[$fieldName])) {
                continue;
            }

            if (!\is_array($fieldArray[$fieldName])) {
                continue;
            }

            /** @var array<string, mixed> $flexData */
            $flexData = $fieldArray[$fieldName];
            // Resolved lazily: the record row is only needed once a FlexForm
            // field is actually part of the current save.
            $recordRow ??= $this->resolveRecordRow($table, $id, $fieldArray);
            // Process the FlexForm data array
            $this->processFlexFormData(
                $flexData,
                $table,
                $id,
                $fieldName,
                ['config' => $fieldConfig],
                $schema,
                $recordRow,
            );
            $fieldArray[$fieldName] = $flexData;
        }
    }

    /**
     * Clone the FlexForm secrets of a source record into the record duplicated
     * from it.
     *
     * The source XML is the map: every vault identifier it holds marks a
     * position the duplicate must fill with a clone. The duplicate's own value
     * at that position is either the source identifier (core duplicated the XML
     * verbatim) or empty (the datamap pass cleared it) — any other value was
     * produced by an ordinary write and is left alone.
     *
     * @param list<string> $flexFieldNames
     */
    private function cloneFlexSecretsIntoDuplicate(
        Connection $connection,
        string $table,
        int $sourceUid,
        int $newUid,
        array $flexFieldNames,
        DataHandler $dataHandler,
    ): void {
        // Both rows in ONE query: issuing a second select() on the connection
        // that DataHandler just wrote through did not see the freshly inserted
        // copy, which silently skipped the clone.
        $rows = $this->readFlexRows($table, $flexFieldNames, [$sourceUid, $newUid]);

        $sourceRecord = $rows[$sourceUid] ?? null;
        $copiedRecord = $rows[$newUid] ?? null;

        if ($sourceRecord === null || $copiedRecord === null) {
            return;
        }

        foreach ($flexFieldNames as $flexFieldName) {
            $sourceXml = $sourceRecord[$flexFieldName] ?? '';
            $copyXml = $copiedRecord[$flexFieldName] ?? '';
            if (!\is_string($sourceXml) || !\is_string($copyXml)) {
                continue;
            }

            if ($sourceXml === '' || $copyXml === '') {
                continue;
            }

            // xml2arrayProcess() rather than xml2array(): the latter memoizes
            // through the runtime cache, which a hook must not depend on.
            $sourceArray = GeneralUtility::xml2arrayProcess($sourceXml);
            $copyArray = GeneralUtility::xml2arrayProcess($copyXml);
            if (!\is_array($sourceArray) || !\is_array($copyArray)) {
                continue;
            }

            $positions = $this->collectVaultIdentifierPositions($sourceArray);
            if ($positions === []) {
                continue;
            }

            $this->cloneFlexField($connection, $table, $flexFieldName, $newUid, $positions, $copyArray, $copyXml, $dataHandler);
        }
    }

    /**
     * Read the FlexForm columns of the given records, indexed by uid.
     *
     * @param list<string> $flexFieldNames
     * @param list<int> $uids
     *
     * @return array<int, array<string, mixed>>
     */
    private function readFlexRows(string $table, array $flexFieldNames, array $uids): array
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $rows = $queryBuilder
            ->select('uid', ...$flexFieldNames)
            ->from($table)
            ->where(
                $queryBuilder->expr()->in(
                    'uid',
                    $queryBuilder->createNamedParameter($uids, Connection::PARAM_INT_ARRAY),
                ),
            )
            ->executeQuery()
            ->fetchAllAssociative();

        $indexed = [];
        foreach ($rows as $row) {
            /** @var mixed $uid */
            $uid = $row['uid'] ?? null;
            if (!is_numeric($uid)) {
                continue;
            }

            $indexed[(int) $uid] = $row;
        }

        return $indexed;
    }

    /**
     * Clone every vault position of one FlexForm field into the duplicate and
     * persist the result.
     *
     * Fails closed: when one clone fails, the clones already written for this
     * field are deleted again and EVERY vault position of the duplicate is
     * cleared — a duplicate that still pointed at the source record's secrets
     * would rotate and delete them as if they were its own.
     *
     * @param list<array{path: list<string>, identifier: string}> $positions
     * @param array<array-key, mixed> $copyArray
     */
    private function cloneFlexField(
        Connection $connection,
        string $table,
        string $flexFieldName,
        int $newUid,
        array $positions,
        array $copyArray,
        string $copyXml,
        DataHandler $dataHandler,
    ): void {
        /** @var list<string> $clonedIdentifiers */
        $clonedIdentifiers = [];

        foreach ($positions as $position) {
            $sourceIdentifier = $position['identifier'];
            $currentValue = $this->valueAtPath($copyArray, $position['path']);
            if ($currentValue !== '' && $currentValue !== $sourceIdentifier) {
                continue;
            }

            $secretValue = null;

            try {
                $secretValue = $this->vaultService->retrieve($sourceIdentifier);
                if ($secretValue === null) {
                    throw SecretNotFoundException::forIdentifier($sourceIdentifier);
                }

                $newIdentifier = IdentifierValidator::generateUuid();
                $this->vaultService->store($newIdentifier, $secretValue, [
                    'table' => $table,
                    'flexField' => $flexFieldName,
                    'uid' => $newUid,
                    'source' => 'flexform_record_copy',
                    'copied_from' => $sourceIdentifier,
                ]);

                $this->setValueAtPath($copyArray, $position['path'], $newIdentifier);
                $clonedIdentifiers[] = $newIdentifier;
            } catch (Throwable $e) {
                $this->abandonFlexClones($clonedIdentifiers, $table, $flexFieldName, $newUid);

                foreach ($positions as $positionToClear) {
                    $this->setValueAtPath($copyArray, $positionToClear['path'], '');
                }

                $this->reportFlexCopyFailure($e, $table, $flexFieldName, $newUid, $sourceIdentifier, $dataHandler);

                break;
            } finally {
                if ($secretValue !== null && $secretValue !== '') {
                    sodium_memzero($secretValue);
                }
            }
        }

        /** @phpstan-ignore method.internal */
        $newXml = $this->flexFormTools->flexArray2Xml($copyArray);
        if ($newXml !== $copyXml) {
            $connection->update($table, [$flexFieldName => $newXml], ['uid' => $newUid]);
        }
    }

    /**
     * Delete the clones written before a duplication failed.
     *
     * @param list<string> $clonedIdentifiers
     */
    private function abandonFlexClones(
        array $clonedIdentifiers,
        string $table,
        string $flexFieldName,
        int $newUid,
    ): void {
        foreach ($clonedIdentifiers as $clonedIdentifier) {
            try {
                $this->vaultService->delete($clonedIdentifier, 'Record copy rolled back');
            } catch (Throwable $compensationError) {
                // The clone is orphaned rather than dangerous — nothing
                // references it any more. Record it for the administrator and
                // keep rolling back.
                $this->failureReporter->report($compensationError, [
                    'table' => $table,
                    'flexField' => $flexFieldName,
                    'uid' => $newUid,
                    'identifier' => $clonedIdentifier,
                    'operation' => 'flexform_copy_rollback',
                ]);
            }
        }
    }

    /**
     * Tell the editor that the duplicate has no FlexForm secrets, and why.
     */
    private function reportFlexCopyFailure(
        Throwable $error,
        string $table,
        string $flexFieldName,
        int $newUid,
        string $sourceIdentifier,
        DataHandler $dataHandler,
    ): void {
        $userMessage = $this->failureReporter->report($error, [
            'table' => $table,
            'flexField' => $flexFieldName,
            'uid' => $newUid,
            'identifier' => $sourceIdentifier,
            'operation' => 'flexform_copy',
        ]);

        /** @phpstan-ignore method.internal */
        $dataHandler->log(
            $table,
            $newUid,
            1,
            null,
            2,
            'Vault error during copy for FlexForm field "' . $flexFieldName . '": ' . $userMessage
            . ' No secret was copied; the vault fields of the new record were cleared and must be filled in again.',
        );
    }

    /**
     * Every position of a parsed FlexForm value that holds a stored vault
     * identifier, as the path of array keys leading to it.
     *
     * @param array<array-key, mixed> $node
     * @param list<string> $path
     *
     * @return list<array{path: list<string>, identifier: string}>
     */
    private function collectVaultIdentifierPositions(array $node, array $path = []): array
    {
        $positions = [];

        /** @var mixed $value */
        foreach ($node as $key => $value) {
            $childPath = [...$path, (string) $key];

            if (\is_array($value)) {
                $positions = [...$positions, ...$this->collectVaultIdentifierPositions($value, $childPath)];

                continue;
            }

            if ((string) $key !== 'vDEF' || !\is_string($value)) {
                continue;
            }

            if (!IdentifierValidator::looksLikeVaultIdentifier($value) || !$this->vaultService->exists($value)) {
                continue;
            }

            $positions[] = ['path' => $childPath, 'identifier' => $value];
        }

        return $positions;
    }

    /**
     * The string value a path points at, or an empty string when the path does
     * not lead to one.
     *
     * @param array<array-key, mixed> $node
     * @param list<string> $path
     */
    private function valueAtPath(array $node, array $path): string
    {
        $current = $node;

        foreach ($path as $key) {
            if (!\is_array($current) || !\array_key_exists($key, $current)) {
                return '';
            }

            $current = $current[$key];
        }

        return \is_string($current) ? $current : '';
    }

    /**
     * Write a string value at a path, leaving the rest of the structure alone.
     *
     * @param array<array-key, mixed> $node
     * @param list<string> $path
     */
    private function setValueAtPath(array &$node, array $path, string $value): void
    {
        $current = &$node;

        foreach ($path as $key) {
            if (!\is_array($current)) {
                return;
            }

            if (!\array_key_exists($key, $current)) {
                return;
            }

            $current = &$current[$key];
        }

        $current = $value;
    }

    /**
     * Process FlexForm data array to find vault fields.
     * Handles both flat FlexForm fields and section container elements.
     *
     * @param array<string, mixed> $data
     * @param array<string, mixed> $flexFieldConfig
     * @param array<string, mixed> $recordRow
     */
    private function processFlexFormData(
        array &$data,
        string $table,
        string|int $id,
        string $flexFieldName,
        array $flexFieldConfig,
        TcaSchema $schema,
        array $recordRow,
    ): void {
        $dataStructure = $this->getFlexFormDataStructure(
            $flexFieldConfig,
            $table,
            $flexFieldName,
            $recordRow,
            $schema,
        );
        if ($dataStructure === null) {
            $this->discardUnprocessedVaultPlaintext($data, $table, $id, $flexFieldName);

            return;
        }

        if (!\is_array($data['data'] ?? null)) {
            return;
        }

        foreach ($data['data'] as $sheetName => &$sheetData) {
            if (!\is_array($sheetData)) {
                continue;
            }

            /** @var array<string, mixed> $sheets */
            $sheets = $dataStructure['sheets'] ?? [];
            /** @var array{ROOT?: array{el?: array<string, mixed>}} $sheetConfig */
            $sheetConfig = \is_array($sheets[$sheetName] ?? null) ? $sheets[$sheetName] : [];

            if (!\is_array($sheetData['lDEF'] ?? null)) {
                continue;
            }

            foreach ($sheetData['lDEF'] as $fieldPath => &$fieldData) {
                if (!\is_array($fieldData)) {
                    continue;
                }

                $fieldPathStr = (string) $fieldPath;
                $elementConfig = $this->getFlexFormElementConfig($sheetConfig, $fieldPathStr);

                $configArray = $elementConfig['config'] ?? [];
                $renderType = \is_array($configArray) ? ($configArray['renderType'] ?? '') : '';
                if (\is_string($renderType) && $renderType === 'vaultSecret') {
                    $this->processVaultSecretValue(
                        $fieldData,
                        $table,
                        $id,
                        $flexFieldName,
                        (string) $sheetName,
                        $fieldPathStr,
                    );

                    continue;
                }

                // Check for section container with repeating elements
                $this->processSectionContainerFields(
                    $fieldData,
                    $sheetConfig,
                    $table,
                    $id,
                    $flexFieldName,
                    (string) $sheetName,
                    $fieldPathStr,
                );
            }
        }

        unset($sheetData, $fieldData);

        $this->discardUnprocessedVaultPlaintext($data, $table, $id, $flexFieldName);
    }

    /**
     * Process a single vault secret value from FlexForm data.
     *
     * @param array<mixed, mixed> $fieldData
     */
    private function processVaultSecretValue(
        array &$fieldData,
        string $table,
        string|int $id,
        string $flexFieldName,
        string $sheetName,
        string $fieldPath,
    ): void {
        $value = $fieldData['vDEF'] ?? '';

        // The nested pass of a record duplication: the value is the SOURCE
        // record's stored identifier, which only looks like a typed secret.
        // Clear it here and let processCmdmap_postProcess() clone the source
        // secret into the same position of the copied XML.
        if ($this->inDuplicationPass && !\is_array($value)) {
            $fieldData['vDEF'] = '';

            return;
        }

        if (\is_array($value)) {
            $rawSecretValue = $value['value'] ?? $value[0] ?? '';
            $rawIdentifier = $value['_vault_identifier'] ?? '';
            $rawChecksum = $value['_vault_checksum'] ?? '';
            $secretValue = \is_string($rawSecretValue) || \is_int($rawSecretValue) ? (string) $rawSecretValue : '';
            $existingIdentifier = \is_string($rawIdentifier) ? $rawIdentifier : '';
            $originalChecksum = \is_string($rawChecksum) ? $rawChecksum : '';
        } else {
            $secretValue = \is_string($value) || \is_int($value) ? (string) $value : '';
            $existingIdentifier = '';
            $originalChecksum = '';
        }

        // A new plaintext value was entered: store it as a new secret or rotate
        // the existing one. See PendingSecretExtractor::extract() for the full
        // empty-value rationale — this mirrors it for FlexForm-embedded fields.
        if ($secretValue !== '') {
            $isNewSecret = $existingIdentifier === '' || $originalChecksum === '';
            $vaultIdentifier = $isNewSecret ? IdentifierValidator::generateUuid() : $existingIdentifier;

            $this->pendingFlexSecrets[$table][$id][] = $isNewSecret
                ? FlexFormPendingSecret::createNew(
                    $flexFieldName,
                    $sheetName,
                    $fieldPath,
                    $secretValue,
                    $vaultIdentifier,
                )
                : FlexFormPendingSecret::createUpdate(
                    $flexFieldName,
                    $sheetName,
                    $fieldPath,
                    $secretValue,
                    $vaultIdentifier,
                    $originalChecksum,
                );

            $fieldData['vDEF'] = $vaultIdentifier;

            return;
        }

        // Empty value with the checksum still present: the field was left
        // untouched (the plaintext is never rendered into the form), so keep the
        // stored secret and collapse the submitted array back to its identifier
        // (issue #223 — a plain re-save must not wipe the key).
        if ($originalChecksum !== '') {
            $fieldData['vDEF'] = $existingIdentifier;

            return;
        }

        // Empty value and no checksum: the clear control blanked the checksum. An
        // identifier still present means the user explicitly cleared the field,
        // so delete the stored secret.
        if ($existingIdentifier !== '') {
            $this->pendingFlexSecrets[$table][$id][] = FlexFormPendingSecret::createUpdate(
                $flexFieldName,
                $sheetName,
                $fieldPath,
                '',
                $existingIdentifier,
                '',
            );

            $fieldData['vDEF'] = '';
        }
    }

    /**
     * Process section container fields to find vault secret fields in repeating elements.
     *
     * @param array<mixed, mixed> $fieldData
     * @param array<mixed, mixed> $sheetConfig
     */
    private function processSectionContainerFields(
        array &$fieldData,
        array $sheetConfig,
        string $table,
        string|int $id,
        string $flexFieldName,
        string $sheetName,
        string $fieldPath,
    ): void {
        if (!isset($fieldData['el']) || !\is_array($fieldData['el'])) {
            return;
        }

        foreach ($fieldData['el'] as &$sectionItem) {
            if (!\is_array($sectionItem)) {
                continue;
            }

            foreach ($sectionItem as &$containerData) {
                if (!\is_array($containerData)) {
                    continue;
                }

                if (!isset($containerData['el'])) {
                    continue;
                }

                if (!\is_array($containerData['el'])) {
                    continue;
                }

                foreach ($containerData['el'] as $innerFieldName => &$innerFieldData) {
                    if (!\is_array($innerFieldData)) {
                        continue;
                    }

                    /** @var array{ROOT?: array{el?: array<string, mixed>}} $typedSheetConfig */
                    $typedSheetConfig = $sheetConfig;
                    $elementConfig = $this->getFlexFormElementConfig($typedSheetConfig, (string) $innerFieldName);
                    $innerConfigArray = $elementConfig['config'] ?? [];
                    $renderType = \is_array($innerConfigArray) ? ($innerConfigArray['renderType'] ?? '') : '';
                    if (!\is_string($renderType)) {
                        continue;
                    }

                    if ($renderType !== 'vaultSecret') {
                        continue;
                    }

                    $this->processVaultSecretValue(
                        $innerFieldData,
                        $table,
                        $id,
                        $flexFieldName,
                        $sheetName,
                        $fieldPath . '/' . $innerFieldName,
                    );
                }
            }
        }

        unset($sectionItem, $containerData, $innerFieldData);
    }

    /**
     * Store a FlexForm vault secret.
     */
    private function storeFlexFormSecret(
        FlexFormPendingSecret $pending,
        string $table,
        int $uid,
        DataHandler $dataHandler,
    ): void {
        try {
            if ($pending->value === '') {
                // The identifier — not the checksum, which the clear control
                // blanks — is the reliable "a secret existed" signal (issue #223).
                if ($pending->identifier !== '') {
                    $this->vaultService->delete($pending->identifier, 'FlexForm field cleared');
                }
            } elseif ($pending->isNew) {
                $this->vaultService->store($pending->identifier, $pending->value, [
                    'table' => $table,
                    'flexField' => $pending->flexField,
                    'sheet' => $pending->sheet,
                    'fieldPath' => $pending->fieldPath,
                    'uid' => $uid,
                    'source' => 'flexform_field',
                ]);
            } else {
                $this->vaultService->rotate($pending->identifier, $pending->value, 'FlexForm field updated');
            }
        } catch (Throwable $e) {
            // One report for both channels: the flash message AND the
            // DataHandler log detail are replayed to the editor, so both must
            // carry the same correlation reference and neither the cause.
            $userMessage = $this->failureReporter->report($e, [
                'table' => $table,
                'flexField' => $pending->flexField,
                'fieldPath' => $pending->fieldPath,
                'uid' => $uid,
                'identifier' => $pending->identifier,
                'operation' => 'flexform_field',
            ]);

            /** @phpstan-ignore method.internal */
            $dataHandler->log(
                $table,
                $uid,
                2,
                null,
                1,
                'Vault error for FlexForm field "' . $pending->fieldPath . '": ' . $userMessage,
            );

            $this->addFlashMessage(
                \sprintf(
                    'Vault storage failed for FlexForm field "%s" on %s:%d: %s',
                    $pending->fieldPath,
                    $table,
                    $uid,
                    $userMessage,
                ),
                'Vault Error',
                ContextualFeedbackSeverity::ERROR,
            );
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

    /**
     * Get the FlexForm data structure.
     *
     * The table and field name identify the TCA column the data structure is
     * defined on, and the record row supplies the record type (CType /
     * list_type) that selects the concrete data structure. Passing empty
     * strings and the submitted FlexForm array instead makes the lookup fail on
     * every supported TYPO3 version, which used to silently disable the vault
     * handling below.
     *
     * @param array<string, mixed> $fieldConfig
     * @param array<string, mixed> $recordRow
     *
     * @return array<string, mixed>|null
     */
    private function getFlexFormDataStructure(
        array $fieldConfig,
        string $table,
        string $fieldName,
        array $recordRow,
        TcaSchema $schema,
    ): ?array {
        $schemaArguments = $this->dataStructureSchemaArguments($schema);

        try {
            $dataStructureIdentifier = $this->flexFormTools->getDataStructureIdentifier(
                $fieldConfig,
                $table,
                $fieldName,
                $recordRow,
                ...$schemaArguments,
            );

            /** @phpstan-ignore return.type */
            return $this->flexFormTools->parseDataStructureByIdentifier(
                $dataStructureIdentifier,
                ...$schemaArguments,
            );
        } catch (Exception) {
            return null;
        }
    }

    /**
     * Build the trailing schema argument for the FlexFormTools API.
     *
     * TYPO3 v14 requires a TcaSchema to resolve a data structure and throws
     * without it; the v13.4 signatures do not accept the argument at all. PHP
     * ignores surplus positional arguments, so it is only appended when the
     * running core knows about it.
     *
     * @return list<TcaSchema>
     */
    private function dataStructureSchemaArguments(TcaSchema $schema): array
    {
        return (new Typo3Version())->getMajorVersion() >= 14 ? [$schema] : [];
    }

    /**
     * Resolve the record row the FlexForm data structure lookup needs.
     *
     * The data structure of a FlexForm field is selected by the record type,
     * which is not necessarily part of the submitted field array on an update,
     * so the persisted row is loaded and the submitted values are layered on
     * top of it.
     *
     * @param array<string, mixed> $fieldArray
     *
     * @return array<string, mixed>
     */
    private function resolveRecordRow(string $table, string|int $id, array $fieldArray): array
    {
        $persistedRow = [];

        if (is_numeric($id) && (int) $id > 0) {
            try {
                $row = $this->connectionPool
                    ->getConnectionForTable($table)
                    ->select(['*'], $table, ['uid' => (int) $id])
                    ->fetchAssociative();

                if (\is_array($row)) {
                    $persistedRow = $row;
                }
            } catch (Throwable) {
                // Without the persisted row the data structure lookup may fail;
                // the fail-closed handling then discards the plaintext.
            }
        }

        return array_merge($persistedRow, $fieldArray);
    }

    /**
     * Discard vault plaintext the data-structure driven pass did not convert
     * into a vault identifier.
     *
     * Without this, DataHandler serialises the submitted value verbatim into the
     * stored FlexForm XML — the secret would end up unencrypted in the record,
     * with no vault entry, no access control and no audit trail.
     *
     * @param array<string, mixed> $data
     */
    private function discardUnprocessedVaultPlaintext(
        array &$data,
        string $table,
        string|int $id,
        string $flexFieldName,
    ): void {
        if (!$this->stripVaultPlaintext($data)) {
            return;
        }

        $this->addFlashMessage(
            \sprintf(
                'A vault secret submitted for FlexForm field "%s" on %s:%s was discarded because the'
                . ' field could not be resolved to a vault secret element. Storing it would have'
                . ' written the value unencrypted into the record.',
                $flexFieldName,
                $table,
                (string) $id,
            ),
            'Vault Error',
            ContextualFeedbackSeverity::ERROR,
        );
    }

    /**
     * Replace every submitted vault value that still carries plaintext with its
     * vault identifier, recursively. Values without plaintext are left as they
     * are.
     *
     * @template TKey of array-key
     *
     * @param array<TKey, mixed> $node
     *
     * @param-out array<TKey, mixed> $node
     *
     * @return bool True if at least one plaintext value was removed
     */
    private function stripVaultPlaintext(array &$node): bool
    {
        $stripped = false;

        foreach ($node as &$value) {
            if (!\is_array($value)) {
                continue;
            }

            if ($this->carriesVaultPlaintext($value)) {
                /** @var mixed $rawIdentifier */
                $rawIdentifier = $value['_vault_identifier'] ?? '';
                $value = \is_string($rawIdentifier) && IdentifierValidator::looksLikeVaultIdentifier($rawIdentifier)
                    ? $rawIdentifier
                    : '';
                $stripped = true;

                continue;
            }

            if ($this->stripVaultPlaintext($value)) {
                $stripped = true;
            }
        }

        unset($value);

        return $stripped;
    }

    /**
     * Check whether a submitted value is a vault secret element submission that
     * still contains the plaintext.
     *
     * @param array<mixed, mixed> $value
     */
    private function carriesVaultPlaintext(array $value): bool
    {
        if (!\array_key_exists('_vault_identifier', $value) && !\array_key_exists('_vault_checksum', $value)) {
            return false;
        }

        /** @var mixed $rawSecretValue */
        $rawSecretValue = $value['value'] ?? $value[0] ?? '';

        return (\is_string($rawSecretValue) || \is_int($rawSecretValue)) && (string) $rawSecretValue !== '';
    }

    /**
     * Get FlexForm element configuration from sheet config.
     * Handles both flat fields and section container elements.
     *
     * @param array<mixed> $sheetConfig
     *
     * @return array<mixed>
     */
    private function getFlexFormElementConfig(array $sheetConfig, string $fieldPath): array
    {
        $root = $sheetConfig['ROOT'] ?? [];
        $elements = \is_array($root) ? ($root['el'] ?? []) : [];
        if (!\is_array($elements)) {
            return [];
        }

        if (isset($elements[$fieldPath]) && \is_array($elements[$fieldPath])) {
            return $elements[$fieldPath];
        }

        // Search in section container elements for repeating fields
        foreach ($elements as $element) {
            if (!\is_array($element)) {
                continue;
            }

            /** @var mixed $elementConfig */
            $elementConfig = $element['config'] ?? [];
            $sectionFlag = $element['section'] ?? (\is_array($elementConfig) ? ($elementConfig['section'] ?? null) : null);
            if ($sectionFlag !== 1 && $sectionFlag !== '1') {
                continue;
            }

            $containerEl = $element['el'] ?? [];
            if (!\is_array($containerEl)) {
                continue;
            }

            foreach ($containerEl as $container) {
                if (!\is_array($container)) {
                    continue;
                }

                $innerEl = $container['el'] ?? [];
                if (!\is_array($innerEl)) {
                    continue;
                }

                if (isset($innerEl[$fieldPath]) && \is_array($innerEl[$fieldPath])) {
                    return $innerEl[$fieldPath];
                }
            }
        }

        return [];
    }

    /**
     * Extract all vault identifiers from FlexForm XML.
     *
     * Uses a broad UUID regex to match any version, then validates each
     * candidate with IdentifierValidator and existence check.
     *
     * @return list<string>
     */
    private function extractVaultIdentifiersFromXml(string $xml): array
    {
        $identifiers = [];

        // Match any UUID format (v1-v7), not just v7
        if (preg_match_all(
            '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i',
            $xml,
            $matches,
        )) {
            foreach ($matches[0] as $match) {
                if (IdentifierValidator::looksLikeVaultIdentifier($match)
                    && $this->vaultService->exists($match)) {
                    $identifiers[] = $match;
                }
            }
        }

        return array_values(array_unique($identifiers));
    }

    /**
     * Get FlexForm field names from a table's TCA schema.
     *
     * @return list<string>
     */
    private function getFlexFieldNames(string $table): array
    {
        if (!$this->tcaSchemaFactory->has($table)) {
            return [];
        }

        $schema = $this->tcaSchemaFactory->get($table);
        $flexFields = [];

        foreach ($schema->getFields() as $field) {
            $fieldConfig = $field->getConfiguration();
            $configType = $fieldConfig['type'] ?? '';
            if (\is_string($configType) && $configType === 'flex') {
                $flexFields[] = $field->getName();
            }
        }

        return $flexFields;
    }

    /**
     * Check if the current delete operation is a hard delete (not soft-delete).
     */
    private function isHardDelete(string $table): bool
    {
        /** @var array<string, array{ctrl?: array{delete?: string}}> $tca */
        $tca = $GLOBALS['TCA'] ?? [];
        $deleteField = $tca[$table]['ctrl']['delete'] ?? null;

        return !\is_string($deleteField) || $deleteField === '';
    }
}
