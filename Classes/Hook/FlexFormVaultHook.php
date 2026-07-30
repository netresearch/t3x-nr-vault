<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

use Exception;
use Netresearch\NrVault\Hook\Dto\FlexFormPendingSecret;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Throwable;
use TYPO3\CMS\Core\Configuration\FlexForm\FlexFormTools;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Information\Typo3Version;
use TYPO3\CMS\Core\Messaging\FlashMessage;
use TYPO3\CMS\Core\Messaging\FlashMessageService;
use TYPO3\CMS\Core\Schema\TcaSchema;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;
use TYPO3\CMS\Core\Type\ContextualFeedbackSeverity;

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
    /** @var array<string, array<string|int, list<FlexFormPendingSecret>>> */
    private array $pendingFlexSecrets = [];

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly TcaSchemaFactory $tcaSchemaFactory,
        private readonly VaultServiceInterface $vaultService,
        private readonly FlexFormTools $flexFormTools,
        private readonly FlashMessageService $flashMessageService,
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
    ): void {
        if (!$this->tcaSchemaFactory->has($table)) {
            return;
        }

        $schema = $this->tcaSchemaFactory->get($table);

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
                    /** @phpstan-ignore method.internal */
                    $dataHandler->log(
                        $table,
                        $id,
                        3,
                        null,
                        1,
                        'Vault error during delete for FlexForm field: ' . $e->getMessage(),
                    );
                }
            }
        }
    }

    /**
     * Called after record copy.
     * Copies FlexForm vault secrets to the new record with fresh UUIDs.
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

        $flexFieldNames = $this->getFlexFieldNames($table);
        if ($flexFieldNames === []) {
            return;
        }

        $connection = $this->connectionPool->getConnectionForTable($table);
        $copiedRecord = $connection->select(
            $flexFieldNames,
            $table,
            ['uid' => $newId],
        )->fetchAssociative();

        if ($copiedRecord === false) {
            return;
        }

        foreach ($flexFieldNames as $flexFieldName) {
            $xmlValue = $copiedRecord[$flexFieldName] ?? '';
            if (!\is_string($xmlValue)) {
                continue;
            }
            if ($xmlValue === '') {
                continue;
            }

            $xml = $xmlValue;
            $identifiers = $this->extractVaultIdentifiersFromXml($xml);

            foreach ($identifiers as $oldIdentifier) {
                try {
                    $secretValue = $this->vaultService->retrieve($oldIdentifier);
                    if ($secretValue === null) {
                        continue;
                    }

                    $newIdentifier = IdentifierValidator::generateUuid();

                    $this->vaultService->store($newIdentifier, $secretValue, [
                        'table' => $table,
                        'flexField' => $flexFieldName,
                        'uid' => $newId,
                        'source' => 'flexform_record_copy',
                        'copied_from' => $oldIdentifier,
                    ]);

                    $xml = str_replace($oldIdentifier, $newIdentifier, $xml);
                } catch (Throwable $e) {
                    /** @phpstan-ignore method.internal */
                    $dataHandler->log(
                        $table,
                        $newId,
                        1,
                        null,
                        1,
                        'Vault error during copy for FlexForm field "' . $flexFieldName . '": ' . $e->getMessage(),
                    );
                }
            }

            if ($xml !== $xmlValue) {
                $connection->update($table, [$flexFieldName => $xml], ['uid' => $newId]);
            }
        }
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
            /** @phpstan-ignore method.internal */
            $dataHandler->log(
                $table,
                $uid,
                2,
                null,
                1,
                'Vault error for FlexForm field "' . $pending->fieldPath . '": ' . $e->getMessage(),
            );

            $this->addFlashMessage(
                \sprintf(
                    'Vault storage failed for FlexForm field "%s" on %s:%d: %s',
                    $pending->fieldPath,
                    $table,
                    $uid,
                    $e->getMessage(),
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
