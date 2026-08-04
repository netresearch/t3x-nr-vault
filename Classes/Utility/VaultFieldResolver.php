<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Utility;

use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Schema\TcaSchemaFactory;

/**
 * Service for resolving vault identifiers to actual secret values.
 *
 * Vault identifiers are UUIDs stored in TCA fields with renderType 'vaultSecret'.
 * Use this in your extension code to retrieve secrets stored via vault TCA fields.
 *
 * Example:
 *   public function __construct(
 *       private readonly VaultFieldResolver $vaultFieldResolver,
 *   ) {}
 *
 *   public function fetchData(): array
 *   {
 *       $settings = $this->getTypoScriptSettings();
 *       return $this->vaultFieldResolver->resolveFields($settings, ['api_key', 'api_secret']);
 *   }
 */
final readonly class VaultFieldResolver
{
    public function __construct(
        private VaultServiceInterface $vaultService,
        private TcaSchemaFactory $tcaSchemaFactory,
        private LoggerInterface $logger,
    ) {}

    /**
     * Resolve vault identifiers in an array to their actual secret values.
     *
     * @param array<string, mixed> $data Record data potentially containing vault identifiers
     * @param list<string> $fields Field names to check and resolve
     * @param bool $throwOnError If true, throws exception on vault errors; if false, sets field to null
     *
     * @throws VaultException If throwOnError is true and vault retrieval fails
     *
     * @return array<string, mixed> Data with vault identifiers replaced by actual values
     */
    public function resolveFields(array $data, array $fields, bool $throwOnError = false): array
    {
        foreach ($fields as $field) {
            if (!isset($data[$field])) {
                continue;
            }

            $value = $data[$field];

            if (!$this->isVaultIdentifier($value)) {
                continue;
            }

            // isVaultIdentifier guarantees value is a string - cast safely
            $identifier = \is_string($value) ? $value : '';

            try {
                $data[$field] = $this->vaultService->retrieve($identifier);
            } catch (VaultException $e) {
                if ($throwOnError) {
                    throw $e;
                }

                $this->logger->error('Failed to resolve vault field', [
                    'field' => $field,
                    'identifier' => $identifier,
                    'error' => $e->getMessage(),
                ]);
                $data[$field] = null;
            }
        }

        return $data;
    }

    /**
     * Resolve a single vault identifier to its secret value.
     *
     * @param string $identifier The vault identifier (UUID)
     *
     * @return string|null The secret value, or null if not found or invalid identifier
     */
    public function resolve(string $identifier): ?string
    {
        if (!$this->isVaultIdentifier($identifier)) {
            return null;
        }

        try {
            return $this->vaultService->retrieve($identifier);
        } catch (VaultException) {
            return null;
        }
    }

    /**
     * Resolve all vault fields in a record based on TCA configuration.
     *
     * Automatically detects which fields use renderType 'vaultSecret'.
     *
     * @param string $table The TCA table name
     * @param array<string, mixed> $record The record data
     *
     * @return array<string, mixed> Record with vault fields resolved
     */
    public function resolveRecord(string $table, array $record): array
    {
        $vaultFields = $this->getVaultFieldsForTable($table);

        if ($vaultFields === []) {
            return $record;
        }

        return $this->resolveFields($record, $vaultFields);
    }

    /**
     * Check if a value looks like a vault identifier (UUID v7).
     *
     * @param mixed $value The value to check
     *
     * @return bool True if the value appears to be a vault identifier
     */
    public function isVaultIdentifier(mixed $value): bool
    {
        if (!\is_string($value) || $value === '') {
            return false;
        }

        return IdentifierValidator::looksLikeVaultIdentifier($value);
    }

    /**
     * Get list of vault field names for a table from TCA.
     *
     * @param string $table The table name
     *
     * @return list<string> Field names that use vaultSecret renderType
     */
    public function getVaultFieldsForTable(string $table): array
    {
        if (!$this->tcaSchemaFactory->has($table)) {
            return [];
        }

        $schema = $this->tcaSchemaFactory->get($table);
        $vaultFields = [];

        foreach ($schema->getFields() as $field) {
            $config = $field->getConfiguration();
            if (($config['renderType'] ?? '') === 'vaultSecret') {
                $vaultFields[] = $field->getName();
            }
        }

        return $vaultFields;
    }

    /**
     * Check if a table has any vault fields configured.
     *
     * @param string $table The table name
     *
     * @return bool True if the table has vault fields
     */
    public function hasVaultFields(string $table): bool
    {
        return $this->getVaultFieldsForTable($table) !== [];
    }
}
