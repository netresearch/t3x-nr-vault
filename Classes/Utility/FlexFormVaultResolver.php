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
 * Service for resolving vault secrets in FlexForm data.
 *
 * Use this to retrieve actual secret values from FlexForm settings
 * that were stored using the vaultSecret renderType.
 *
 * FlexForm vault fields store UUIDs just like regular TCA vault fields.
 *
 * Example:
 *   public function __construct(
 *       private readonly FlexFormVaultResolver $flexFormVaultResolver,
 *   ) {}
 *
 *   public function getSettings(array $record): array
 *   {
 *       $flexFormService = GeneralUtility::makeInstance(FlexFormService::class);
 *       $settings = $flexFormService->convertFlexFormContentToArray($record['pi_flexform']);
 *       return $this->flexFormVaultResolver->resolveSettings($settings, ['apiKey', 'apiSecret']);
 *   }
 */
final readonly class FlexFormVaultResolver
{
    /** UUID v7 pattern for vault identifiers. */
    private const UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

    public function __construct(
        private VaultServiceInterface $vaultService,
        private LoggerInterface $logger,
        private TcaSchemaFactory $tcaSchemaFactory,
    ) {}

    /**
     * Resolve vault identifiers in FlexForm settings.
     *
     * @param array<string, mixed> $settings FlexForm settings array
     * @param list<string> $fields Field names to resolve
     * @param bool $throwOnError Throw exception on vault errors
     *
     * @return array<string, mixed> Settings with vault identifiers resolved
     */
    public function resolveSettings(array $settings, array $fields, bool $throwOnError = false): array
    {
        foreach ($fields as $field) {
            if (!isset($settings[$field])) {
                continue;
            }

            $value = $settings[$field];

            if (!$this->isVaultIdentifier($value)) {
                continue;
            }

            // isVaultIdentifier guarantees value is a string - cast safely
            $identifier = \is_string($value) ? $value : '';

            try {
                $settings[$field] = $this->vaultService->retrieve($identifier);
            } catch (VaultException $e) {
                if ($throwOnError) {
                    throw $e;
                }

                $this->logger->error('Failed to resolve FlexForm vault field', [
                    'field' => $field,
                    'identifier' => $identifier,
                    'error' => $e->getMessage(),
                ]);
                $settings[$field] = null;
            }
        }

        return $settings;
    }

    /**
     * Resolve all vault identifiers in FlexForm settings recursively.
     *
     * This scans the entire settings array for vault identifiers
     * without needing to specify field names.
     *
     * @param array<string, mixed> $settings FlexForm settings array
     *
     * @return array<string, mixed> Settings with all vault identifiers resolved
     */
    public function resolveAll(array $settings): array
    {
        return $this->resolveRecursive($settings);
    }

    /**
     * Check if a value is a vault identifier (UUID v7).
     *
     * Both FlexForm and regular TCA vault fields use the same UUID format.
     *
     * @param mixed $value Value to check
     *
     * @return bool True if it's a vault identifier
     */
    public function isVaultIdentifier(mixed $value): bool
    {
        if (!\is_string($value) || $value === '') {
            return false;
        }

        return (bool) preg_match(self::UUID_PATTERN, $value);
    }

    /**
     * Get the FlexForm (type 'flex') field names for a table from its TCA schema.
     *
     * Used by the DataHandler FlexForm hook to discover which fields may carry
     * vault secrets, so the discovery logic lives in one place.
     *
     * @param string $table The table name
     *
     * @return list<string> Field names that are FlexForm fields
     */
    public function getFlexFieldsForTable(string $table): array
    {
        if (!$this->tcaSchemaFactory->has($table)) {
            return [];
        }

        $schema = $this->tcaSchemaFactory->get($table);
        $flexFields = [];

        foreach ($schema->getFields() as $field) {
            $configType = $field->getConfiguration()['type'] ?? '';
            if (\is_string($configType) && $configType === 'flex') {
                $flexFields[] = $field->getName();
            }
        }

        return $flexFields;
    }

    /**
     * Resolve vault identifiers recursively in nested arrays.
     *
     * @param array<string, mixed> $data
     *
     * @return array<string, mixed>
     */
    private function resolveRecursive(array $data): array
    {
        foreach ($data as $key => $value) {
            if (\is_array($value)) {
                /** @var array<string, mixed> $value */
                $data[$key] = $this->resolveRecursive($value);
            } elseif ($this->isVaultIdentifier($value)) {
                // isVaultIdentifier guarantees value is a string - cast safely
                $identifier = \is_string($value) ? $value : '';

                try {
                    $data[$key] = $this->vaultService->retrieve($identifier);
                } catch (VaultException $e) {
                    $this->logger->error('Failed to resolve vault identifier', [
                        'key' => $key,
                        'identifier' => $identifier,
                        'error' => $e->getMessage(),
                    ]);
                    $data[$key] = null;
                }
            }
        }

        return $data;
    }
}
