<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\TCA;

/**
 * Helper for creating vault secret TCA field configurations.
 *
 * Provides a convenient API for defining vault-backed fields in TCA.
 *
 * Example usage in Configuration/TCA/tx_myext_settings.php:
 *
 *   use Netresearch\NrVault\TCA\VaultFieldHelper;
 *
 *   return [
 *       'columns' => [
 *           'api_key' => VaultFieldHelper::getFieldConfig([
 *               'label' => 'API Key',
 *           ]),
 *           'api_secret' => VaultFieldHelper::getFieldConfig([
 *               'label' => 'API Secret',
 *               'description' => 'The secret key for API authentication',
 *               'required' => true,
 *           ]),
 *       ],
 *   ];
 */
final class VaultFieldHelper
{
    /**
     * Get TCA field configuration for a vault secret field.
     *
     * @param array{
     *     label?: string,
     *     description?: string,
     *     size?: int,
     *     required?: bool,
     *     placeholder?: string,
     *     displayCond?: string,
     *     l10n_mode?: string,
     *     exclude?: bool,
     * } $options Field options
     *
     * @return array<string, mixed> TCA field configuration
     */
    public static function getFieldConfig(array $options = []): array
    {
        $config = [
            'type' => 'input',
            'renderType' => 'vaultSecret',
            'size' => $options['size'] ?? 30,
        ];

        // Add required validation if specified
        if ($options['required'] ?? false) {
            $config['required'] = true;
        }

        // Add placeholder if specified
        if (isset($options['placeholder'])) {
            $config['placeholder'] = $options['placeholder'];
        }

        $field = [
            'config' => $config,
        ];

        // Add label
        if (isset($options['label'])) {
            $field['label'] = $options['label'];
        }

        // Add description
        if (isset($options['description'])) {
            $field['description'] = $options['description'];
        }

        // Add display condition
        if (isset($options['displayCond'])) {
            $field['displayCond'] = $options['displayCond'];
        }

        // Add localization mode
        if (isset($options['l10n_mode'])) {
            $field['l10n_mode'] = $options['l10n_mode'];
        }

        // Add exclude flag
        if (isset($options['exclude'])) {
            $field['exclude'] = $options['exclude'];
        }

        return $field;
    }

    /**
     * Get a complete TCA column definition with common defaults.
     *
     * This is a convenience method that includes sensible defaults
     * for vault fields including:
     * - exclude: true (admin-only by default)
     * - l10n_mode: exclude (secrets typically aren't translated)
     *
     * @param string $label The field label
     * @param array<string, mixed> $options Additional options
     *
     * @return array<string, mixed> Complete TCA column definition
     */
    public static function getSecureFieldConfig(string $label, array $options = []): array
    {
        /** @var array{label?: string, description?: string, size?: int, required?: bool, placeholder?: string, displayCond?: string, l10n_mode?: string, exclude?: bool} $mergedOptions */
        $mergedOptions = array_merge([
            'label' => $label,
            'exclude' => true,
            'l10n_mode' => 'exclude',
        ], $options);

        return self::getFieldConfig($mergedOptions);
    }

    /**
     * Get SQL column definition for a vault field.
     *
     * Use this in ext_tables.sql generation.
     *
     * @param string $fieldName The field name
     *
     * @return string SQL column definition
     */
    public static function getSqlDefinition(string $fieldName): string
    {
        // Vault identifiers are stored as: table__field__uid
        // Maximum length: ~200 characters should be sufficient
        return $fieldName . " varchar(255) DEFAULT '' NOT NULL";
    }

    /**
     * Add vault field columns to an existing TCA array.
     *
     * @param array<string, mixed> $tca Existing TCA configuration
     * @param array<string, array{label?: string, description?: string, size?: int, required?: bool, placeholder?: string, displayCond?: string, l10n_mode?: string, exclude?: bool}> $vaultFields Map of field names to options
     *
     * @return array<string, mixed> Modified TCA with vault fields added
     */
    public static function addVaultFields(array $tca, array $vaultFields): array
    {
        /** @var array<string, mixed> $columns */
        $columns = \is_array($tca['columns'] ?? null) ? $tca['columns'] : [];
        foreach ($vaultFields as $fieldName => $options) {
            $columns[$fieldName] = self::getFieldConfig($options);
        }

        $tca['columns'] = $columns;

        return $tca;
    }

    /**
     * Check if a TCA field is configured as a vault field.
     *
     * @param array<string, mixed> $fieldConfig The TCA field configuration
     *
     * @return bool True if it's a vault field
     */
    public static function isVaultField(array $fieldConfig): bool
    {
        /** @var array<string, mixed>|mixed $config */
        $config = $fieldConfig['config'] ?? [];
        if (!\is_array($config)) {
            return false;
        }

        $renderType = $config['renderType'] ?? '';

        return $renderType === 'vaultSecret';
    }
}
