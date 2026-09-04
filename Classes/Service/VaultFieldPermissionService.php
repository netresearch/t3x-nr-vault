<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use TYPO3\CMS\Backend\Utility\BackendUtility;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\SingletonInterface;
use Netresearch\NrVault\Security\CurrentBackendUserProviderInterface;

/**
 * Service for checking TSconfig-based permissions on vault fields.
 *
 * TSconfig structure:
 *
 * vault.permissions {
 *     # Global defaults
 *     default {
 *         reveal = 1
 *         copy = 1
 *         edit = 1
 *     }
 *
 *     # Table-specific overrides
 *     tx_myext_settings {
 *         # All fields in this table
 *         default {
 *             reveal = 0
 *         }
 *
 *         # Specific field
 *         api_key {
 *             reveal = 1
 *             copy = 0
 *             edit = 1
 *             readOnly = 0
 *         }
 *     }
 * }
 */
final class VaultFieldPermissionService implements SingletonInterface
{
    /** @var array<string, bool> */
    private array $permissionCache = [];

    public function __construct(
        private readonly CurrentBackendUserProviderInterface $currentBackendUserProvider,
    ) {}

    /**
     * Check if a specific action is allowed for a vault field.
     */
    public function isAllowed(
        string $table,
        string $field,
        VaultFieldPermission $permission,
        ?BackendUserAuthentication $backendUser = null,
    ): bool {
        $backendUser ??= $this->currentBackendUserProvider->get();

        if (!$backendUser instanceof BackendUserAuthentication) {
            return false;
        }

        // Admins always have full access
        if ($backendUser->isAdmin()) {
            // For readOnly permission, admins should NOT be read-only (return false)
            // For all other permissions, admins have full access (return true)
            return $permission !== VaultFieldPermission::ReadOnly;
        }

        /** @phpstan-ignore property.internal */
        $userRecord = $backendUser->user;
        /** @var array<string, mixed> $userRecordTyped */
        $userRecordTyped = \is_array($userRecord) ? $userRecord : [];
        $uid = \is_int($userRecordTyped['uid'] ?? null) ? $userRecordTyped['uid'] : 0;
        $cacheKey = \sprintf('%s:%s:%s:%d', $table, $field, $permission->value, $uid);

        if (isset($this->permissionCache[$cacheKey])) {
            return $this->permissionCache[$cacheKey];
        }

        $allowed = $this->checkPermission($table, $field, $permission);
        $this->permissionCache[$cacheKey] = $allowed;

        return $allowed;
    }

    /**
     * Get all permissions for a vault field.
     *
     * @return array<string, bool>
     */
    public function getPermissions(
        string $table,
        string $field,
        ?BackendUserAuthentication $backendUser = null,
    ): array {
        $permissions = [];

        foreach (VaultFieldPermission::cases() as $permission) {
            $permissions[$permission->value] = $this->isAllowed($table, $field, $permission, $backendUser);
        }

        return $permissions;
    }

    /**
     * Check if field should be rendered as read-only.
     */
    public function isReadOnly(
        string $table,
        string $field,
        ?BackendUserAuthentication $backendUser = null,
    ): bool {
        return $this->isAllowed($table, $field, VaultFieldPermission::ReadOnly, $backendUser);
    }

    /**
     * Clear the permission cache.
     */
    public function clearCache(): void
    {
        $this->permissionCache = [];
    }

    private function checkPermission(
        string $table,
        string $field,
        VaultFieldPermission $permission,
    ): bool {
        $tsConfig = $this->getVaultTsConfig();

        // Check field-specific setting: vault.permissions.{table}.{field}.{permission}
        $fieldValue = $this->getNestedValue($tsConfig, [$table, $field, $permission->value]);
        if ($fieldValue !== null) {
            return $this->toBoolean($fieldValue);
        }

        // Check table default: vault.permissions.{table}.default.{permission}
        $tableDefault = $this->getNestedValue($tsConfig, [$table, 'default', $permission->value]);
        if ($tableDefault !== null) {
            return $this->toBoolean($tableDefault);
        }

        // Check global default: vault.permissions.default.{permission}
        $globalDefault = $this->getNestedValue($tsConfig, ['default', $permission->value]);
        if ($globalDefault !== null) {
            return $this->toBoolean($globalDefault);
        }

        // No explicit setting - use built-in defaults
        return $this->getBuiltInDefault($permission);
    }

    /**
     * @return array<string, mixed>
     */
    private function getVaultTsConfig(): array
    {
        $pageTsConfig = BackendUtility::getPagesTSconfig(0);
        /** @var array<string, mixed> $vaultConfig */
        $vaultConfig = \is_array($pageTsConfig['vault.'] ?? null) ? $pageTsConfig['vault.'] : [];

        /** @phpstan-ignore return.type */
        return \is_array($vaultConfig['permissions.'] ?? null) ? $vaultConfig['permissions.'] : [];
    }

    /**
     * @param array<string, mixed> $array
     * @param array<int, string> $keys
     */
    private function getNestedValue(array $array, array $keys): mixed
    {
        $current = $array;

        foreach ($keys as $key) {
            if (!\is_array($current)) {
                return null;
            }

            // Try with trailing dot (TSconfig convention for nested)
            if (isset($current[$key . '.'])) {
                $current = $current[$key . '.'];
            } elseif (isset($current[$key])) {
                return $current[$key];
            } else {
                return null;
            }
        }

        return null;
    }

    private function toBoolean(mixed $value): bool
    {
        if (\is_bool($value)) {
            return $value;
        }

        if (\is_string($value)) {
            return \in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true);
        }

        return (bool) $value;
    }

    private function getBuiltInDefault(VaultFieldPermission $permission): bool
    {
        return match ($permission) {
            VaultFieldPermission::Reveal => true,
            VaultFieldPermission::Copy => true,
            VaultFieldPermission::Edit => true,
            VaultFieldPermission::ReadOnly => false,
        };
    }
}
