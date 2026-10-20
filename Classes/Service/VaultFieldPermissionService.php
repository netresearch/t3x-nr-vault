<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use Psr\Log\LoggerAwareInterface;
use TYPO3\CMS\Backend\Utility\BackendUtility;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Cache\CacheManager;
use TYPO3\CMS\Core\Cache\Frontend\PhpFrontend;
use TYPO3\CMS\Core\Context\Context;
use TYPO3\CMS\Core\Context\UserAspect;
use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\Page\PageLayoutResolver;
use TYPO3\CMS\Core\SingletonInterface;
use TYPO3\CMS\Core\Site\Entity\NullSite;
use TYPO3\CMS\Core\TypoScript\IncludeTree\IncludeNode\TsConfigInclude;
use TYPO3\CMS\Core\TypoScript\IncludeTree\Traverser\ConditionVerdictAwareIncludeTreeTraverser;
use TYPO3\CMS\Core\TypoScript\IncludeTree\TsConfigTreeBuilder;
use TYPO3\CMS\Core\TypoScript\IncludeTree\Visitor\IncludeTreeAstBuilderVisitor;
use TYPO3\CMS\Core\TypoScript\IncludeTree\Visitor\IncludeTreeConditionMatcherVisitor;
use TYPO3\CMS\Core\TypoScript\PageTsConfig;
use TYPO3\CMS\Core\TypoScript\Tokenizer\LossyTokenizer;
use TYPO3\CMS\Core\Utility\GeneralUtility;

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

    /**
     * Check if a specific action is allowed for a vault field.
     */
    public function isAllowed(
        string $table,
        string $field,
        VaultFieldPermission $permission,
        ?BackendUserAuthentication $backendUser = null,
    ): bool {
        $backendUser ??= $this->getBackendUser();

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

        $allowed = $this->checkPermission($table, $field, $permission, $backendUser);
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
        BackendUserAuthentication $backendUser,
    ): bool {
        $tsConfig = $this->getVaultTsConfig($backendUser);

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
    private function getVaultTsConfig(
        BackendUserAuthentication $backendUser,
    ): array {
        // The selected-user coordinator's native Core result is the ADR049 boundary.
        /** @phpstan-ignore method.internalClass */
        $pageTsConfig = $backendUser === $this->getBackendUser() ? BackendUtility::getPagesTSconfig(0) : $this->getSelectedUserPageTsConfig($backendUser)->getPageTsConfigArray();
        /** @var array<string, mixed> $vaultConfig */
        $vaultConfig = \is_array($pageTsConfig['vault.'] ?? null) ? $pageTsConfig['vault.'] : [];

        /** @phpstan-ignore return.type */
        return \is_array($vaultConfig['permissions.'] ?? null) ? $vaultConfig['permissions.'] : [];
    }

    private function getBackendUser(): ?BackendUserAuthentication
    {
        $beUser = $GLOBALS['BE_USER'] ?? null;

        return $beUser instanceof BackendUserAuthentication ? $beUser : null;
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

    /**
     * Build a private page-zero policy for a distinct selected user. Core's
     * ordinary page-zero runtime cache and the ambient Context stay untouched.
     *
     * ADR049 deliberately coordinates these Core internals; native Core 13/14
     * functional tests cover their signatures, configured AST visitor and state.
     */
    private function getSelectedUserPageTsConfig(
        BackendUserAuthentication $backendUser,
    ): PageTsConfig {
        /** @phpstan-ignore new.internalClass */
        $tokenizer = new LossyTokenizer();
        /** @var PhpFrontend $cache */
        $cache = GeneralUtility::makeInstance(CacheManager::class)->getCache(
            'typoscript',
        );
        /** @phpstan-ignore classConstant.internalClass, method.internalClass */
        $tree = GeneralUtility::makeInstance(TsConfigTreeBuilder::class)->getPagesTsConfigTree(
            [],
            $tokenizer,
            $cache,
        );
        $overrides = '';
        /**
         * Core AST flattening excludes null values.
         *
         * @var array<string, string> $flatOverrides
         *
         * @phpstan-ignore method.internal, method.internalClass
         */
        $flatOverrides = $backendUser->getUserTsConfig()?->getUserTsConfigTree()->flatten() ?? [];
        foreach ($flatOverrides as $key => $value) {
            if (str_starts_with($key, 'page.')) {
                $overrides .= substr($key, 5) . ' = ' . $value . "\n";
            }
        }

        if ($overrides !== '') {
            /** @phpstan-ignore new.internalClass */
            $node = new TsConfigInclude();
            /** @phpstan-ignore method.internalClass */
            $node->setName('selected-page-overrides');
            /** @phpstan-ignore method.internalClass */
            $overrideLines = $tokenizer->tokenize($overrides);
            /** @phpstan-ignore method.internalClass */
            $node->setLineStream($overrideLines);
            /** @phpstan-ignore method.internalClass */
            $tree->addChild($node);
        }

        $context = clone GeneralUtility::makeInstance(Context::class);
        $context->setAspect('backend.user', new UserAspect($backendUser));
        /** @phpstan-ignore classConstant.internalClass */
        $layout = GeneralUtility::makeInstance(PageLayoutResolver::class);
        /** @phpstan-ignore classConstant.internalClass */
        $conditionVisitorClass = IncludeTreeConditionMatcherVisitor::class;
        $logger = GeneralUtility::makeInstance(LogManager::class)->getLogger(
            $conditionVisitorClass,
        );

        // Core 13 uses setter injection; Core 14 requires its logger in the constructor.
        // The loaded-major analyzer sees only one side of this native-tested branch.
        /** @phpstan-ignore function.impossibleType, function.alreadyNarrowedType */
        if (is_a($conditionVisitorClass, LoggerAwareInterface::class, true)) {
            /** @phpstan-ignore arguments.count, method.internalClass, new.internalClass */
            $matcher = new IncludeTreeConditionMatcherVisitor($context, $layout);
            /** @phpstan-ignore method.notFound, method.internalClass */
            $matcher->setLogger($logger);
        } else {
            /** @phpstan-ignore arguments.count, method.internalClass, new.internalClass */
            $matcher = new IncludeTreeConditionMatcherVisitor($context, $layout, $logger);
        }

        /** @phpstan-ignore method.internalClass */
        $matcher->initializeExpressionMatcherWithVariables(
            [
                'fullRootLine' => [],
                'site' => new NullSite(),
                'page' => [],
                'pageId' => 0,
            ],
        );
        /** @phpstan-ignore classConstant.internalClass */
        $astVisitor = GeneralUtility::makeInstance(IncludeTreeAstBuilderVisitor::class);
        /** @phpstan-ignore method.internalClass, new.internalClass */
        (new ConditionVerdictAwareIncludeTreeTraverser())->traverse(
            $tree,
            [$matcher, $astVisitor],
        );

        /** @phpstan-ignore method.internalClass, new.internalClass */
        return new PageTsConfig(
            /** @phpstan-ignore method.internalClass */
            $astVisitor->getAst(),
            /** @phpstan-ignore method.internalClass */
            $matcher->getConditionListWithVerdicts(),
        );
    }
}
