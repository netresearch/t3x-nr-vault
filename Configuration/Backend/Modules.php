<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\Controller\AnalyticsController;
use Netresearch\NrVault\Controller\AuditController;
use Netresearch\NrVault\Controller\MigrationController;
use Netresearch\NrVault\Controller\OverviewController;
use Netresearch\NrVault\Controller\SecretsController;

/**
 * Backend module configuration for nr_vault.
 *
 * Parent module with submodules (following TYPO3 styleguide pattern).
 * - Parent shows submodule overview with cards
 * - Submodule selector appears in DocHeader
 *
 * Uses 'tools' as parent for v13+v14 compatibility:
 * - v13: 'tools' exists natively as the admin tools group
 * - v14: 'tools' is an alias for the new 'admin' group
 *
 * Uses LLL:EXT: label format (compatible with TYPO3 v13+v14)
 *
 * v13 compatibility: 'admin_vault_overview' is registered as first submodule so that
 * v13 (which redirects to the first submodule) shows the overview page.
 * v14 uses 'showSubmoduleOverview' on the parent module for the same effect.
 */
$indexAction = '::indexAction';
$helpAction = '::helpAction';

return [
    // Parent module - custom overview with usage information
    // dependsOnSubmodules: true enables the submodule dropdown in DocHeader
    // showSubmoduleOverview: true prevents redirect to last-used submodule
    'admin_vault' => [
        'parent' => 'tools',
        'position' => ['after' => 'admin_sites'],
        'access' => 'admin',
        'workspaces' => 'live',
        'path' => '/module/admin/vault',
        'labels' => 'LLL:EXT:nr_vault/Resources/Private/Language/Modules/overview.xlf',
        'iconIdentifier' => 'module-vault',
        'appearance' => [
            'dependsOnSubmodules' => true,
        ],
        // v14+: Show overview page for parent module
        'showSubmoduleOverview' => true,
        'routes' => [
            '_default' => [
                'target' => OverviewController::class . $indexAction,
            ],
            'help' => [
                'target' => OverviewController::class . $helpAction,
            ],
        ],
    ],

    // Overview submodule - v13 compatibility
    // In v13, dependsOnSubmodules redirects to the first submodule.
    // This ensures the overview page is shown instead of secrets.
    // In v14, showSubmoduleOverview on the parent handles this natively.
    'admin_vault_overview' => [
        'parent' => 'admin_vault',
        'position' => ['before' => '*'],
        'access' => 'admin',
        'workspaces' => 'live',
        'path' => '/module/admin/vault/overview',
        'labels' => 'LLL:EXT:nr_vault/Resources/Private/Language/Modules/overview_submodule.xlf',
        'iconIdentifier' => 'module-vault',
        'routes' => [
            '_default' => [
                'target' => OverviewController::class . $indexAction,
            ],
            'help' => [
                'target' => OverviewController::class . $helpAction,
            ],
        ],
    ],

    // Secrets submodule
    'admin_vault_secrets' => [
        'parent' => 'admin_vault',
        'access' => 'admin',
        'workspaces' => 'live',
        'path' => '/module/admin/vault/secrets',
        'labels' => 'LLL:EXT:nr_vault/Resources/Private/Language/Modules/secrets.xlf',
        'iconIdentifier' => 'module-vault-secrets',
        'routes' => [
            '_default' => [
                'target' => SecretsController::class . '::listAction',
            ],
            'create' => [
                'target' => SecretsController::class . '::createAction',
            ],
            'edit' => [
                'target' => SecretsController::class . '::editAction',
            ],
            'toggle' => [
                'target' => SecretsController::class . '::toggleAction',
                'methods' => ['POST'],
            ],
            'delete' => [
                'target' => SecretsController::class . '::deleteAction',
                'methods' => ['POST'],
            ],
        ],
    ],

    // Analytics submodule
    'admin_vault_analytics' => [
        'parent' => 'admin_vault',
        'access' => 'admin',
        'workspaces' => 'live',
        'path' => '/module/admin/vault/analytics',
        'labels' => 'LLL:EXT:nr_vault/Resources/Private/Language/Modules/analytics.xlf',
        'iconIdentifier' => 'module-vault-analytics',
        'routes' => [
            '_default' => [
                'target' => AnalyticsController::class . $indexAction,
            ],
        ],
    ],

    // Audit submodule
    'admin_vault_audit' => [
        'parent' => 'admin_vault',
        'access' => 'admin',
        'workspaces' => 'live',
        'path' => '/module/admin/vault/audit',
        'labels' => 'LLL:EXT:nr_vault/Resources/Private/Language/Modules/audit.xlf',
        'iconIdentifier' => 'module-vault-audit',
        'routes' => [
            '_default' => [
                'target' => AuditController::class . '::listAction',
            ],
            'export' => [
                'target' => AuditController::class . '::exportAction',
            ],
            'verifyChain' => [
                'target' => AuditController::class . '::verifyChainAction',
            ],
        ],
    ],

    // Migration wizard submodule
    // Uses handleRequest pattern like TYPO3 core - dispatches based on ?action= query param
    'admin_vault_migration' => [
        'parent' => 'admin_vault',
        'access' => 'admin',
        'workspaces' => 'live',
        'path' => '/module/admin/vault/migration',
        'labels' => 'LLL:EXT:nr_vault/Resources/Private/Language/Modules/migration.xlf',
        'iconIdentifier' => 'module-vault-migration',
        'routes' => [
            '_default' => [
                'target' => MigrationController::class . '::handleRequest',
            ],
        ],
    ],
];
