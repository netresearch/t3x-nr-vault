<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use Exception;
use Netresearch\NrVault\Crypto\MasterKeyProviderFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Backend\Routing\UriBuilder as BackendUriBuilder;
use TYPO3\CMS\Backend\Template\ModuleTemplate;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Localization\LanguageService;

/**
 * Backend module controller for vault overview/dashboard.
 */
#[AsController]
final readonly class OverviewController
{
    private const MODULE_NAME = 'admin_vault';

    public function __construct(
        private ModuleTemplateFactory $moduleTemplateFactory,
        private ConnectionPool $connectionPool,
        private MasterKeyProviderFactoryInterface $masterKeyProviderFactory,
        private BackendUriBuilder $backendUriBuilder,
    ) {}

    /**
     * Display vault overview with submodule cards and usage information.
     */
    public function indexAction(ServerRequestInterface $request): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        $this->buildDocHeaderTabMenu($moduleTemplate, 'dashboard');
        /** @phpstan-ignore function.alreadyNarrowedType (v14-only method, not available in v13) */
        if (method_exists($moduleTemplate->getDocHeaderComponent(), 'setShortcutContext')) {
            $moduleTemplate->getDocHeaderComponent()->setShortcutContext(
                routeIdentifier: self::MODULE_NAME,
                displayName: $this->getLanguageService()->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:mlang_tabs_tab'),
            );
        }

        // Get statistics for the overview
        $stats = $this->getVaultStatistics();
        $healthChecks = $this->getHealthChecks();

        $lang = $this->getLanguageService();

        $moduleTemplate->assignMultiple([
            'stats' => $stats,
            'healthChecks' => $healthChecks,
            'submodules' => [
                [
                    'route' => 'admin_vault_secrets',
                    'icon' => 'content-elements-login',
                    'title' => 'Secrets',
                    'description' => $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:overview.secrets.description'),
                ],
                [
                    'route' => 'admin_vault_audit',
                    'icon' => 'actions-document-history-open',
                    'title' => 'Audit Log',
                    'description' => $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:overview.audit.description'),
                ],
                [
                    'route' => 'admin_vault_migration',
                    'icon' => 'actions-database-import',
                    'title' => 'Migration Wizard',
                    'description' => $lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:overview.migration.description'),
                ],
            ],
        ]);

        return $moduleTemplate->renderResponse('Overview/Index');
    }

    /**
     * Display vault help and documentation page.
     */
    public function helpAction(ServerRequestInterface $request): ResponseInterface
    {
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        $this->buildDocHeaderTabMenu($moduleTemplate, 'help');

        $moduleTemplate->assignMultiple([
            'dashboardUrl' => (string) $this->backendUriBuilder->buildUriFromRoute(self::MODULE_NAME),
        ]);

        return $moduleTemplate->renderResponse('Overview/Help');
    }

    /**
     * Build a Dashboard/Help tab menu in the docheader.
     */
    private function buildDocHeaderTabMenu(
        ModuleTemplate $moduleTemplate,
        string $activeTab,
    ): void {
        $menuRegistry = $moduleTemplate->getDocHeaderComponent()->getMenuRegistry();
        $menu = $menuRegistry->makeMenu();
        $menu->setIdentifier('VaultOverviewMenu');

        $dashboardItem = $menu->makeMenuItem()
            ->setTitle('Dashboard')
            ->setHref((string) $this->backendUriBuilder->buildUriFromRoute(self::MODULE_NAME));
        if ($activeTab === 'dashboard') {
            $dashboardItem->setActive(true);
        }
        $menu->addMenuItem($dashboardItem);

        $helpItem = $menu->makeMenuItem()
            ->setTitle('Help')
            ->setHref((string) $this->backendUriBuilder->buildUriFromRoute(self::MODULE_NAME . '.help'));
        if ($activeTab === 'help') {
            $helpItem->setActive(true);
        }
        $menu->addMenuItem($helpItem);

        $menuRegistry->addMenu($menu);
    }

    /**
     * Get vault statistics for the overview.
     *
     * @return array<string, int>
     */
    private function getVaultStatistics(): array
    {
        try {
            // Count total secrets (including hidden) - remove default restrictions
            $queryBuilder = $this->connectionPool->getQueryBuilderForTable('tx_nrvault_secret');
            $queryBuilder->getRestrictions()->removeAll();
            $totalResult = $queryBuilder
                ->count('uid')
                ->from('tx_nrvault_secret')
                ->where($queryBuilder->expr()->eq('deleted', 0))
                ->executeQuery()
                ->fetchOne();
            $totalSecrets = is_numeric($totalResult) ? (int) $totalResult : 0;

            // Count active secrets (not hidden) - remove default restrictions for explicit control
            $queryBuilder = $this->connectionPool->getQueryBuilderForTable('tx_nrvault_secret');
            $queryBuilder->getRestrictions()->removeAll();
            $activeResult = $queryBuilder
                ->count('uid')
                ->from('tx_nrvault_secret')
                ->where(
                    $queryBuilder->expr()->eq('deleted', 0),
                    $queryBuilder->expr()->eq('hidden', 0),
                )
                ->executeQuery()
                ->fetchOne();
            $activeSecrets = is_numeric($activeResult) ? (int) $activeResult : 0;

            return [
                'totalSecrets' => $totalSecrets,
                'activeSecrets' => $activeSecrets,
                'disabledSecrets' => $totalSecrets - $activeSecrets,
            ];
        } catch (Exception) {
            return [
                'totalSecrets' => 0,
                'activeSecrets' => 0,
                'disabledSecrets' => 0,
            ];
        }
    }

    /**
     * Run health checks and return status information.
     *
     * @return array{masterKeyAvailable: bool, masterKeyProvider: string, masterKeyError: string, encryptionWorking: bool, encryptionError: string, hasIssues: bool}
     */
    private function getHealthChecks(): array
    {
        $result = [
            'masterKeyAvailable' => false,
            'masterKeyProvider' => '',
            'masterKeyError' => '',
            'encryptionWorking' => false,
            'encryptionError' => '',
            'hasIssues' => false,
        ];

        // Check 1: Is a master key provider available?
        try {
            $provider = $this->masterKeyProviderFactory->getAvailableProvider();
            $result['masterKeyProvider'] = $provider->getIdentifier();

            if ($provider->isAvailable()) {
                $result['masterKeyAvailable'] = true;

                // Check 2: Can we actually derive/read the master key?
                try {
                    $key = $provider->getMasterKey();
                    if ($key === '') {
                        $result['encryptionError'] = 'Master key provider returned an empty key.';
                        $result['hasIssues'] = true;
                    } else {
                        $result['encryptionWorking'] = true;
                        sodium_memzero($key);
                    }
                } catch (Exception $e) {
                    $result['encryptionError'] = $e->getMessage();
                    $result['hasIssues'] = true;
                }
            } else {
                $result['masterKeyError'] = 'Master key provider "' . $provider->getIdentifier() . '" is configured but not available.';
                $result['hasIssues'] = true;
            }
        } catch (Exception $e) {
            $result['masterKeyError'] = $e->getMessage();
            $result['hasIssues'] = true;
        }

        return $result;
    }

    private function getLanguageService(): LanguageService
    {
        \assert($GLOBALS['LANG'] instanceof LanguageService);

        return $GLOBALS['LANG'];
    }
}
