<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use Exception;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\VaultHealthServiceInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Attribute\AsController;
use TYPO3\CMS\Backend\Routing\UriBuilder as BackendUriBuilder;
use TYPO3\CMS\Backend\Template\ModuleTemplate;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Page\PageRenderer;

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
        private VaultHealthServiceInterface $vaultHealthService,
        private BackendUriBuilder $backendUriBuilder,
        private PageRenderer $pageRenderer,
        private ModuleAccessGuard $accessGuard,
        private BreakGlassBannerProvider $breakGlassBanner,
        private SecurityStatusProvider $securityStatus,
    ) {}

    /**
     * Display vault overview with submodule cards and usage information.
     *
     * Reachable with ANY vault permission — it is the landing page of the
     * module tree. The submodule cards are filtered to the ones the actor can
     * actually open, so the overview never links into a 403.
     */
    public function indexAction(ServerRequestInterface $request): ResponseInterface
    {
        if (!$this->hasAnyVaultPermission()) {
            return $this->accessGuard->deniedResponse($request, VaultPermission::SecretUse);
        }

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

        // Expose JS UI labels to TYPO3.lang for any vault ESM module that may
        // run on the overview surface (graceful: modules fall back to English).
        $this->pageRenderer->addInlineLanguageLabelFile('EXT:nr_vault/Resources/Private/Language/locallang_js.xlf');
        $this->pageRenderer->addCssFile('EXT:nr_vault/Resources/Public/Css/backend.css');

        // Get statistics for the overview
        $stats = $this->getVaultStatistics();
        $healthChecks = $this->getHealthChecks();

        $lang = $this->getLanguageService();

        $moduleTemplate->assignMultiple([
            'stats' => $stats,
            'healthChecks' => $healthChecks,
            'submodules' => $this->getAccessibleSubmodules($lang),
            'breakGlass' => $this->breakGlassBanner->forView(),
            // Readiness controls with the profile badge and pass ratio. The
            // detailed finding list inside is gated on VaultConfigure by the
            // provider, not by the template.
            'securityStatus' => $this->securityStatus->forView(),
        ]);

        return $moduleTemplate->renderResponse('Overview/Index');
    }

    /**
     * Display vault help and documentation page.
     */
    public function helpAction(ServerRequestInterface $request): ResponseInterface
    {
        if (!$this->hasAnyVaultPermission()) {
            return $this->accessGuard->deniedResponse($request, VaultPermission::SecretUse);
        }

        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        $this->buildDocHeaderTabMenu($moduleTemplate, 'help');
        $this->pageRenderer->addCssFile('EXT:nr_vault/Resources/Public/Css/backend.css');

        $moduleTemplate->assignMultiple([
            'dashboardUrl' => (string) $this->backendUriBuilder->buildUriFromRoute(self::MODULE_NAME),
        ]);

        return $moduleTemplate->renderResponse('Overview/Help');
    }

    /**
     * Does the actor hold at least one vault permission?
     *
     * The overview is the module tree's landing page, so any single permission
     * is enough to see it; the cards and the submodules themselves enforce the
     * specific permission each operation needs.
     */
    private function hasAnyVaultPermission(): bool
    {
        return $this->accessGuard->isAnyGranted(...VaultPermission::cases());
    }

    /**
     * Submodule cards, filtered to the ones the actor may actually open.
     *
     * The required permission per card mirrors exactly what the target
     * controller asserts, so a rendered card can never lead to a 403.
     *
     * @return list<array{route: string, icon: string, title: string, description: string}>
     */
    private function getAccessibleSubmodules(LanguageService $lang): array
    {
        $llPrefix = 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:';

        $candidates = [
            [
                'route' => 'admin_vault_secrets',
                'icon' => 'module-vault-secrets',
                'title' => $lang->sL($llPrefix . 'secrets.title'),
                'description' => $lang->sL($llPrefix . 'overview.secrets.description'),
                // SecretsController::listAction() admits any secret-handling
                // permission.
                'permissions' => VaultPermission::secretOperations(),
            ],
            [
                'route' => 'admin_vault_analytics',
                'icon' => 'module-vault-analytics',
                'title' => $lang->sL($llPrefix . 'analytics.title'),
                'description' => $lang->sL($llPrefix . 'overview.analytics.description'),
                'permissions' => [VaultPermission::AuditView],
            ],
            [
                'route' => 'admin_vault_audit',
                'icon' => 'module-vault-audit',
                'title' => $lang->sL($llPrefix . 'audit.title'),
                'description' => $lang->sL($llPrefix . 'overview.audit.description'),
                'permissions' => [VaultPermission::AuditView],
            ],
            [
                'route' => 'admin_vault_migration',
                'icon' => 'module-vault-migration',
                'title' => $lang->sL($llPrefix . 'migration.title'),
                'description' => $lang->sL($llPrefix . 'overview.migration.description'),
                'permissions' => [VaultPermission::VaultConfigure],
            ],
        ];

        $accessible = [];
        foreach ($candidates as $card) {
            if (!$this->accessGuard->isAnyGranted(...$card['permissions'])) {
                continue;
            }

            unset($card['permissions']);
            $accessible[] = $card;
        }

        return $accessible;
    }

    /**
     * Build a Dashboard/Help tab menu in the docheader.
     */
    private function buildDocHeaderTabMenu(
        ModuleTemplate $moduleTemplate,
        string $activeTab,
    ): void {
        $lang = $this->getLanguageService();
        $menuRegistry = $moduleTemplate->getDocHeaderComponent()->getMenuRegistry();
        $menu = $menuRegistry->makeMenu();
        $menu->setIdentifier('VaultOverviewMenu');

        $dashboardItem = $menu->makeMenuItem()
            ->setTitle($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:overview.tab.dashboard'))
            ->setHref((string) $this->backendUriBuilder->buildUriFromRoute(self::MODULE_NAME));
        if ($activeTab === 'dashboard') {
            $dashboardItem->setActive(true);
        }
        $menu->addMenuItem($dashboardItem);

        $helpItem = $menu->makeMenuItem()
            ->setTitle($lang->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:overview.tab.help'))
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
     * Run health checks and return status information for the template.
     *
     * The probe lives in {@see VaultHealthServiceInterface} so this controller
     * does not depend on the Crypto namespace (ARCHITECTURE-2). Only generic
     * booleans + the provider identifier reach the view — no raw exception
     * text or key file paths (SEC-INJECTION-LEAK-2); detail is logged in the
     * service.
     *
     * @return array{masterKeyAvailable: bool, masterKeyProvider: string, encryptionWorking: bool, hasIssues: bool}
     */
    private function getHealthChecks(): array
    {
        $status = $this->vaultHealthService->checkHealth();

        return [
            'masterKeyAvailable' => $status->masterKeyAvailable,
            'masterKeyProvider' => $status->masterKeyProvider,
            'encryptionWorking' => $status->encryptionWorking,
            'hasIssues' => $status->hasIssues,
        ];
    }

    private function getLanguageService(): LanguageService
    {
        \assert($GLOBALS['LANG'] instanceof LanguageService);

        return $GLOBALS['LANG'];
    }
}
