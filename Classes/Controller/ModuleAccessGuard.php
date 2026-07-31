<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Localization\LanguageService;

/**
 * Per-action operation-permission gate for the vault backend modules.
 *
 * The vault modules are registered with `'access' => 'user'` so that a
 * non-admin holding a vault permission can reach them at all; the actual
 * authorization is asserted here, in the controller, for every single action
 * (same defence-in-depth stance as SEC-ACCESS-6 for the AJAX endpoints — the
 * module registration is a routing convenience, never the authority).
 *
 * Centralised in one collaborator rather than copied into five controllers so
 * the denial response is byte-identical everywhere and the "which permission
 * does this action need" decision has exactly one shape.
 */
final readonly class ModuleAccessGuard
{
    private const LL_PREFIX = 'LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:';

    public function __construct(
        private AccessControlServiceInterface $accessControlService,
        private ModuleTemplateFactory $moduleTemplateFactory,
    ) {}

    /**
     * Is the actor granted this single operation permission?
     */
    public function isGranted(VaultPermission $permission): bool
    {
        return $this->accessControlService->isGranted($permission);
    }

    /**
     * Is the actor granted at least ONE of these operation permissions?
     *
     * Used for the "may this actor enter the module at all" gates, where any
     * single permission from a set implies a legitimate reason to see the
     * listing (the individual mutating actions re-check their own permission).
     */
    public function isAnyGranted(VaultPermission ...$permissions): bool
    {
        foreach ($permissions as $permission) {
            if ($this->accessControlService->isGranted($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Render the module-shaped 403 for a denied action.
     *
     * Keeps the backend chrome (module menu) so the operator can navigate to a
     * submodule they *are* allowed to use, states which permission is missing,
     * and carries a real 403 status rather than a 200 with an error body.
     */
    public function deniedResponse(
        ServerRequestInterface $request,
        VaultPermission $required,
    ): ResponseInterface {
        $lang = $this->getLanguageService();
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        $moduleTemplate->setTitle($lang->sL(self::LL_PREFIX . 'accessDenied.title'));
        $moduleTemplate->assignMultiple([
            'requiredPermission' => $required->value,
        ]);

        return $moduleTemplate->renderResponse('AccessDenied')->withStatus(403);
    }

    private function getLanguageService(): LanguageService
    {
        \assert($GLOBALS['LANG'] instanceof LanguageService);

        return $GLOBALS['LANG'];
    }
}
