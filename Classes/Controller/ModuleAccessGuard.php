<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Controller;

use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Template\ModuleTemplateFactory;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;

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
        private LanguageServiceFactory $languageServiceFactory,
    ) {}

    /**
     * Is the actor granted this single operation permission?
     */
    public function isGranted(VaultPermission $permission): bool
    {
        return $this->accessControlService->isGranted($permission);
    }

    /**
     * May the actor change THIS secret?
     *
     * An operation permission answers "may this actor ever do X"; it says
     * nothing about which secrets X may be done to. Module actions that
     * mutate one named secret need both, so the per-secret tier is exposed
     * here alongside isGranted() rather than reached for through a second
     * injected service in every controller.
     */
    public function canWrite(Secret $secret): bool
    {
        return $this->accessControlService->canWrite($secret);
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
        return $this->renderDenied($request, $required->value);
    }

    /**
     * Render the module-shaped 403 for an action refused on ONE secret.
     *
     * The actor passed the operation permission gate — the refusal comes from
     * the secret's own tiers (owner / write groups). Reusing deniedResponse()
     * here would name a permission the actor demonstrably holds, sending both
     * the operator and whoever picks up the ticket after a grant that is
     * already in place. Deliberately says nothing about WHICH secret: the page
     * carries no identifier, so it cannot become a disclosure channel, and the
     * audit entry the caller writes is where the identifier belongs.
     */
    public function deniedForSecretResponse(ServerRequestInterface $request): ResponseInterface
    {
        return $this->renderDenied($request, null);
    }

    /**
     * @param string|null $requiredPermission the missing permission, or null
     *                                        when the refusal is per-secret
     */
    private function renderDenied(
        ServerRequestInterface $request,
        ?string $requiredPermission,
    ): ResponseInterface {
        $lang = $this->getLanguageService();
        $moduleTemplate = $this->moduleTemplateFactory->create($request);
        $moduleTemplate->makeDocHeaderModuleMenu();
        $moduleTemplate->setTitle($lang->sL(self::LL_PREFIX . 'accessDenied.title'));
        $moduleTemplate->assignMultiple([
            'requiredPermission' => $requiredPermission,
        ]);

        return $moduleTemplate->renderResponse('AccessDenied')->withStatus(403);
    }

    private function getLanguageService(): LanguageService
    {
        return $this->languageServiceFactory->create();
    }
}
