<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Backend\Module\ModuleInterface;
use TYPO3\CMS\Backend\Routing\Route;

/**
 * Make `/typo3/module/admin/vault` render the vault overview on every supported
 * TYPO3 major.
 *
 * `Configuration/Backend/Modules.php` documents the parent module as the
 * overview page, and TYPO3 14 honours that through `showSubmoduleOverview`.
 * TYPO3 13 has no such option: `BackendModuleValidator` unconditionally
 * rewrites a second-level module that has submodules to a third-level one,
 *
 *     if ($module->getParentModule() && $module->hasSubModules()) {
 *         $subModuleIdentifier = (string)($backendUser->getModuleData($module->getIdentifier())['action'] ?? '');
 *         …
 *
 * and that `action` key is the LAST submodule the user opened (the same
 * middleware writes it further down, "remember the previously selected module
 * in the parent module"). Registering the overview as the first submodule only
 * covers the fallback branch, which is reached exactly once — for a user who
 * has never opened a vault submodule. Afterwards the parent opens Secrets, or
 * Audit, or whatever was visited last, and the overview is unreachable.
 *
 * The fix resolves the parent route to the overview submodule BEFORE the core
 * middleware runs. `admin_vault_overview` has no submodules of its own, so
 * core's rewrite branch no longer applies and the route target — already
 * `OverviewController::indexAction` on the parent route — stands.
 *
 * On TYPO3 14 the module reports `hasSubmoduleOverview()`, core skips its
 * rewrite by itself, and this middleware returns untouched.
 */
final readonly class VaultOverviewModuleResolver implements MiddlewareInterface
{
    // The vault parent module, whose route this middleware re-points.
    private const PARENT_MODULE = 'admin_vault';

    // The submodule rendering the overview. Same controller action as the
    // parent's `_default` route, registered separately because TYPO3 13 can
    // only resolve a parent module to one of its children.
    private const OVERVIEW_MODULE = 'admin_vault_overview';

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $route = $request->getAttribute('route');
        if (!$route instanceof Route) {
            return $handler->handle($request);
        }

        $module = $route->getOption('module');
        if (!$module instanceof ModuleInterface || $module->getIdentifier() !== self::PARENT_MODULE) {
            return $handler->handle($request);
        }

        // TYPO3 14 and later: core renders the overview itself.
        if ($module->hasSubmoduleOverview()) {
            return $handler->handle($request);
        }

        $overview = $module->getSubModule(self::OVERVIEW_MODULE);
        if (!$overview instanceof ModuleInterface) {
            return $handler->handle($request);
        }

        // Only the module option is replaced. The route keeps its path and its
        // target, so the URL the user sees and the controller that answers it
        // are the ones the parent module registered.
        $route->setOption('module', $overview);

        return $handler->handle($request);
    }
}
