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
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;

/**
 * Make `/typo3/module/admin/vault` render the vault overview on every supported
 * TYPO3 major.
 *
 * `Configuration/Backend/Modules.php` documents the parent module as the
 * overview page, and TYPO3 14 honours that through `showSubmoduleOverview`.
 * TYPO3 13.4 has no such option: `BackendModuleValidator` rewrites a
 * second-level module that has submodules to a third-level one,
 *
 *     if ($module->getParentModule() && $module->hasSubModules()) {
 *         $subModuleIdentifier = (string)($backendUser->getModuleData($module->getIdentifier())['action'] ?? '');
 *
 * and that `action` key holds the submodule the user opened last — the same
 * middleware writes it further down, under "remember the previously selected
 * module in the parent module". Registering the overview as the first submodule
 * only covers the fallback branch, reached exactly once: for a user who has
 * never opened a vault submodule. Afterwards the parent opens Secrets, or
 * Audit, and the overview is unreachable.
 *
 * So the stored selection is what has to say "overview" — not the route.
 * Replacing the route's module instead does not work: the requested route's
 * `_identifier` is then the new module's PARENT, which is precisely the
 * condition of core's `elseif` branch, and that branch resolves the last-used
 * submodule all over again. Measured on 13.4: the 500 disappeared and the page
 * was still Secrets.
 *
 * Writing the selection lets core's own first branch pick the overview, keeps
 * the URL and the route target untouched, and matches what the parent module is
 * documented to do. The write is in-memory (`pushModuleData(..., true)`): this
 * middleware does not persist a user setting of its own.
 *
 * On TYPO3 14 the module reports `hasSubmoduleOverview()`, core renders the
 * overview itself, and this middleware returns untouched.
 */
final readonly class VaultOverviewModuleResolver implements MiddlewareInterface
{
    // The vault parent module, whose stored submodule selection is steered.
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
        //
        // `hasSubmoduleOverview()` arrived on ModuleInterface with TYPO3 14 —
        // calling it unguarded is a fatal on 13.4, the very major this
        // middleware exists for. method_exists() asks the running core for the
        // capability rather than inferring it from a version number.
        if (method_exists($module, 'hasSubmoduleOverview') && $module->hasSubmoduleOverview()) {
            return $handler->handle($request);
        }

        $backendUser = $GLOBALS['BE_USER'] ?? null;
        if (!$backendUser instanceof BackendUserAuthentication) {
            return $handler->handle($request);
        }

        $moduleData = $backendUser->getModuleData(self::PARENT_MODULE);
        $moduleData = \is_array($moduleData) ? $moduleData : [];

        if (($moduleData['action'] ?? null) !== self::OVERVIEW_MODULE) {
            $moduleData['action'] = self::OVERVIEW_MODULE;
            // `true` keeps the write in memory: core persists the user's
            // settings itself when it has a reason to, and opening the parent
            // module is not one.
            $backendUser->pushModuleData(self::PARENT_MODULE, $moduleData, true);
        }

        return $handler->handle($request);
    }
}
