<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use Netresearch\NrVault\Controller\OverviewController;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Backend\Module\ModuleInterface;
use TYPO3\CMS\Backend\Routing\Router;
use TYPO3\CMS\Backend\Routing\UriBuilder;

/**
 * Functional smoke tests for {@see OverviewController} wiring.
 *
 * The controller's `indexAction()` renders a full backend module
 * template through `ModuleTemplateFactory` → `BackendViewFactory`, which
 * pulls the current "module" request attribute to resolve view paths.
 * In a functional test the synthetic `ServerRequest` has no module
 * attribute attached — reproducing that routing context requires a
 * fake backend module registry that is deep enough to not belong here.
 * The full-rendering path is covered by the Playwright E2E suite
 * (`Tests/E2E/user-pathways/overview.spec.ts` — runs against a live
 * DDEV instance with the real module registered).
 *
 * This file only verifies the DI graph — that the controller can be
 * instantiated from the container with all its real collaborators,
 * which is still a regression guard against Services.yaml drift.
 *
 * `CoversNothing` because the class is excluded from unit coverage in
 * `Build/phpunit.xml` (its indexAction is covered functionally by E2E);
 * without it, PHPUnit 12 emits a "not a valid target for code
 * coverage" warning that `failOnWarning=true` promotes to an error.
 */
#[CoversNothing]
final class OverviewControllerTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    #[Test]
    public function controllerCanBeResolvedFromContainer(): void
    {
        $controller = $this->get(OverviewController::class);

        self::assertInstanceOf(OverviewController::class, $controller);
    }

    /**
     * The Help tab and the Dashboard tab must reach their own action on
     * TYPO3 13.4 as well. There, core's BackendModuleValidator::process()
     * rewrites any route whose module has a parent AND submodules
     * (`$module->getParentModule() && $module->hasSubModules()`) to a
     * submodule's `_default` target, so a link to `admin_vault.help` rendered
     * the overview. The link routes therefore have to belong to a module the
     * rewrite does not touch, and resolve to the intended action.
     */
    #[Test]
    public function theDocHeaderLinksTargetRoutesCoreDoesNotRewrite(): void
    {
        $router = $this->get(Router::class);
        $uriBuilder = $this->get(UriBuilder::class);

        foreach ([OverviewController::HELP_ROUTE => '::helpAction', OverviewController::OVERVIEW_ROUTE => '::indexAction'] as $routeName => $action) {
            self::assertTrue($router->hasRoute($routeName), $routeName . ' is registered');
            $route = $router->getRoute($routeName);
            self::assertNotNull($route);

            $module = $route->getOption('module');
            self::assertInstanceOf(ModuleInterface::class, $module);
            self::assertFalse(
                $module->getParentModule() instanceof ModuleInterface && $module->hasSubModules(),
                $routeName . ' belongs to ' . $module->getIdentifier() . ', which TYPO3 13.4 reroutes to a submodule',
            );
            self::assertSame(OverviewController::class . $action, $route->getOption('target'));

            $path = $uriBuilder->buildUriFromRoute($routeName)->getPath();
            self::assertSame($route->getPath(), preg_replace('#^/typo3#', '', $path));
        }

        self::assertSame('/module/admin/vault/overview/help', $router->getRoute(OverviewController::HELP_ROUTE)?->getPath());
    }
}
