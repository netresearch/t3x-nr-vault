<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use DOMDocument;
use Netresearch\NrVault\Controller\OverviewController;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\Routing\Route as SymfonyRoute;
use TYPO3\CMS\Backend\Module\ModuleData;
use TYPO3\CMS\Backend\Module\ModuleInterface;
use TYPO3\CMS\Backend\Module\ModuleProvider;
use TYPO3\CMS\Backend\Routing\Route;
use TYPO3\CMS\Backend\Routing\Router;
use TYPO3\CMS\Backend\Routing\UriBuilder;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Http\NormalizedParams;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;

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

    /**
     * The links the Help page actually renders, read from its response: the
     * Help and Dashboard entries of the docheader tab menu, and the dashboard
     * link in the page body. Each must reach the overview submodule, not the
     * `admin_vault` parent, which TYPO3 13.4 reroutes.
     */
    #[Test]
    public function theHelpPageLinksItsTabsAndDashboardToTheOverviewSubmodule(): void
    {
        $html = $this->renderHelpPage();
        $links = $this->linkPaths($html);

        // The docheader tab menu: one entry per tab. 13.4 renders it as a
        // <select>, 14.3 as a dropdown of titled links.
        self::assertSame(['typo3/module/admin/vault/overview/help'], $links['menu=Help'] ?? null);
        self::assertSame(['typo3/module/admin/vault/overview'], $links['menu=Dashboard'] ?? null);
        // The "Visit the Dashboard" link in the page body carries no title.
        self::assertSame(['typo3/module/admin/vault/overview'], $links['text=Dashboard'] ?? null);
    }

    private function withModuleContext(ServerRequestInterface $request, Route|SymfonyRoute $route, ModuleInterface $module): ServerRequestInterface
    {
        /** @phpstan-ignore classConstant.internal */
        $applicationType = SystemEnvironmentBuilder::REQUESTTYPE_BE;

        $request = $request
            ->withAttribute('applicationType', $applicationType)
            ->withAttribute('route', $route)
            ->withAttribute('module', $module)
            ->withAttribute('moduleData', ModuleData::createFromModule($module, []));

        /** @phpstan-ignore staticMethod.internal */
        $normalizedParams = NormalizedParams::createFromRequest($request);

        return $request->withAttribute('normalizedParams', $normalizedParams);
    }

    /**
     * Link targets in $html without the leading slash (14.3 renders relative
     * hrefs) and without the route token, which differs per route and says
     * nothing about the target. Docheader menu entries are keyed
     * `menu=<label>`: an <option> on 13.4, a titled link on 14.3. Links
     * without a title are keyed `text=<text>`.
     *
     * @return array<string, list<string>>
     */
    private function linkPaths(string $html): array
    {
        $document = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $document->loadHTML('<?xml encoding="utf-8"?>' . $html);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        $links = [];
        foreach ($document->getElementsByTagName('option') as $option) {
            $links['menu=' . $this->text($option->textContent)][] = $this->path($option->getAttribute('value'));
        }

        foreach ($document->getElementsByTagName('a') as $anchor) {
            $key = $anchor->getAttribute('title') !== ''
                ? 'menu=' . $anchor->getAttribute('title')
                : 'text=' . $this->text($anchor->textContent);
            $links[$key][] = $this->path($anchor->getAttribute('href'));
        }

        return $links;
    }

    private function path(string $url): string
    {
        return ltrim((string) parse_url($url, PHP_URL_PATH), '/');
    }

    private function text(string $text): string
    {
        return trim((string) preg_replace('/\s+/', ' ', $text));
    }

    private function renderHelpPage(): string
    {
        $backendUser = $GLOBALS['BE_USER'];
        self::assertInstanceOf(BackendUserAuthentication::class, $backendUser);
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences($backendUser);

        $route = $this->get(Router::class)->getRoute(OverviewController::HELP_ROUTE);
        self::assertNotNull($route);
        $module = $this->get(ModuleProvider::class)->getModule(OverviewController::OVERVIEW_ROUTE, $backendUser);
        self::assertInstanceOf(ModuleInterface::class, $module);

        // Same construction as SecretsControllerToggleAclTest: core marks
        // ServerRequest, the request-type constant and NormalizedParams
        // @internal and offers no public equivalent.
        /** @phpstan-ignore new.internalClass, method.internalClass */
        $request = new ServerRequest('https://localhost/typo3' . $route->getPath(), 'GET');
        $request = $this->withModuleContext($request, $route, $module);
        $GLOBALS['TYPO3_REQUEST'] = $request;

        // Collect every deprecation the action raises. Core 14.3 deprecates
        // Menu::makeMenuItem(), which the tab menu used; a regression back to
        // it keeps the page working and only adds a deprecation, so the
        // assertion has to look at the deprecations themselves.
        $deprecations = [];
        set_error_handler(
            static function (int $level, string $message) use (&$deprecations): bool {
                $deprecations[] = ($level === E_USER_DEPRECATED ? 'E_USER_DEPRECATED: ' : 'E_DEPRECATED: ') . $message;

                return true;
            },
            E_DEPRECATED | E_USER_DEPRECATED,
        );

        try {
            $response = $this->get(OverviewController::class)->helpAction($request);
        } finally {
            restore_error_handler();
        }

        self::assertSame([], $deprecations, 'Rendering the Help page raised deprecations');
        self::assertSame(200, $response->getStatusCode());

        return $response->getBody()->__toString();
    }
}
