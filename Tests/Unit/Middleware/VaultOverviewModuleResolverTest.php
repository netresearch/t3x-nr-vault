<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Middleware;

use Netresearch\NrVault\Middleware\VaultOverviewModuleResolver;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Backend\Module\ModuleInterface;
use TYPO3\CMS\Backend\Routing\Route;

/**
 * The route rewrite that makes `/typo3/module/admin/vault` show the overview on
 * TYPO3 13 as well.
 *
 * What is pinned here is a decision, not a rendering: given the parent module's
 * route, does the middleware hand core the overview submodule or leave the
 * parent in place? Core's own `BackendModuleValidator` does the rest, and which
 * page comes out is covered by the Playwright overview specs on both majors.
 */
#[CoversClass(VaultOverviewModuleResolver::class)]
final class VaultOverviewModuleResolverTest extends TestCase
{
    #[Test]
    public function parentRouteResolvesToTheOverviewSubmoduleWhereCoreCannotShowIt(): void
    {
        $overview = $this->module('admin_vault_overview');
        $route = new Route('/module/admin/vault', [
            'module' => $this->vaultParentModule(false, $overview),
        ]);

        $this->process($route);

        self::assertSame(
            $overview,
            $route->getOption('module'),
            'On a core without submodule-overview support the parent route must resolve to the '
            . 'overview submodule, or the validator sends the user to the last-used one.',
        );
    }

    /**
     * TYPO3 14 honours `showSubmoduleOverview` itself. Rewriting there would
     * swap the module for no reason and change what the module menu highlights.
     */
    #[Test]
    public function parentRouteIsLeftAloneWhereCoreShowsTheOverviewItself(): void
    {
        $parent = $this->vaultParentModule(true, $this->module('admin_vault_overview'));
        $route = new Route('/module/admin/vault', ['module' => $parent]);

        $this->process($route);

        self::assertSame($parent, $route->getOption('module'));
    }

    #[Test]
    public function otherModulesAreLeftAlone(): void
    {
        $foreign = $this->module('web_list');
        $route = new Route('/module/web/list', ['module' => $foreign]);

        $this->process($route);

        self::assertSame($foreign, $route->getOption('module'));
    }

    /**
     * Defensive: if the overview submodule is not registered — or the user
     * cannot reach it, in which case core filters it out of the parent — the
     * middleware must not blank the route out. Core's own fallback is the
     * better answer there.
     */
    #[Test]
    public function routeIsUntouchedWhenTheOverviewSubmoduleIsAbsent(): void
    {
        $parent = $this->vaultParentModule(false, null);
        $route = new Route('/module/admin/vault', ['module' => $parent]);

        $this->process($route);

        self::assertSame($parent, $route->getOption('module'));
    }

    /**
     * Non-module backend requests (AJAX routes, the login form) carry no route
     * attribute at all.
     */
    #[Test]
    public function requestWithoutARouteIsPassedThrough(): void
    {
        $request = self::createStub(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturn(null);

        $expected = self::createStub(ResponseInterface::class);

        self::assertSame($expected, (new VaultOverviewModuleResolver())->process($request, $this->handler($expected)));
    }

    private function process(Route $route): void
    {
        $request = self::createStub(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturn($route);

        (new VaultOverviewModuleResolver())->process($request, $this->handler(self::createStub(ResponseInterface::class)));
    }

    private function handler(ResponseInterface $response): RequestHandlerInterface
    {
        $handler = self::createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        return $handler;
    }

    private function vaultParentModule(bool $hasSubmoduleOverview, ?ModuleInterface $overview): ModuleInterface
    {
        $module = self::createStub(ModuleInterface::class);
        $module->method('getIdentifier')->willReturn('admin_vault');
        $module->method('hasSubmoduleOverview')->willReturn($hasSubmoduleOverview);
        $module->method('getSubModule')->willReturn($overview);

        return $module;
    }

    private function module(string $identifier): ModuleInterface
    {
        $module = self::createStub(ModuleInterface::class);
        $module->method('getIdentifier')->willReturn($identifier);
        $module->method('hasSubmoduleOverview')->willReturn(false);
        $module->method('getSubModule')->willReturn(null);

        return $module;
    }
}
