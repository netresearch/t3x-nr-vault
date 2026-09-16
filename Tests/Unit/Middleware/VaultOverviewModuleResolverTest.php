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
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use TYPO3\CMS\Backend\Module\ModuleInterface;
use TYPO3\CMS\Backend\Routing\Route;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;

/**
 * The stored submodule selection that makes `/typo3/module/admin/vault` show
 * the overview on TYPO3 13 as well.
 *
 * What is pinned here is a decision, not a rendering: given the parent module's
 * route, does the middleware point the parent's remembered selection at the
 * overview submodule or leave it alone? Core's own `BackendModuleValidator`
 * reads that selection and resolves the module from it, and which page comes
 * out is covered by the Playwright overview specs on both majors.
 */
#[CoversClass(VaultOverviewModuleResolver::class)]
final class VaultOverviewModuleResolverTest extends TestCase
{
    private const PARENT_PATH = '/module/admin/vault';

    private ?BackendUserAuthentication $previousBackendUser = null;

    protected function setUp(): void
    {
        parent::setUp();

        $existing = $GLOBALS['BE_USER'] ?? null;
        $this->previousBackendUser = $existing instanceof BackendUserAuthentication ? $existing : null;
    }

    protected function tearDown(): void
    {
        if ($this->previousBackendUser instanceof BackendUserAuthentication) {
            $GLOBALS['BE_USER'] = $this->previousBackendUser;
        } else {
            unset($GLOBALS['BE_USER']);
        }

        parent::tearDown();
    }

    /**
     * The finding: without this, core resolves the parent to whichever
     * submodule the user opened last, and the documented overview is
     * unreachable.
     */
    #[Test]
    public function parentRouteSelectsTheOverviewSubmoduleWhereCoreCannotShowIt(): void
    {
        $backendUser = $this->backendUser(['action' => 'admin_vault_secrets']);
        $backendUser->expects($this->once())
            ->method('pushModuleData')
            ->with('admin_vault', ['action' => 'admin_vault_overview'], true);

        $this->process($this->parentRoute(false));
    }

    /**
     * A selection that already names the overview is left as it is — a write
     * per request would be noise, and the value is identical.
     */
    #[Test]
    public function anAlreadySelectedOverviewIsNotWrittenAgain(): void
    {
        $backendUser = $this->backendUser(['action' => 'admin_vault_overview']);
        $backendUser->expects($this->never())->method('pushModuleData');

        $this->process($this->parentRoute(false));
    }

    /**
     * TYPO3 14 honours `showSubmoduleOverview` itself, so touching the stored
     * selection there would change what the module menu highlights for nothing.
     *
     * The scenario cannot exist on TYPO3 13.4: `hasSubmoduleOverview()` is not
     * on ModuleInterface there, which is exactly what the production guard
     * asks. Skipped rather than asserted on that leg of the matrix.
     */
    #[Test]
    public function storedSelectionIsLeftAloneWhereCoreShowsTheOverviewItself(): void
    {
        if (!$this->coreKnowsSubmoduleOverview()) {
            self::markTestSkipped('TYPO3 13.4 has no ModuleInterface::hasSubmoduleOverview()');
        }

        $backendUser = $this->backendUser(['action' => 'admin_vault_secrets']);
        $backendUser->expects($this->never())->method('pushModuleData');

        $this->process($this->parentRoute(true));
    }

    #[Test]
    public function otherModulesAreLeftAlone(): void
    {
        $backendUser = $this->backendUser(['action' => 'web_info']);
        $backendUser->expects($this->never())->method('pushModuleData');

        $module = self::createStub(ModuleInterface::class);
        $module->method('getIdentifier')->willReturn('web_list');

        $this->process(new Route('/module/web/list', ['module' => $module]));
    }

    /**
     * Non-module backend requests (AJAX routes, the login form) carry no route
     * attribute at all.
     */
    #[Test]
    public function requestWithoutARouteIsPassedThrough(): void
    {
        $backendUser = $this->backendUser([]);
        $backendUser->expects($this->never())->method('pushModuleData');

        $request = self::createStub(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturn(null);

        $expected = self::createStub(ResponseInterface::class);

        self::assertSame(
            $expected,
            (new VaultOverviewModuleResolver())->process($request, $this->handler($expected)),
        );
    }

    /**
     * No backend user means nothing to steer — and must not be an error: the
     * middleware chain reaches this point before authentication has produced
     * one on some requests.
     */
    #[Test]
    public function requestWithoutABackendUserIsPassedThrough(): void
    {
        unset($GLOBALS['BE_USER']);

        $expected = self::createStub(ResponseInterface::class);
        $request = self::createStub(ServerRequestInterface::class);
        $request->method('getAttribute')->willReturn($this->parentRoute(false));

        self::assertSame(
            $expected,
            (new VaultOverviewModuleResolver())->process($request, $this->handler($expected)),
        );
    }

    #[Test]
    public function theParentModulesHelpRouteLeavesTheRememberedSubmoduleAlone(): void
    {
        $backendUser = $this->backendUser(['action' => 'admin_vault_secrets']);
        $backendUser->expects($this->never())->method('pushModuleData');

        // Every route of the module carries the same `module` option, so the
        // identifier alone would rewrite the remembered submodule when
        // somebody opens Help.
        $this->process($this->parentRoute(false, self::PARENT_PATH . '/help'));
    }

    private function coreKnowsSubmoduleOverview(): bool
    {
        return method_exists(ModuleInterface::class, 'hasSubmoduleOverview');
    }

    private function parentRoute(bool $hasSubmoduleOverview, string $path = self::PARENT_PATH): Route
    {
        $module = self::createStub(ModuleInterface::class);
        $module->method('getIdentifier')->willReturn('admin_vault');
        // Core registers the default route under the module's own path and
        // every further route beneath it, which is how the middleware tells
        // them apart — so the double has to answer this the same way.
        $module->method('getPath')->willReturn(self::PARENT_PATH);

        if ($this->coreKnowsSubmoduleOverview()) {
            $module->method('hasSubmoduleOverview')->willReturn($hasSubmoduleOverview);
        }

        return new Route($path, ['module' => $module]);
    }

    /**
     * @param array<string, mixed> $moduleData
     *
     * @return BackendUserAuthentication&MockObject
     */
    private function backendUser(array $moduleData): BackendUserAuthentication
    {
        $backendUser = $this->createMock(BackendUserAuthentication::class);
        $backendUser->method('getModuleData')->willReturn($moduleData);
        $GLOBALS['BE_USER'] = $backendUser;

        return $backendUser;
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
}
