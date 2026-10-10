<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use GuzzleHttp\Psr7\ServerRequest;
use Netresearch\NrVault\Controller\AnalyticsController;
use Netresearch\NrVault\Controller\AuditController;
use Netresearch\NrVault\Controller\MigrationController;
use Netresearch\NrVault\Controller\OverviewController;
use Netresearch\NrVault\Controller\SecretsController;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionMethod;
use TYPO3\CMS\Backend\Routing\Route;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Http\NormalizedParams;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;

#[CoversClass(SecretsController::class)]
#[CoversClass(AuditController::class)]
#[CoversClass(AnalyticsController::class)]
#[CoversClass(MigrationController::class)]
#[CoversClass(OverviewController::class)]
final class ModulePermissionTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_toggle_acl.csv';

    protected ?int $backendUserUid = 5;

    /**
     * @return iterable<string, array{class-string, string}>
     */
    public static function deniedActions(): iterable
    {
        yield 'secret list' => [SecretsController::class, 'listAction'];
        yield 'secret create' => [SecretsController::class, 'createAction'];
        yield 'secret edit' => [SecretsController::class, 'editAction'];
        yield 'secret delete' => [SecretsController::class, 'deleteAction'];
        yield 'audit list' => [AuditController::class, 'listAction'];
        yield 'audit verify' => [AuditController::class, 'verifyChainAction'];
        yield 'audit export' => [AuditController::class, 'exportAction'];
        yield 'analytics' => [AnalyticsController::class, 'indexAction'];
        yield 'migration' => [MigrationController::class, 'handleRequest'];
        yield 'overview' => [OverviewController::class, 'indexAction'];
        yield 'help' => [OverviewController::class, 'helpAction'];
    }

    #[Test]
    #[DataProvider('deniedActions')]
    public function anAuthenticatedUserWithoutVaultPermissionsIsRefused(
        string $controllerClass,
        string $action,
    ): void {
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences(null);
        $controller = $this->get($controllerClass);
        $response = (new ReflectionMethod($controllerClass, $action))->invoke($controller, $this->moduleRequest());
        self::assertInstanceOf(ResponseInterface::class, $response);

        self::assertSame(403, $response->getStatusCode(), $controllerClass . '::' . $action);
        self::assertStringNotContainsString('type="password"', (string) $response->getBody());
    }

    #[Test]
    public function aNonAdminWithCreatePermissionCanReachTheCreationForm(): void
    {
        $this
            ->getConnectionPool()
            ->getConnectionForTable('be_groups')
            ->update('be_groups', ['custom_options' => 'tx_nrvault:secret.create'], ['uid' => 12]);
        $this->setUpBackendUser(3);
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences(null);

        $response = $this->get(SecretsController::class)->createAction($this->moduleRequest());

        self::assertSame(302, $response->getStatusCode());
        self::assertStringContainsString('record/edit', $response->getHeaderLine('Location'));
        self::assertStringContainsString('tx_nrvault_secret', urldecode($response->getHeaderLine('Location')));
    }

    private function moduleRequest(): ServerRequestInterface
    {
        $path = '/module/admin/vault';

        $request = new ServerRequest('POST', 'https://example.com' . $path);
        /** @phpstan-ignore classConstant.internal */
        $applicationType = SystemEnvironmentBuilder::REQUESTTYPE_BE;
        /** @phpstan-ignore staticMethod.internal */
        $normalizedParams = NormalizedParams::createFromRequest($request);

        return $request
            ->withAttribute('route', new Route($path, ['packageName' => 'netresearch/nr-vault']))
            ->withAttribute('applicationType', $applicationType)
            ->withAttribute('normalizedParams', $normalizedParams);
    }
}
