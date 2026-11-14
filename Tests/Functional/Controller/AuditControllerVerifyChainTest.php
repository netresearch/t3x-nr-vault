<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingItem;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchorServiceInterface;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Controller\AuditController;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use Netresearch\NrVault\Tests\Functional\Traits\AuditSinkSandboxTrait;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Module\ModuleData;
use TYPO3\CMS\Backend\Module\ModuleInterface;
use TYPO3\CMS\Backend\Module\ModuleProvider;
use TYPO3\CMS\Backend\Routing\Router;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Http\NormalizedParams;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;

/**
 * The backend "Verify chain" view runs the same full verification as
 * `vault:audit-verify` and reports its reason codes; the acknowledge route is
 * POST-only, administrator-only and append-only.
 *
 * `CoversNothing` for the same reason as {@see OverviewControllerTest}: the
 * controller is excluded from unit coverage and exercised here and in E2E.
 */
#[CoversNothing]
final class AuditControllerVerifyChainTest extends AbstractVaultFunctionalTestCase
{
    use AuditSinkSandboxTrait;

    protected ?string $backendUserFixture = __DIR__ . '/../Command/Fixtures/be_users_audit_permission.csv';

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'masterKeyProvider' => 'file',
        'auditHmacEpoch'    => 3,
    ];

    private int $actingUid = 1;

    protected function setUp(): void
    {
        $this->extensionConfiguration = $this->prepareAuditSinkSandbox($this->extensionConfiguration);

        parent::setUp();
    }

    protected function tearDown(): void
    {
        $this->cleanUpAuditSinkSandbox();

        parent::tearDown();
    }

    /**
     * Fails without the change: the old view only ran `verifyHashChain()` and
     * printed bare error strings, so it never showed a reason code, a verified
     * range or the anchor comparison.
     */
    #[Test]
    public function theViewReportsUidGapAndTableResetWithTheirCodes(): void
    {
        $auditService  = $this->get(AuditLogServiceInterface::class);
        $anchorService = $this->get(ChainTipAnchorServiceInterface::class);

        for ($i = 0; $i < 6; ++$i) {
            $auditService->log('view-' . $i, 'read', true, null, 'view test');
        }

        $anchorService->publish($anchorService->capture());
        $this->truncateAuditTable();
        $this->getConnectionPool()->getConnectionForTable('sys_registry')
            ->delete('sys_registry', ['entry_namespace' => 'tx_nrvault_audit_anchor']);
        for ($i = 0; $i < 6; ++$i) {
            $auditService->log('rebuilt-' . $i, 'read', true, null, 'rebuilt');
        }

        $this->getConnectionPool()->getConnectionForTable(AuditLogService::TABLE_NAME)->delete(AuditLogService::TABLE_NAME, ['uid' => 3]);

        $html = $this->body($this->get(AuditController::class)->verifyChainAction($this->request('verifyChain')));

        self::assertStringContainsString('UID_GAP', $html);
        self::assertStringContainsString('TABLE_RESET', $html);
        // The verified range and the anchor comparison are shown.
        self::assertStringContainsString('#1 &ndash; #6', $html);
        self::assertStringContainsString('Mismatch: the chain is not the chain that was anchored', $html);
        // The forensic guidance block stays.
        self::assertStringContainsString('What to do now', $html);
        // An administrator can acknowledge; the form posts to the acknowledge route.
        self::assertStringContainsString('name="fingerprint"', $html);
        self::assertStringContainsString('acknowledgeFindings', $html);
    }

    #[Test]
    public function aCleanChainShowsNoFindingsAndNoAcknowledgeForm(): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        for ($i = 0; $i < 4; ++$i) {
            $auditService->log('clean-' . $i, 'read', true, null, 'clean');
        }

        $html = $this->body($this->get(AuditController::class)->verifyChainAction($this->request('verifyChain')));

        self::assertStringContainsString('Hash chain is valid', $html);
        self::assertStringNotContainsString('name="fingerprint"', $html);
        self::assertStringContainsString('#1 &ndash; #4', $html);
    }

    #[Test]
    public function acknowledgingOverThePostRouteTurnsTheViewGreenAndKeepsTheIncidentVisible(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $controller = $this->get(AuditController::class);

        $view = $this->body($controller->verifyChainAction($this->request('verifyChain')));
        preg_match('/name="fingerprint" value="([0-9a-f]{64})"/', $view, $match);
        self::assertArrayHasKey(1, $match, 'the page carries the fingerprint of the open findings');
        $fingerprint = $match[1];

        $response = $controller->acknowledgeFindingsAction(
            $this->request('acknowledgeFindings', 'POST')->withParsedBody([
                'fingerprint' => $fingerprint,
                'reason'      => 'restored from the 2026-11-12 backup',
                'ticket'      => 'OPS-1',
                'confirm'     => '1',
            ]),
        );

        self::assertSame(303, $response->getStatusCode());
        self::assertStringContainsString('ackResult=acknowledged', $response->getHeaderLine('Location'));

        $after = $this->body($controller->verifyChainAction($this->request('verifyChain')->withQueryParams(['ackResult' => 'acknowledged'])));
        self::assertStringContainsString('Hash chain is valid', $after);
        self::assertStringContainsString('Acknowledged findings', $after);
        self::assertStringContainsString('HASH_MISMATCH', $after);
        self::assertSame(1, $this->acknowledgementRowCount());
    }

    #[Test]
    public function aGetRequestToTheAcknowledgeRouteIsRefusedAndWritesNothing(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);

        $response = $this->get(AuditController::class)->acknowledgeFindingsAction($this->request('acknowledgeFindings', 'GET'));

        self::assertSame(405, $response->getStatusCode());
        self::assertSame('POST', $response->getHeaderLine('Allow'));
        self::assertSame(0, $this->acknowledgementRowCount());
    }

    #[Test]
    public function aPostWithoutTheConfirmationWritesNothing(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $fingerprint = AuditFindingItem::fingerprint(
            $this->get(ChainTipAnchorServiceInterface::class)->inspect()->getOpenItems(),
        );

        $response = $this->get(AuditController::class)->acknowledgeFindingsAction(
            $this->request('acknowledgeFindings', 'POST')->withParsedBody(['fingerprint' => $fingerprint, 'reason' => 'no tick']),
        );

        self::assertStringContainsString('ackResult=reason_invalid', $response->getHeaderLine('Location'));
        self::assertSame(0, $this->acknowledgementRowCount());
    }

    #[Test]
    public function aNonAdministratorCannotAcknowledge(): void
    {
        $this->writeEntries(8);
        $this->tamperRow(5);
        $fingerprint = AuditFindingItem::fingerprint(
            $this->get(ChainTipAnchorServiceInterface::class)->inspect()->getOpenItems(),
        );

        $this->actAs(3);
        $response = $this->get(AuditController::class)->acknowledgeFindingsAction(
            $this->request('acknowledgeFindings', 'POST')->withParsedBody(['fingerprint' => $fingerprint, 'reason' => 'x', 'confirm' => '1']),
        );

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(0, $this->acknowledgementRowCount());
    }

    #[Test]
    public function theEvidenceExportNeedsTheExportPermissionAndCarriesTheRowsAroundTheFinding(): void
    {
        $this->writeEntries(20);
        $this->tamperRow(10);

        $this->actAs(3);
        self::assertSame(403, $this->get(AuditController::class)->evidenceAction($this->request('evidence'))->getStatusCode());

        $this->actAs(1);
        $response = $this->get(AuditController::class)->evidenceAction($this->request('evidence'));

        self::assertSame(200, $response->getStatusCode());
        $evidence = json_decode($this->body($response), true);
        self::assertIsArray($evidence);
        self::assertIsArray($evidence['rows']);
        self::assertIsArray($evidence['report']);
        $uids = array_map(static fn (mixed $row): int => is_array($row) && is_numeric($row['uid'] ?? null) ? (int) $row['uid'] : 0, $evidence['rows']);
        self::assertSame(range(5, 15), $uids);
        self::assertSame(['HASH_MISMATCH'], $evidence['report']['reasonCodes'] ?? null);
    }

    private function actAs(int $uid): void
    {
        $this->actingUid = $uid;
        $this->setUpBackendUser($uid);
    }

    private function writeEntries(int $count): void
    {
        $auditService = $this->get(AuditLogServiceInterface::class);
        for ($i = 0; $i < $count; ++$i) {
            $auditService->log('ctl-' . $i, 'read', true, null, 'controller test');
        }
    }

    private function tamperRow(int $uid): void
    {
        $this->getConnectionPool()->getConnectionForTable(AuditLogService::TABLE_NAME)
            ->update(AuditLogService::TABLE_NAME, ['reason' => 'edited after the fact'], ['uid' => $uid]);
    }

    private function acknowledgementRowCount(): int
    {
        return (int) $this->getConnectionPool()->getConnectionForTable(AuditLogService::TABLE_NAME)->createQueryBuilder()
            ->count('uid')->from(AuditLogService::TABLE_NAME)
            ->where('action = :a')->setParameter('a', AuditAction::AuditFindingsAcknowledged->value)
            ->executeQuery()->fetchOne();
    }

    private function truncateAuditTable(): void
    {
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(AuditLogService::TABLE_NAME);
        $connection->executeStatement('DELETE FROM ' . AuditLogService::TABLE_NAME);
        $connection->executeStatement("DELETE FROM sqlite_sequence WHERE name = '" . AuditLogService::TABLE_NAME . "'");
    }

    private function body(ResponseInterface $response): string
    {
        self::assertContains($response->getStatusCode(), [200, 303], 'unexpected status');

        return $response->getBody()->__toString();
    }

    private function request(string $routeSuffix, string $method = 'GET'): ServerRequestInterface
    {
        $backendUser = $GLOBALS['BE_USER'];
        self::assertInstanceOf(BackendUserAuthentication::class, $backendUser);
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences($backendUser);

        $route = $this->get(Router::class)->getRoute('admin_vault_audit.' . $routeSuffix);
        self::assertNotNull($route);
        $module = $this->get(ModuleProvider::class)->getModule('admin_vault_audit', $backendUser);
        if ($module === null) {
            // The module is only resolvable for a user with module access. The
            // refusal pages of the non-administrator cases still render inside
            // it, so resolve it through the administrator and switch back.
            $this->setUpBackendUser(1);
            $module = $this->get(ModuleProvider::class)->getModule('admin_vault_audit', $GLOBALS['BE_USER']);
            $this->setUpBackendUser($this->actingUid);
            $backendUser = $GLOBALS['BE_USER'];
            self::assertInstanceOf(BackendUserAuthentication::class, $backendUser);
            $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences($backendUser);
        }

        self::assertInstanceOf(ModuleInterface::class, $module);

        /** @phpstan-ignore new.internalClass, method.internalClass */
        $request    = new ServerRequest('https://localhost/typo3' . $route->getPath(), $method);
        $attributes = [
            /** @phpstan-ignore classConstant.internal */
            'applicationType' => SystemEnvironmentBuilder::REQUESTTYPE_BE,
            'route'           => $route,
            'module'          => $module,
            'moduleData'      => ModuleData::createFromModule($module, []),
        ];
        foreach ($attributes as $name => $value) {
            /** @phpstan-ignore method.internalClass */
            $request = $request->withAttribute($name, $value);
        }

        /** @phpstan-ignore staticMethod.internal, method.internalClass */
        $request = $request->withAttribute('normalizedParams', NormalizedParams::createFromRequest($request));

        return $GLOBALS['TYPO3_REQUEST'] = $request;
    }
}
