<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Controller\SecretsController;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Backend\Routing\Route;
use TYPO3\CMS\Core\Core\SystemEnvironmentBuilder;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Http\NormalizedParams;
use TYPO3\CMS\Core\Http\ServerRequest;
use TYPO3\CMS\Core\Localization\LanguageService;
use TYPO3\CMS\Core\Localization\LanguageServiceFactory;

/**
 * Functional tests for the per-secret gate on
 * `SecretsController::toggleAction()`.
 *
 * Disabling a secret withdraws it from the backend listing, so the action
 * already required the `secret.manage_policy` operation permission. That
 * permission answers "may this actor manage policy at all" and says nothing
 * about WHICH secrets — so on its own it let any holder disable every
 * colleague's secret. The per-secret `canWrite()` tier is the missing half.
 *
 * The AJAX branch is exercised deliberately: it returns a plain JSON
 * response, so the assertions are about the authorization outcome and not
 * about backend template rendering.
 *
 * The browser branch renders the module 403 page, and there the two refusals
 * must not read alike: a missing operation permission names the permission,
 * while a per-secret refusal must not — the actor holds that permission, so
 * naming it would send them (and whoever picks up the ticket) after a grant
 * that is already in place.
 */
#[CoversClass(SecretsController::class)]
final class SecretsControllerToggleAclTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Holds secret.manage_policy but owns nothing. */
    private const POLICY_HOLDER_UID = 3;

    /** Holds secret.manage_policy and owns the seeded secret. */
    private const OWNER_UID = 4;

    /** Holds no vault permission at all. */
    private const OUTSIDER_UID = 5;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_toggle_acl.csv';

    /** Logged in per test — the scenarios need different actors. */
    protected ?int $backendUserUid = null;

    #[Test]
    public function aPolicyHolderCannotToggleASecretTheyHaveNoWriteAccessTo(): void
    {
        $this->setUpBackendUser(self::POLICY_HOLDER_UID);
        $identifier = $this->seedSecretOwnedBy(self::OWNER_UID);
        $this->setUpLanguageService();

        $response = $this->get(SecretsController::class)
            ->toggleAction($this->toggleRequest($identifier));

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(
            0,
            $this->currentHiddenState($identifier),
            'The secret must still be enabled — the toggle was refused.',
        );
        self::assertTrue(
            $this->hasAuditEntry($identifier, AuditAction::AccessDenied),
            'The refusal must be recorded as access_denied.',
        );
    }

    /**
     * The counterpart, so the gate is shown to refuse the right actor rather
     * than everyone: the owner holds the same permission and may toggle.
     */
    #[Test]
    public function theOwnerCanStillToggleTheirOwnSecret(): void
    {
        $this->setUpBackendUser(self::OWNER_UID);
        $identifier = $this->seedSecretOwnedBy(self::OWNER_UID);
        $this->setUpLanguageService();

        $response = $this->get(SecretsController::class)
            ->toggleAction($this->toggleRequest($identifier));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(
            1,
            $this->currentHiddenState($identifier),
            'The toggle by the owner must take effect.',
        );
    }

    /**
     * The per-secret refusal must not blame `secret.manage_policy`: this actor
     * holds it, and the page is read by the operator and by whoever diagnoses
     * the resulting ticket.
     */
    #[Test]
    public function theBrowserRefusalForOneSecretDoesNotNameAPermissionTheActorHolds(): void
    {
        $this->setUpBackendUser(self::POLICY_HOLDER_UID);
        $identifier = $this->seedSecretOwnedBy(self::OWNER_UID);
        $this->setUpLanguageService();

        $response = $this->get(SecretsController::class)
            ->toggleAction($this->browserToggleRequest($identifier));

        self::assertSame(403, $response->getStatusCode());

        $body = (string) $response->getBody();
        self::assertStringContainsString($this->label('accessDenied.secret.message'), $body);
        self::assertStringContainsString($this->label('accessDenied.secret.explanation'), $body);
        self::assertStringNotContainsString(
            VaultPermission::SecretManagePolicy->value,
            $body,
            'The page must not demand a permission the actor already holds.',
        );
        self::assertStringNotContainsString(
            $this->label('accessDenied.message'),
            $body,
            'The permission-level wording must not appear on a per-secret refusal.',
        );
    }

    /**
     * The counterpart on the same page: a refusal that IS about a missing
     * operation permission must still name it.
     */
    #[Test]
    public function theBrowserRefusalForAMissingPermissionStillNamesIt(): void
    {
        $this->setUpBackendUser(self::OUTSIDER_UID);
        $identifier = $this->seedSecretOwnedBy(self::OWNER_UID);
        $this->setUpLanguageService();

        $response = $this->get(SecretsController::class)
            ->toggleAction($this->browserToggleRequest($identifier));

        self::assertSame(403, $response->getStatusCode());

        $body = (string) $response->getBody();
        self::assertStringContainsString($this->label('accessDenied.message'), $body);
        self::assertStringContainsString(VaultPermission::SecretManagePolicy->value, $body);
        self::assertStringNotContainsString(
            $this->label('accessDenied.secret.message'),
            $body,
            'The per-secret wording must not appear when the permission itself is missing.',
        );
    }

    /**
     * `toggleAction()` resolves the language service for its flash messages
     * before it reaches any gate, and nothing in a bare functional bootstrap
     * populates $GLOBALS['LANG'].
     */
    private function setUpLanguageService(): void
    {
        $GLOBALS['LANG'] = $this->get(LanguageServiceFactory::class)->createFromUserPreferences(null);
    }

    /**
     * The `Accept: application/json` header selects `toggleAction()`'s AJAX
     * branch, which answers with a plain JSON response instead of rendering
     * the backend module template.
     */
    private function toggleRequest(string $identifier): ServerRequestInterface
    {
        /** @phpstan-ignore new.internalClass, method.internalClass */
        $request = new ServerRequest('https://example.com/module/admin/vault/secrets/toggle', 'POST');

        // Handed on as the PSR interface: core marks its own ServerRequest
        // @internal, but the withers being called are PSR-7 contract.
        return $this->withToggleBody($request, $identifier);
    }

    private function withToggleBody(ServerRequestInterface $request, string $identifier): ServerRequestInterface
    {
        return $request
            ->withHeader('Accept', 'application/json')
            ->withParsedBody(['identifier' => $identifier]);
    }

    /**
     * A plain form post — no JSON Accept header, so `toggleAction()` answers
     * with the rendered module page instead of JSON.
     */
    private function browserToggleRequest(string $identifier): ServerRequestInterface
    {
        $path = '/module/admin/vault/secrets/toggle';

        /** @phpstan-ignore new.internalClass, method.internalClass */
        $request = new ServerRequest('https://example.com' . $path, 'POST');

        return $this->withBackendModuleContext($request, $path)
            ->withParsedBody(['identifier' => $identifier]);
    }

    /**
     * Attach the three attributes a real backend request carries and a
     * synthetic one does not: `route` is what `BackendViewFactory` reads to
     * resolve the extension's template paths, while `applicationType` and
     * `normalizedParams` are what `PageRenderer` demands before it will
     * assemble a backend page.
     *
     * Core marks both of those values `@internal` and offers no public
     * equivalent, so the two accesses are ignored locally rather than grown
     * into the baseline.
     */
    private function withBackendModuleContext(
        ServerRequestInterface $request,
        string $path,
    ): ServerRequestInterface {
        /** @phpstan-ignore classConstant.internal */
        $applicationType = SystemEnvironmentBuilder::REQUESTTYPE_BE;

        /** @phpstan-ignore staticMethod.internal */
        $normalizedParams = NormalizedParams::createFromRequest($request);

        return $request
            ->withAttribute('route', new Route($path, ['packageName' => 'netresearch/nr-vault']))
            ->withAttribute('applicationType', $applicationType)
            ->withAttribute('normalizedParams', $normalizedParams);
    }

    /**
     * Resolve a module label, so the assertions pin the rendered LABEL rather
     * than a copy of its English source drifting apart from the XLF.
     */
    private function label(string $key): string
    {
        return $this->getLanguageService()
            ->sL('LLL:EXT:nr_vault/Resources/Private/Language/locallang_mod.xlf:' . $key);
    }

    private function getLanguageService(): LanguageService
    {
        self::assertInstanceOf(LanguageService::class, $GLOBALS['LANG']);

        return $GLOBALS['LANG'];
    }

    private function seedSecretOwnedBy(int $ownerUid): string
    {
        $identifier = 'toggle_secret_' . bin2hex(random_bytes(4));

        $this->getConnectionPool()
            ->getConnectionForTable(self::SECRET_TABLE)
            ->insert(self::SECRET_TABLE, [
                'pid' => 0,
                'identifier' => $identifier,
                'owner_uid' => $ownerUid,
                'hidden' => 0,
            ]);

        return $identifier;
    }

    private function currentHiddenState(string $identifier): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        return (int) $queryBuilder
            ->select('hidden')
            ->from(self::SECRET_TABLE)
            ->where(
                $queryBuilder->expr()->eq(
                    'identifier',
                    $queryBuilder->createNamedParameter($identifier),
                ),
            )
            ->executeQuery()
            ->fetchOne();
    }

    private function hasAuditEntry(string $identifier, AuditAction $action): bool
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        $count = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq(
                    'secret_identifier',
                    $queryBuilder->createNamedParameter($identifier),
                ),
                $queryBuilder->expr()->eq(
                    'action',
                    $queryBuilder->createNamedParameter($action->value),
                ),
                $queryBuilder->expr()->eq(
                    'success',
                    $queryBuilder->createNamedParameter(0, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        return (int) $count > 0;
    }
}
