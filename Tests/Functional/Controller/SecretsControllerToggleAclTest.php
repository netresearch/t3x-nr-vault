<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Controller;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Controller\SecretsController;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Http\ServerRequest;
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
