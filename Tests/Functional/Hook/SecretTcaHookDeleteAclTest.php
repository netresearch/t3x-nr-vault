<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Hook;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Hook\SecretTcaHook;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Functional tests for the delete-command write-path authorization in
 * SecretTcaHook (F5, CWE-862).
 *
 * A DataHandler `delete` on tx_nrvault_secret must enforce the vault
 * canDelete ACL (owner / admin / system-maintainer only). A non-owner
 * non-admin editor with generic table-modify rights must NOT be able to
 * delete another user's secret.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookDeleteAclTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Admin backend user (uid 1 in the fixture). */
    private const ADMIN_UID = 1;

    /** Non-admin editor (uid 2 in the fixture), no operation permissions. */
    private const EDITOR_UID = 2;

    /** Non-admin user (uid 3) whose group grants tx_nrvault:secret.delete. */
    private const DELETER_UID = 3;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_acl.csv';

    /** Log in explicitly per test — different actors per scenario. */
    protected ?int $backendUserUid = null;

    #[Test]
    public function nonOwnerNonAdminDeleteIsBlocked(): void
    {
        $this->setUpBackendUser(self::EDITOR_UID);
        [$uid, $identifier] = $this->seedSecret(self::ADMIN_UID);

        // Drive the hook contract directly rather than DataHandler::process_cmdmap():
        // core's own table-permission check (checkModifyAccessList) would block a
        // group-less editor BEFORE the hook runs, masking the vault gate under test.
        // The direct call isolates the vault ACL, which is the finding.
        $commandIsProcessed = $this->runDeleteHook($uid);

        // The vault gate must cancel the delete (commandIsProcessed=true makes core
        // skip its deleteAction) AND record an access_denied audit entry — the
        // fingerprint that the HOOK, not core's table permissions, blocked it.
        self::assertTrue(
            $commandIsProcessed,
            'The vault gate must cancel a non-owner non-admin delete (commandIsProcessed=true).',
        );
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::AccessDenied->value, 0),
            'A failed access_denied audit entry must be recorded for the denied delete.',
        );
        self::assertSame(
            0,
            $this->countAudit($identifier, AuditAction::Delete->value, 1),
            'No successful delete audit entry may be written for a denied delete.',
        );
    }

    #[Test]
    public function ownerWithoutDeletePermissionIsBlocked(): void
    {
        // Separation of duties: owning the secret satisfies the per-secret
        // tier, but without the secret.delete operation permission the delete
        // must still be cancelled.
        $this->setUpBackendUser(self::EDITOR_UID);
        [$uid, $identifier] = $this->seedSecret(self::EDITOR_UID);

        $commandIsProcessed = $this->runDeleteHook($uid);

        self::assertTrue(
            $commandIsProcessed,
            'An owner without the secret.delete permission must be blocked (commandIsProcessed=true).',
        );
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::AccessDenied->value, 0),
            'A failed access_denied audit entry must be recorded for the denied delete.',
        );
        self::assertSame(
            0,
            $this->countAudit($identifier, AuditAction::Delete->value, 1),
            'No successful delete audit entry may be written for a denied delete.',
        );
    }

    #[Test]
    public function ownerWithDeletePermissionIsAllowedByVaultGate(): void
    {
        // Both gates hold: per-secret tier (owner) AND the secret.delete
        // operation permission via the group custom permission option.
        $this->setUpBackendUser(self::DELETER_UID);
        [$uid, $identifier] = $this->seedSecret(self::DELETER_UID);

        $commandIsProcessed = $this->runDeleteHook($uid);

        self::assertFalse(
            $commandIsProcessed,
            'An owner holding secret.delete must not be blocked by the vault delete gate.',
        );
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::Delete->value, 1),
            'The authorized delete must record a successful delete audit entry.',
        );
    }

    #[Test]
    public function adminDeleteIsAllowedByVaultGate(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);
        [$uid, $identifier] = $this->seedSecret(self::EDITOR_UID);

        $commandIsProcessed = $this->runDeleteHook($uid);

        self::assertFalse($commandIsProcessed, 'An admin must not be blocked by the vault delete gate.');
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::Delete->value, 1),
            'The authorized delete must record a successful delete audit entry.',
        );
    }

    /**
     * Drive the hook contract directly (preProcess decision + processCmdmap
     * cancellation) so the vault gate is isolated from core DataHandler's own
     * table-permission system — which would otherwise block a permission-less
     * non-admin owner and mask the result.
     */
    private function runDeleteHook(int $uid): bool
    {
        $hook = $this->get(SecretTcaHook::class);
        self::assertInstanceOf(SecretTcaHook::class, $hook);

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];

        $hook->processCmdmap_preProcess('delete', self::SECRET_TABLE, $uid, dataHandler: $dataHandler);

        $commandIsProcessed = false;
        $hook->processCmdmap('delete', self::SECRET_TABLE, $uid, '', $commandIsProcessed, $dataHandler, false);

        return $commandIsProcessed;
    }

    /**
     * @return array{0: int, 1: string} [secret uid, identifier]
     */
    private function seedSecret(int $ownerUid): array
    {
        $identifier = 'del_acl_' . bin2hex(random_bytes(4));
        $connection = $this->getConnectionPool()->getConnectionForTable(self::SECRET_TABLE);
        $connection->insert(self::SECRET_TABLE, [
            'pid' => 0,
            'identifier' => $identifier,
            'owner_uid' => $ownerUid,
            'frontend_accessible' => 0,
            'deleted' => 0,
        ]);

        return [(int) $connection->lastInsertId(), $identifier];
    }

    private function countAudit(string $identifier, string $action, int $success): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $count = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq('secret_identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action)),
                $queryBuilder->expr()->eq('success', $queryBuilder->createNamedParameter($success, Connection::PARAM_INT)),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }
}
