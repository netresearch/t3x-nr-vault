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
 * Functional tests for SecretTcaHook against a DISABLED secret
 * (`hidden = 1`, TCA's `disabled` enable column).
 *
 * The hook resolved its DataHandler target through the restriction-honouring
 * lookup, which drops such a record. A guard that cannot see its subject does
 * not refuse the operation — it returns early and hands the record back to
 * core, which then carried out the delete with no per-secret ACL, no
 * `secret.delete` permission and no audit entry. Disabling a secret must not
 * be the way to strip it of its guard, so both gates now resolve through the
 * disabled-visible lookup.
 *
 * ## Why these tests drive the real DataHandler
 *
 * The sibling suites call the hook methods directly to isolate the vault ACL
 * from core's table permissions. That is exactly wrong here: the finding is
 * that the hook DOES NOTHING, and a direct call cannot show what core does
 * next. The actors therefore hold real table-modify and page rights, so
 * `process_cmdmap()` reaches core's own `deleteAction()` whenever the hook
 * declines the command — which is what makes the unguarded delete visible.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookDisabledSecretTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Page the secrets live on; both actors may edit and delete here. */
    private const PAGE_UID = 1;

    /**
     * Non-admin editor with table-modify rights and nothing else: not the
     * owner, in neither tier, holding no operation permission.
     */
    private const EDITOR_UID = 2;

    /** Non-admin whose group grants tx_nrvault:secret.delete. */
    private const DELETER_UID = 3;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_disabled_secret.csv';

    /** Logged in per test — the scenarios need different actors. */
    protected ?int $backendUserUid = null;

    /**
     * The finding itself: before the fix core soft-deleted the row unasked,
     * without the per-secret ACL and without an audit entry.
     */
    #[Test]
    public function anUnauthorizedDeleteOfADisabledSecretDoesNotLand(): void
    {
        $this->setUpBackendUser(self::EDITOR_UID);
        [$uid, $identifier] = $this->seedDisabledSecret(self::DELETER_UID);

        $this->submitDeleteCommand($uid);

        self::assertSame(
            0,
            $this->readDeletedFlag($uid),
            'A disabled secret must not be deleted by an actor the vault never authorized.',
        );
        self::assertSame(
            0,
            $this->countAudit($identifier, AuditAction::Delete->value, 1),
            'No successful delete audit entry may exist for a delete that was never authorized.',
        );
    }

    /**
     * The atomicity the finding broke, asserted as the equivalence it is: a
     * disabled secret is soft-deleted if and only if the vault audited the
     * delete. Both sides false is the branch's current outcome — the vault
     * service still resolves its own target through the restricted lookup, so
     * the delete fails closed and the record survives. Both sides true is the
     * outcome once that lookup is widened as well. What must never occur, and
     * what happened before this fix, is a deleted row with no audit entry.
     */
    #[Test]
    public function aDisabledSecretIsNeverDeletedWithoutBeingAudited(): void
    {
        $this->setUpBackendUser(self::DELETER_UID);
        [$uid, $identifier] = $this->seedDisabledSecret(self::DELETER_UID);

        $this->submitDeleteCommand($uid);

        self::assertSame(
            $this->countAudit($identifier, AuditAction::Delete->value, 1) === 1,
            $this->readDeletedFlag($uid) === 1,
            'Deleting a disabled secret and auditing that delete are all-or-nothing.',
        );
    }

    /**
     * `undelete` is refused unconditionally on this table, and being disabled
     * must not change that: the refusal reads its target through the
     * deleted-visible read, so the record it names is found either way.
     */
    #[Test]
    public function undeleteOfADisabledSecretIsStillRefused(): void
    {
        $this->setUpBackendUser(self::DELETER_UID);
        [$uid, $identifier] = $this->seedDisabledSecret(self::DELETER_UID, deleted: true);

        $hook = $this->get(SecretTcaHook::class);
        self::assertInstanceOf(SecretTcaHook::class, $hook);

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];

        $hook->processCmdmap_preProcess('undelete', self::SECRET_TABLE, $uid, dataHandler: $dataHandler);

        $commandIsProcessed = false;
        $hook->processCmdmap('undelete', self::SECRET_TABLE, $uid, '', $commandIsProcessed, $dataHandler, false);

        self::assertTrue($commandIsProcessed, 'core must skip its own undelete branch');
        self::assertSame(1, $this->readDeletedFlag($uid), 'The refused undelete must leave the record deleted.');
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::AccessDenied->value, 0),
            'The refusal must be recorded under the identifier it is about.',
        );
    }

    /**
     * The milder second site: the per-secret write tier is asserted on every
     * FormEngine edit, and it too resolved its subject through the restricted
     * lookup — so a non-owner could rewrite a disabled secret's columns
     * without canWrite() ever being consulted.
     */
    #[Test]
    public function aNonOwnerCannotEditADisabledSecret(): void
    {
        $this->setUpBackendUser(self::EDITOR_UID);
        [$uid, $identifier] = $this->seedDisabledSecret(self::DELETER_UID);

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];
        $dataHandler->start(
            [self::SECRET_TABLE => [$uid => ['description' => 'rewritten by someone else']]],
            [],
        );
        $dataHandler->process_datamap();

        self::assertSame(
            'seeded description',
            $this->readDescription($uid),
            'A disabled secret must keep its description against an actor without write access.',
        );
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::AccessDenied->value, 0),
            'The refused edit must be recorded as access_denied.',
        );
    }

    /**
     * Run the delete as FormEngine would, through the whole DataHandler —
     * core's own permission checks included, so that a hook which declines
     * the command really does leave core to perform it.
     */
    private function submitDeleteCommand(int $uid): void
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];
        $dataHandler->start([], [self::SECRET_TABLE => [$uid => ['delete' => 1]]]);
        $dataHandler->process_cmdmap();
    }

    /**
     * @return array{int, string} The new secret UID and its identifier
     */
    private function seedDisabledSecret(int $ownerUid, bool $deleted = false): array
    {
        $identifier = 'disabled_' . bin2hex(random_bytes(4));
        $connection = $this->getConnectionPool()->getConnectionForTable(self::SECRET_TABLE);
        $connection->insert(self::SECRET_TABLE, [
            'pid' => self::PAGE_UID,
            'identifier' => $identifier,
            'description' => 'seeded description',
            'owner_uid' => $ownerUid,
            'frontend_accessible' => 0,
            'hidden' => 1,
            'deleted' => $deleted ? 1 : 0,
        ]);

        return [(int) $connection->lastInsertId(), $identifier];
    }

    private function readDeletedFlag(int $uid): int
    {
        $deleted = $this->readColumn($uid, 'deleted');

        return is_numeric($deleted) ? (int) $deleted : -1;
    }

    private function readDescription(int $uid): string
    {
        $description = $this->readColumn($uid, 'description');

        return \is_string($description) ? $description : '';
    }

    private function readColumn(int $uid, string $column): mixed
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();

        return $queryBuilder
            ->select($column)
            ->from(self::SECRET_TABLE)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();
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
