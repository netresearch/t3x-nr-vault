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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Functional tests for the cmdmap commands SecretTcaHook refuses outright on
 * tx_nrvault_secret.
 *
 * The sharpest of the three is `undelete`: core's undeleteRecord() applies
 * checkModifyAccessList() and checkRecordEditAccess(), and skips its
 * page-permission branch entirely for a record at pid 0 — which every vault
 * secret is. Because a vault delete is a SOFT delete, the ciphertext, the
 * wrapped DEK, `frontend_accessible` and both MM ACL tiers survive it, so the
 * restore handed the secret back intact after zero vault checks. `copy` and
 * `move` are refused for the reasons given in SecretTcaHook::REFUSED_COMMANDS.
 *
 * The refusal is a PRODUCT rule, not a permission tier: an admin gets the same
 * answer as an editor, because "a vault delete cannot be undone" must not mean
 * "unless an administrator says otherwise".
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookCommandRefusalTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    /** Admin backend user (uid 1 in the fixture). */
    private const ADMIN_UID = 1;

    /** Non-admin editor (uid 2 in the fixture), no operation permissions. */
    private const EDITOR_UID = 2;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_acl.csv';

    /** Log in explicitly per test — different actors per scenario. */
    protected ?int $backendUserUid = null;

    /**
     * @return iterable<string, array{0: int}>
     */
    public static function actorProvider(): iterable
    {
        yield 'non-admin editor' => [self::EDITOR_UID];
        yield 'administrator' => [self::ADMIN_UID];
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function refusedCommandProvider(): iterable
    {
        yield 'undelete' => ['undelete'];
        yield 'copy' => ['copy'];
        yield 'move' => ['move'];
    }

    #[Test]
    #[DataProvider('actorProvider')]
    public function undeleteLeavesTheSecretDeletedAndRecordsTheRefusal(int $actorUid): void
    {
        $this->setUpBackendUser($actorUid);
        [$uid, $identifier] = $this->seedSecret(self::ADMIN_UID, deleted: true);

        $messages = [];
        $commandIsProcessed = $this->runCommandHook('undelete', $uid, $messages);

        self::assertTrue(
            $commandIsProcessed,
            'The refusal must cancel the command so core skips its own undeleteRecord().',
        );
        self::assertSame(1, $this->readDeletedFlag($uid), 'The secret must stay soft-deleted.');
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::AccessDenied->value, 0),
            'The refused restore must be recorded in the tamper-evident chain.',
        );
        // DataHandler prefixes every errorLog entry with "[<type>.<action>]: ",
        // so the reason is asserted as the tail rather than the whole entry.
        self::assertCount(1, $messages, 'The backend user must be told why the restore did nothing.');
        self::assertStringEndsWith(
            'A deleted vault secret cannot be restored: the vault has no restore operation, '
            . 'and its delete is documented as not reversible.',
            $messages[0],
        );
    }

    /**
     * The refusal must not depend on the row being readable through the
     * ordinary (soft-delete-filtering) path, which is exactly the state an
     * undelete target is in.
     */
    #[Test]
    #[DataProvider('refusedCommandProvider')]
    public function everyRefusedCommandIsCancelledAndAudited(string $command): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);
        [$uid, $identifier] = $this->seedSecret(self::ADMIN_UID, deleted: $command === 'undelete');

        $messages = [];
        $commandIsProcessed = $this->runCommandHook($command, $uid, $messages);

        self::assertTrue($commandIsProcessed, $command . ' must be cancelled');
        self::assertCount(1, $messages, $command . ' must explain itself once');
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::AccessDenied->value, 0),
            'The refused ' . $command . ' must be recorded in the tamper-evident chain.',
        );
    }

    /**
     * The whole chain, not the hook contract in isolation: a real
     * DataHandler::process_cmdmap() run as an ADMIN, who clears every core
     * check undeleteRecord() applies (checkModifyAccessList,
     * checkRecordEditAccess) and for whom the page-permission branch is
     * skipped anyway because the record sits at pid 0. Without the refusal
     * this restores the secret; with it, the row stays deleted.
     */
    #[Test]
    public function processCmdmapDoesNotRestoreADeletedSecret(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);
        [$uid, $identifier] = $this->seedSecret(self::ADMIN_UID, deleted: true);

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start([], [self::SECRET_TABLE => [$uid => ['undelete' => 1]]], $GLOBALS['BE_USER']);
        $dataHandler->process_cmdmap();

        self::assertSame(1, $this->readDeletedFlag($uid), 'The secret must not be restored.');
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::AccessDenied->value, 0),
            'The refused restore must be recorded in the tamper-evident chain.',
        );
    }

    /**
     * The commands core already refuses for this table (no languageField, no
     * versioningWS) are deliberately NOT intercepted — blocking them would
     * add a gate with nothing behind it and hide that fact from the next
     * reader.
     */
    #[Test]
    public function aCommandCoreAlreadyRefusesIsLeftToCore(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);
        [$uid, $identifier] = $this->seedSecret(self::ADMIN_UID);

        $messages = [];
        $commandIsProcessed = $this->runCommandHook('localize', $uid, $messages);

        self::assertFalse($commandIsProcessed, 'localize must be left to core');
        self::assertSame([], $messages);
        self::assertSame(0, $this->countAudit($identifier, AuditAction::AccessDenied->value, 0));
    }

    /**
     * The refusal must not have cost the one command this table does support:
     * an authorized delete still runs through VaultService and soft-deletes
     * the record.
     */
    #[Test]
    public function theDeletePathIsUnchanged(): void
    {
        $this->setUpBackendUser(self::ADMIN_UID);
        [$uid, $identifier] = $this->seedSecret(self::EDITOR_UID);

        $messages = [];
        $commandIsProcessed = $this->runCommandHook('delete', $uid, $messages);

        self::assertTrue($commandIsProcessed, 'The service-performed delete must cancel core deleteAction.');
        self::assertSame(1, $this->readDeletedFlag($uid), 'The record must be soft-deleted by the service.');
        self::assertSame(
            1,
            $this->countAudit($identifier, AuditAction::Delete->value, 1),
            'The authorized delete must record a successful delete audit entry.',
        );
        self::assertSame([], $messages, 'A successful delete has nothing to report to the editor.');
    }

    /**
     * Drive the hook contract directly (preProcess decision + processCmdmap
     * cancellation) so the vault gate is isolated from core DataHandler's own
     * table-permission system — which would otherwise block a permission-less
     * non-admin and mask the result.
     *
     * @param list<string> $messages Collected DataHandler error details
     */
    private function runCommandHook(string $command, int $uid, array &$messages): bool
    {
        $hook = $this->get(SecretTcaHook::class);
        self::assertInstanceOf(SecretTcaHook::class, $hook);

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];

        $hook->processCmdmap_preProcess($command, self::SECRET_TABLE, $uid, null, $dataHandler);

        $commandIsProcessed = false;
        $hook->processCmdmap($command, self::SECRET_TABLE, $uid, '', $commandIsProcessed, $dataHandler, false);

        // $errorLog is core-internal, but it is the only place a
        // DataHandler::log() call the hook made is observable — and what the
        // editor is told is exactly what this test is about.
        /** @phpstan-ignore property.internal */
        $errorLog = $dataHandler->errorLog;

        // Explicit narrowing rather than a cast: the v13 stubs type errorLog
        // as a plain array, so its entries are mixed on that matrix leg only.
        foreach ($errorLog as $entry) {
            if (\is_scalar($entry)) {
                $messages[] = (string) $entry;
            }
        }

        return $commandIsProcessed;
    }

    /**
     * @return array{0: int, 1: string} [secret uid, identifier]
     */
    private function seedSecret(int $ownerUid, bool $deleted = false): array
    {
        $identifier = 'cmd_refusal_' . bin2hex(random_bytes(4));
        $connection = $this->getConnectionPool()->getConnectionForTable(self::SECRET_TABLE);
        $connection->insert(self::SECRET_TABLE, [
            'pid' => 0,
            'identifier' => $identifier,
            'owner_uid' => $ownerUid,
            'frontend_accessible' => 0,
            'deleted' => $deleted ? 1 : 0,
        ]);

        return [(int) $connection->lastInsertId(), $identifier];
    }

    private function readDeletedFlag(int $uid): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $deleted = $queryBuilder
            ->select('deleted')
            ->from(self::SECRET_TABLE)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return is_numeric($deleted) ? (int) $deleted : -1;
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
