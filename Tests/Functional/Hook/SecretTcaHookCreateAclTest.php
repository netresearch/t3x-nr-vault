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
 * The review's acceptance scenario for the FormEngine create path: a backend
 * user holding generic TABLE permissions on tx_nrvault_secret but NOT the
 * secret.create operation permission must not be able to store a secret value
 * through a direct DataHandler request — the secrets-module controller check
 * is UX, the enforcement lives in VaultService::store() behind the hook.
 *
 * A refusal must leave nothing behind either. The denied create used to keep
 * its row (squatting the identifier under the denied user as owner, which
 * makes every later legitimate non-admin create of that identifier fail
 * canWrite) and to be audited as a SUCCESSFUL creation, because the hook
 * classified the outcome by "no value was stored" — which a deliberately
 * value-less create produces as well.
 *
 * The hook contract is driven directly (like SecretTcaHookDeleteAclTest):
 * core's own table-permission system would block the group-less editor before
 * the vault gate runs and mask the result under test.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookCreateAclTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    private const READ_MM_TABLE = 'tx_nrvault_secret_begroups_mm';

    private const WRITE_MM_TABLE = 'tx_nrvault_secret_writegroups_mm';

    /** Non-admin editor (uid 2), no vault operation permissions. */
    private const EDITOR_UID = 2;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_acl.csv';

    protected ?int $backendUserUid = self::EDITOR_UID;

    #[Test]
    public function editorWithoutSecretCreatePermissionCannotStoreViaDataHandler(): void
    {
        $identifier = 'op_create_' . bin2hex(random_bytes(4));

        $hook = $this->get(SecretTcaHook::class);
        self::assertInstanceOf(SecretTcaHook::class, $hook);

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];

        // Simulate the FormEngine create: preProcess captures the pending
        // secret value, core writes the row, afterDatabaseOperations hands
        // the value to VaultService::store() — which must deny.
        $fieldArray = [
            'pid' => 0,
            'identifier' => $identifier,
            'secret_input' => 'must-not-be-stored',
        ];
        $hook->processDatamap_preProcessFieldArray($fieldArray, self::SECRET_TABLE, 'NEW1', $dataHandler);

        $connection = $this->getConnectionPool()->getConnectionForTable(self::SECRET_TABLE);
        $connection->insert(self::SECRET_TABLE, [
            'pid' => 0,
            'identifier' => $identifier,
            'owner_uid' => self::EDITOR_UID,
            'deleted' => 0,
        ]);
        $newUid = (int) $connection->lastInsertId();

        $dataHandler->substNEWwithIDs['NEW1'] = $newUid;
        $hook->processDatamap_afterDatabaseOperations('new', self::SECRET_TABLE, 'NEW1', $fieldArray, $dataHandler);

        // DataHandler defers a new record's MM writes until every
        // afterDatabaseOperations() hook has run — stand in for that flush,
        // so the deferred purge has something to clean up.
        $this->insertMmRow(self::READ_MM_TABLE, $newUid, 10);
        $this->insertMmRow(self::WRITE_MM_TABLE, $newUid, 20);

        $hook->processDatamap_afterAllOperations($dataHandler);

        // Nothing was created, so no row may survive: it would hold no secret
        // and squat the identifier under the denied user as owner.
        $row = $connection->select(
            ['uid'],
            self::SECRET_TABLE,
            ['uid' => $newUid],
        )->fetchAssociative();
        self::assertFalse($row, 'The denied create must not leave a record behind.');

        // ... nor its ACL relations, which DataHandler writes after the row
        // has already been removed.
        self::assertSame(
            [],
            $this->loadMmGroups(self::READ_MM_TABLE, $newUid),
            'The denied create must leave no orphaned read-tier ACL relations.',
        );
        self::assertSame(
            [],
            $this->loadMmGroups(self::WRITE_MM_TABLE, $newUid),
            'The denied create must leave no orphaned write-tier ACL relations.',
        );

        // The denial is recorded in the audit trail.
        self::assertSame(
            1,
            $this->countAuditEntries($identifier, AuditAction::AccessDenied->value, false),
            'The denied create must be audited as access_denied.',
        );

        // And nothing else is: a success create entry would be a
        // verifiable-looking falsehood in the tamper-evident chain, standing
        // right next to the truthful denial.
        self::assertSame(
            0,
            $this->countAuditEntries($identifier, AuditAction::Create->value, true),
            'A denied create must not be audited as a successful creation.',
        );

        // The DataHandler log carries the user-facing error.
        /** @phpstan-ignore property.internal */
        self::assertNotEmpty($dataHandler->errorLog, 'The denied create must surface in the DataHandler error log.');
    }

    private function insertMmRow(string $mmTable, int $secretUid, int $groupUid): void
    {
        $this->getConnectionPool()->getConnectionForTable($mmTable)->insert($mmTable, [
            'uid_local' => $secretUid,
            'uid_foreign' => $groupUid,
            'sorting' => 0,
            'sorting_foreign' => 0,
        ]);
    }

    /**
     * @return list<int>
     */
    private function loadMmGroups(string $mmTable, int $secretUid): array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable($mmTable);
        $queryBuilder->getRestrictions()->removeAll();
        $rows = $queryBuilder
            ->select('uid_foreign')
            ->from($mmTable)
            ->where($queryBuilder->expr()->eq(
                'uid_local',
                $queryBuilder->createNamedParameter($secretUid, Connection::PARAM_INT),
            ))
            ->executeQuery()
            ->fetchAllAssociative();

        $groups = [];
        foreach ($rows as $row) {
            $groups[] = (int) $row['uid_foreign'];
        }

        return $groups;
    }

    private function countAuditEntries(string $identifier, string $action, bool $success): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::AUDIT_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $count = $queryBuilder
            ->count('uid')
            ->from(self::AUDIT_TABLE)
            ->where(
                $queryBuilder->expr()->eq('secret_identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter($action)),
                $queryBuilder->expr()->eq(
                    'success',
                    $queryBuilder->createNamedParameter($success ? 1 : 0, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }
}
