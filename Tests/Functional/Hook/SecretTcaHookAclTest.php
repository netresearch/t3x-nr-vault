<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Hook;

use Netresearch\NrVault\Hook\SecretTcaHook;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\DataHandling\DataHandler;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Functional tests for the privileged-ACL-column write-path authorization in
 * SecretTcaHook (CWE-639/CWE-269).
 *
 * A non-admin, non-owner backend editor with table-modify rights on
 * tx_nrvault_secret must NOT be able to widen another user's ACL or reassign
 * ownership / frontend-accessibility through the FormEngine path.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookAclTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const READ_MM_TABLE = 'tx_nrvault_secret_begroups_mm';

    private const WRITE_MM_TABLE = 'tx_nrvault_secret_writegroups_mm';

    /** Owner of the seeded secret (a different user than the editor). */
    private const OWNER_UID = 1;

    /** Non-admin editor performing the malicious edit. */
    private const EDITOR_UID = 2;

    /** Pre-existing read-tier group on the secret. */
    private const EXISTING_READ_GROUP = 10;

    /** Pre-existing write-tier group on the secret. */
    private const EXISTING_WRITE_GROUP = 20;

    /** Group the attacker tries to inject (e.g. one they belong to). */
    private const ATTACKER_GROUP = 99;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_acl.csv';

    /** Log in as the non-admin editor (uid 2), not the default admin. */
    protected ?int $backendUserUid = self::EDITOR_UID;

    #[Test]
    public function nonOwnerEditorCannotWidenMmGroupAcls(): void
    {
        $secretUid = $this->seedSecretOwnedByOther();

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];
        $dataHandler->start(
            [
                self::SECRET_TABLE => [
                    $secretUid => [
                        // Attacker appends their own group to BOTH tiers.
                        'allowed_groups' => self::EXISTING_READ_GROUP . ',' . self::ATTACKER_GROUP,
                        'write_groups' => self::EXISTING_WRITE_GROUP . ',' . self::ATTACKER_GROUP,
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        // The MM relations must be exactly what was seeded — the attacker group
        // must NOT have been added to either tier.
        self::assertSame(
            [self::EXISTING_READ_GROUP],
            $this->loadMmGroups(self::READ_MM_TABLE, $secretUid),
            'Read-tier MM relations must be unchanged by a non-owner editor.',
        );
        self::assertSame(
            [self::EXISTING_WRITE_GROUP],
            $this->loadMmGroups(self::WRITE_MM_TABLE, $secretUid),
            'Write-tier MM relations must be unchanged by a non-owner editor.',
        );
    }

    #[Test]
    public function nonOwnerEditorCannotReassignOwnerOrFrontendAccess(): void
    {
        $secretUid = $this->seedSecretOwnedByOther();

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];
        $dataHandler->start(
            [
                self::SECRET_TABLE => [
                    $secretUid => [
                        // Attacker grabs ownership and flips frontend exposure.
                        'owner_uid' => self::EDITOR_UID,
                        'frontend_accessible' => 1,
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        $record = $this->loadSecretRow($secretUid);
        self::assertSame(
            self::OWNER_UID,
            (int) $record['owner_uid'],
            'owner_uid must remain the original owner.',
        );
        self::assertSame(
            0,
            (int) $record['frontend_accessible'],
            'frontend_accessible must remain disabled.',
        );
    }

    /**
     * Seed a secret owned by OWNER_UID with one read-tier and one write-tier
     * MM relation, not frontend-accessible.
     *
     * @return int The new secret UID
     */
    private function seedSecretOwnedByOther(): int
    {
        $connection = $this->getConnectionPool()->getConnectionForTable(self::SECRET_TABLE);
        $connection->insert(self::SECRET_TABLE, [
            'pid' => 0,
            'identifier' => 'acl_secret_' . bin2hex(random_bytes(4)),
            'owner_uid' => self::OWNER_UID,
            'frontend_accessible' => 0,
            // DataHandler stores the relation count in the row column.
            'allowed_groups' => 1,
            'write_groups' => 1,
        ]);
        $secretUid = (int) $connection->lastInsertId();

        $this->insertMmRelation(self::READ_MM_TABLE, $secretUid, self::EXISTING_READ_GROUP);
        $this->insertMmRelation(self::WRITE_MM_TABLE, $secretUid, self::EXISTING_WRITE_GROUP);

        return $secretUid;
    }

    private function insertMmRelation(string $mmTable, int $secretUid, int $groupUid): void
    {
        $this->getConnectionPool()
            ->getConnectionForTable($mmTable)
            ->insert($mmTable, [
                'uid_local' => $secretUid,
                'uid_foreign' => $groupUid,
                'sorting' => 1,
                'sorting_foreign' => 0,
            ]);
    }

    /**
     * @return list<int> Group UIDs related to the secret, ascending
     */
    private function loadMmGroups(string $mmTable, int $secretUid): array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable($mmTable);
        $queryBuilder->getRestrictions()->removeAll();
        $rows = $queryBuilder
            ->select('uid_foreign')
            ->from($mmTable)
            ->where(
                $queryBuilder->expr()->eq(
                    'uid_local',
                    $queryBuilder->createNamedParameter($secretUid, Connection::PARAM_INT),
                ),
            )
            ->orderBy('uid_foreign', 'ASC')
            ->executeQuery()
            ->fetchAllAssociative();

        $groups = [];
        foreach ($rows as $row) {
            $groups[] = (int) $row['uid_foreign'];
        }

        return $groups;
    }

    /**
     * @return array<string, mixed>
     */
    private function loadSecretRow(int $secretUid): array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $record = $queryBuilder
            ->select('owner_uid', 'frontend_accessible')
            ->from(self::SECRET_TABLE)
            ->where(
                $queryBuilder->expr()->eq(
                    'uid',
                    $queryBuilder->createNamedParameter($secretUid, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchAssociative();

        self::assertIsArray($record);

        return $record;
    }
}
