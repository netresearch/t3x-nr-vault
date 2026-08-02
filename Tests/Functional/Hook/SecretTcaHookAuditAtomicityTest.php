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
 * SEC-3 all-or-nothing on the FormEngine/DataHandler paths: a mutation and
 * its tamper-evident audit entry must stand or fall together. The audit
 * write is broken for real (the audit table is dropped mid-test), then the
 * review's acceptance scenarios are exercised end-to-end:
 *
 * - "AuditLogService throws on the metadata update => the database change
 *   is not kept" — SecretTcaHook's compensating rollback restores the
 *   captured pre-change values.
 * - "AuditLogService throws on the FormEngine delete => the secret
 *   survives" — the delete runs through VaultService::delete(), whose
 *   compensation re-stores the record (deleted=0).
 * - The same guarantee for the ACL group tiers, whose effective value lives
 *   in the MM relation tables rather than in the row: a reverted change must
 *   restore the relations themselves, and a reverted creation must not leave
 *   its relation rows behind.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookAuditAtomicityTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    private const READ_MM_TABLE = 'tx_nrvault_secret_begroups_mm';

    private const WRITE_MM_TABLE = 'tx_nrvault_secret_writegroups_mm';

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_and_groups.csv';

    #[Test]
    public function metadataChangeIsRevertedWhenAuditWriteFails(): void
    {
        $identifier = 'atomic_meta_' . bin2hex(random_bytes(4));
        $recordUid = $this->createRecord($identifier, 'Original description');

        $this->breakAuditWrites();

        $updateHandler = GeneralUtility::makeInstance(DataHandler::class);
        $updateHandler->start(
            [
                self::SECRET_TABLE => [
                    $recordUid => [
                        'description' => 'Changed description',
                    ],
                ],
            ],
            [],
        );
        $updateHandler->process_datamap();

        // The mutation must not survive its failed audit entry.
        self::assertSame(
            'Original description',
            $this->readColumn($recordUid, 'description'),
            'The metadata change must be reverted when its audit write fails.',
        );

        /** @phpstan-ignore property.internal */
        $errorLog = $updateHandler->errorLog;
        self::assertNotEmpty(
            $errorLog,
            'The reverted save must surface in the DataHandler error log.',
        );
    }

    #[Test]
    public function formEngineDeleteIsRevertedWhenAuditWriteFails(): void
    {
        $identifier = 'atomic_del_' . bin2hex(random_bytes(4));
        $recordUid = $this->createRecord($identifier, 'To be deleted');

        $this->breakAuditWrites();

        $deleteHandler = GeneralUtility::makeInstance(DataHandler::class);
        $deleteHandler->start(
            [],
            [
                self::SECRET_TABLE => [
                    $recordUid => [
                        'delete' => 1,
                    ],
                ],
            ],
        );
        $deleteHandler->process_cmdmap();

        // VaultService::delete() compensated the failed audit write by
        // re-storing the record, and the hook cancelled core's deleteAction.
        self::assertSame(
            0,
            (int) $this->readColumn($recordUid, 'deleted'),
            'The secret must survive a delete whose audit write failed.',
        );
        self::assertNotSame(
            '',
            $this->readColumn($recordUid, 'encrypted_value'),
            'The encrypted value must remain intact after the reverted delete.',
        );
    }

    /**
     * The regression this test pins: the rollback used to restore only the
     * main row, whose ACL columns hold nothing but the relation COUNT. The
     * widened MM rows — the ones the ACL is actually read from — survived,
     * leaving a record that claimed the old number of groups while granting
     * the new ones.
     */
    #[Test]
    public function aclGroupRelationsAreRevertedWhenAuditWriteFails(): void
    {
        $identifier = 'atomic_acl_' . bin2hex(random_bytes(4));
        $recordUid = $this->createRecord($identifier, 'ACL rollback');

        // Seed the ACL tiers through a separate, still-audited edit, so the
        // rollback under test faces relations written on the UPDATE path —
        // the one whose MM writes land during checkValue(), before this hook
        // runs, and therefore the one the snapshot/restore has to cope with.
        // (A create-path seed is covered by
        // SecretTcaHookCreateAclPreservationTest.)
        $this->updateAclGroups($recordUid, '10,11', '20');

        // Precondition: DataHandler really wrote the seeded relations, and
        // the count columns agree with them.
        self::assertSame([10, 11], $this->loadMmGroups(self::READ_MM_TABLE, $recordUid));
        self::assertSame([20], $this->loadMmGroups(self::WRITE_MM_TABLE, $recordUid));
        self::assertSame('2', $this->readColumn($recordUid, 'allowed_groups'));
        self::assertSame('1', $this->readColumn($recordUid, 'write_groups'));

        $this->breakAuditWrites();

        $updateHandler = GeneralUtility::makeInstance(DataHandler::class);
        $updateHandler->start(
            [
                self::SECRET_TABLE => [
                    $recordUid => [
                        // Widen BOTH tiers with group 99, and reorder the read
                        // tier so a restore that ignored `sorting` would show.
                        'allowed_groups' => '11,10,99',
                        'write_groups' => '20,99',
                    ],
                ],
            ],
            [],
        );
        $updateHandler->process_datamap();

        self::assertSame(
            [10, 11],
            $this->loadMmGroups(self::READ_MM_TABLE, $recordUid),
            'The read-tier MM relations must be restored exactly, order included.',
        );
        self::assertSame(
            [20],
            $this->loadMmGroups(self::WRITE_MM_TABLE, $recordUid),
            'The write-tier MM relations must be restored exactly.',
        );

        // The count columns must agree with the restored relations — the
        // inconsistency the old rollback produced was precisely a restored
        // count over a widened relation set.
        self::assertSame('2', $this->readColumn($recordUid, 'allowed_groups'));
        self::assertSame('1', $this->readColumn($recordUid, 'write_groups'));

        /** @phpstan-ignore property.internal */
        $errorLog = $updateHandler->errorLog;
        self::assertNotEmpty($errorLog, 'The reverted save must surface in the DataHandler error log.');
    }

    /**
     * Create path: DataHandler defers a new record's MM writes until after
     * every afterDatabaseOperations() hook has run, so the compensating
     * delete of the record happens BEFORE its relation rows are written.
     * Without the deferred purge, a reverted creation left MM rows pointing
     * at a uid that no longer exists.
     */
    #[Test]
    public function revertedRecordCreationLeavesNoOrphanedAclRelations(): void
    {
        $this->breakAuditWrites();

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                self::SECRET_TABLE => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => 'atomic_orphan_' . bin2hex(random_bytes(4)),
                        'description' => 'Value-less create with ACL groups',
                        // No secret_input: the hook itself audits this
                        // creation, so its failure triggers the hook's own
                        // compensating delete.
                        'allowed_groups' => '10,11',
                        'write_groups' => '20',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        $recordUid = (int) ($dataHandler->substNEWwithIDs['NEW1'] ?? 0);
        self::assertGreaterThan(0, $recordUid, 'The record must have been inserted before being reverted.');

        self::assertSame(
            '',
            $this->readColumn($recordUid, 'identifier'),
            'The record creation must be reverted when its audit write fails.',
        );
        self::assertSame(
            [],
            $this->loadMmGroups(self::READ_MM_TABLE, $recordUid),
            'A reverted creation must leave no orphaned read-tier relations.',
        );
        self::assertSame(
            [],
            $this->loadMmGroups(self::WRITE_MM_TABLE, $recordUid),
            'A reverted creation must leave no orphaned write-tier relations.',
        );
    }

    /**
     * Set both ACL group tiers through the real DataHandler while the audit
     * log is still healthy, so the edit is accepted and persisted.
     */
    private function updateAclGroups(int $recordUid, string $allowedGroups, string $writeGroups): void
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                self::SECRET_TABLE => [
                    $recordUid => [
                        'allowed_groups' => $allowedGroups,
                        'write_groups' => $writeGroups,
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        /** @phpstan-ignore property.internal */
        $errorLog = $dataHandler->errorLog;
        self::assertSame([], $errorLog, 'Seeding the ACL tiers must succeed without DataHandler errors.');
    }

    /**
     * Create a value-bearing secret record through the real DataHandler
     * (audit still healthy at this point).
     */
    private function createRecord(string $identifier, string $description): int
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                self::SECRET_TABLE => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => $identifier,
                        'description' => $description,
                        'secret_input' => 'atomicity-test-value',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        $recordUid = $dataHandler->substNEWwithIDs['NEW1'] ?? 0;
        self::assertIsNumeric($recordUid);
        self::assertGreaterThan(0, (int) $recordUid);

        // assertSame([], ...) prints the offending entries itself on failure
        // (and sidesteps the v13 core stub typing errorLog as plain `array`,
        // which rejects implode()).
        /** @phpstan-ignore property.internal */
        $errorLog = $dataHandler->errorLog;
        self::assertSame([], $errorLog, 'Seeding must succeed without DataHandler errors.');

        return (int) $recordUid;
    }

    /**
     * Make every subsequent audit-chain write fail for real: drop the audit
     * table. AuditLogService::log() wraps the resulting driver exception in
     * AuditWriteException — the type the compensations key on.
     */
    private function breakAuditWrites(): void
    {
        $this->getConnectionPool()
            ->getConnectionForTable(self::AUDIT_TABLE)
            ->executeStatement('DROP TABLE ' . self::AUDIT_TABLE);
    }

    /**
     * The secret's related group UIDs for one tier, in relation order — the
     * same `sorting` order `SecretRepository::loadGroupsForSecret()` reads
     * the effective ACL in.
     *
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
            ->orderBy('sorting', 'ASC')
            ->executeQuery()
            ->fetchAllAssociative();

        $groups = [];
        foreach ($rows as $row) {
            $groups[] = (int) $row['uid_foreign'];
        }

        return $groups;
    }

    private function readColumn(int $uid, string $column): string
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $value = $queryBuilder
            ->select($column)
            ->from(self::SECRET_TABLE)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return \is_scalar($value) ? (string) $value : '';
    }
}
