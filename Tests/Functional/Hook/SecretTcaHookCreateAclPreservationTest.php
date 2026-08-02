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
 * A value-bearing FormEngine create that also assigns ACL groups must end up
 * with the groups the editor assigned.
 *
 * The regression this pins: DataHandler inserts the row and defers a NEW
 * record's MM writes until every afterDatabaseOperations() hook has run, so
 * VaultService::store() — called from that hook — read the record back while
 * its relations did not exist yet and saved it again with empty group tiers.
 * The MM rows then landed and survived, but the count columns had been zeroed
 * in between, leaving a record that claimed no groups while granting two.
 * The update path never had the problem: there DataHandler writes the MM rows
 * during checkValue(), before the hook runs.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookCreateAclPreservationTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const READ_MM_TABLE = 'tx_nrvault_secret_begroups_mm';

    private const WRITE_MM_TABLE = 'tx_nrvault_secret_writegroups_mm';

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_and_groups.csv';

    #[Test]
    public function valueBearingCreateKeepsTheAclGroupsItWasGiven(): void
    {
        $identifier = 'create_acl_' . bin2hex(random_bytes(4));

        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start(
            [
                self::SECRET_TABLE => [
                    'NEW1' => [
                        'pid' => 0,
                        'identifier' => $identifier,
                        'description' => 'Value-bearing create with ACL groups',
                        'secret_input' => 'create-acl-test-value',
                        'allowed_groups' => '10,11',
                        'write_groups' => '20',
                    ],
                ],
            ],
            [],
        );
        $dataHandler->process_datamap();

        /** @phpstan-ignore property.internal */
        $errorLog = $dataHandler->errorLog;
        self::assertSame([], $errorLog, 'The create must succeed without DataHandler errors.');

        $recordUid = (int) ($dataHandler->substNEWwithIDs['NEW1'] ?? 0);
        self::assertGreaterThan(0, $recordUid);

        // Precondition for the assertions below: the value really was stored,
        // so store() ran and had the chance to overwrite the ACL state.
        self::assertNotSame(
            '',
            $this->readColumn($recordUid, 'encrypted_value'),
            'The submitted secret value must have been stored.',
        );

        self::assertSame(
            [10, 11],
            $this->loadMmGroups(self::READ_MM_TABLE, $recordUid),
            'The read-tier ACL relations the editor assigned must survive the create.',
        );
        self::assertSame(
            [20],
            $this->loadMmGroups(self::WRITE_MM_TABLE, $recordUid),
            'The write-tier ACL relations the editor assigned must survive the create.',
        );

        // The count columns must agree with the relations — reporting 0 for a
        // record that grants two groups is the inconsistency under test.
        self::assertSame('2', $this->readColumn($recordUid, 'allowed_groups'));
        self::assertSame('1', $this->readColumn($recordUid, 'write_groups'));
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
