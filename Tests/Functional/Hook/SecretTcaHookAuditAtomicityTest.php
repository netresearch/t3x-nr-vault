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
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookAuditAtomicityTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users.csv';

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

        /** @phpstan-ignore property.internal */
        $errorLog = $dataHandler->errorLog;
        self::assertEmpty($errorLog, 'Seeding must succeed: ' . implode(', ', $errorLog));

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
