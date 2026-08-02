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
 * The `secret.create` gate on the FormEngine create path.
 *
 * The gap this pins: both create gates (`canCreate()` and
 * `isGranted(secret.create)`) live inside `VaultService::store()`, and a
 * record saved with an EMPTY value never calls store() — `secret_input` is
 * optional and the table is not adminOnly, so that is an ordinary save. A
 * backend user holding table rights but not `secret.create` could therefore
 * create a vault secret record: the row landed, `owner_uid` was forced to the
 * unauthorized creator by the privileged-column policy, and a SUCCESS `create`
 * entry went into the tamper-evident HMAC chain for an operation nobody was
 * allowed to perform. The identifier then stayed squatted — a later legitimate
 * non-admin creator of the same identifier fails `canWrite()` against the
 * existing row, not the unique key.
 *
 * The gate is a pre-process refusal, not a compensating rollback: it nulls the
 * by-ref field array in `processDatamap_preProcessFieldArray()`, which makes
 * core skip the record entirely before `insertDB()`. These tests therefore
 * drive the REAL DataHandler — the assertion "no row exists" is produced by
 * core itself, and the fixture gives the denied user the table and page rights
 * that would otherwise mask the result.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookCreateAclTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    private const READ_MM_TABLE = 'tx_nrvault_secret_begroups_mm';

    private const WRITE_MM_TABLE = 'tx_nrvault_secret_writegroups_mm';

    /** Storage page both editors may write content to. */
    private const STORAGE_PID = 1;

    /** Non-admin editor with table rights but WITHOUT secret.create. */
    private const EDITOR_WITHOUT_CREATE = 2;

    /** Non-admin editor with table rights AND secret.create. */
    private const EDITOR_WITH_CREATE = 4;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_create_permission.csv';

    /** Each test logs in the user it needs. */
    protected ?int $backendUserUid = null;

    /**
     * The finding itself: no value, no store() call, and until now no gate
     * either.
     */
    #[Test]
    public function valuelessCreateWithoutSecretCreatePermissionInsertsNoRecord(): void
    {
        $this->setUpBackendUser(self::EDITOR_WITHOUT_CREATE);
        $identifier = 'valueless_' . bin2hex(random_bytes(4));

        $dataHandler = $this->processCreate([
            'pid' => self::STORAGE_PID,
            'identifier' => $identifier,
            'description' => 'A record carrying no secret value at all',
        ]);

        self::assertNull(
            $this->findRecord($identifier),
            'A creator without secret.create must not get a record — it would squat the identifier.',
        );

        self::assertSame(
            1,
            $this->countAuditEntries($identifier, AuditAction::AccessDenied->value, false),
            'The refused create must be audited as access_denied.',
        );
        self::assertSame(
            0,
            $this->countAuditEntries($identifier, AuditAction::Create->value, true),
            'A refused create must never produce a success create entry in the HMAC chain.',
        );

        self::assertStringContainsString(
            'secret.create',
            $this->errorLogText($dataHandler),
            'FormEngine must tell the editor which permission the save needed.',
        );
    }

    /**
     * The same gate catches a value-BEARING create one step earlier than
     * VaultService::store() would: the row is never inserted, so there is
     * nothing to revert and nothing to squat in between.
     */
    #[Test]
    public function valueBearingCreateWithoutSecretCreatePermissionInsertsNoRecord(): void
    {
        $this->setUpBackendUser(self::EDITOR_WITHOUT_CREATE);
        $identifier = 'valuebearing_' . bin2hex(random_bytes(4));

        $this->processCreate([
            'pid' => self::STORAGE_PID,
            'identifier' => $identifier,
            'secret_input' => 'must-not-be-stored',
        ]);

        self::assertNull($this->findRecord($identifier));
        self::assertSame(
            1,
            $this->countAuditEntries($identifier, AuditAction::AccessDenied->value, false),
        );
        self::assertSame(
            0,
            $this->countAuditEntries($identifier, AuditAction::Create->value, true),
        );
    }

    /**
     * A refused create must not leave the ACL relations DataHandler would
     * otherwise queue for it behind either.
     */
    #[Test]
    public function refusedCreateLeavesNoAclRelationRows(): void
    {
        $this->setUpBackendUser(self::EDITOR_WITHOUT_CREATE);
        $identifier = 'acl_refused_' . bin2hex(random_bytes(4));

        $this->processCreate([
            'pid' => self::STORAGE_PID,
            'identifier' => $identifier,
            'allowed_groups' => '30,31',
            'write_groups' => '31',
        ]);

        self::assertNull($this->findRecord($identifier));
        self::assertSame(0, $this->countRows(self::READ_MM_TABLE), 'No read-tier ACL relations may be written.');
        self::assertSame(0, $this->countRows(self::WRITE_MM_TABLE), 'No write-tier ACL relations may be written.');
    }

    /**
     * The gate must not break the legitimate case it guards: a value-less
     * record is a valid thing to create, and after this change that is the
     * only thing RecordCreationOutcome::ValueLess can still mean — an
     * AUTHORIZED creator who deliberately left the value empty.
     */
    #[Test]
    public function creatorHoldingSecretCreateMayCreateAValuelessRecord(): void
    {
        $this->setUpBackendUser(self::EDITOR_WITH_CREATE);
        $identifier = 'granted_valueless_' . bin2hex(random_bytes(4));

        $dataHandler = $this->processCreate([
            'pid' => self::STORAGE_PID,
            'identifier' => $identifier,
            'description' => 'Deliberately created without a value',
        ]);

        $record = $this->findRecord($identifier);
        self::assertIsArray(
            $record,
            'A creator holding secret.create must still be able to create. DataHandler log: '
            . $this->errorLogText($dataHandler),
        );
        // The creator owns what they created (the privileged-column policy
        // forces this for non-admins) — the gate runs in front of it, it does
        // not replace it.
        self::assertSame(self::EDITOR_WITH_CREATE, (int) $record['owner_uid']);

        self::assertSame(
            1,
            $this->countAuditEntries($identifier, AuditAction::Create->value, true),
            'An authorized value-less create is audited as a creation.',
        );
        self::assertSame(
            0,
            $this->countAuditEntries($identifier, AuditAction::AccessDenied->value, false),
        );
    }

    #[Test]
    public function creatorHoldingSecretCreateMayCreateAValueBearingRecord(): void
    {
        $this->setUpBackendUser(self::EDITOR_WITH_CREATE);
        $identifier = 'granted_value_' . bin2hex(random_bytes(4));

        $this->processCreate([
            'pid' => self::STORAGE_PID,
            'identifier' => $identifier,
            'secret_input' => 'a-real-value',
        ]);

        $record = $this->findRecord($identifier);
        self::assertIsArray($record);
        $encryptedValue = $record['encrypted_value'];
        self::assertIsString($encryptedValue);
        self::assertNotSame(
            '',
            $encryptedValue,
            'The submitted value must have been encrypted and stored.',
        );

        self::assertSame(
            1,
            $this->countAuditEntries($identifier, AuditAction::Create->value, true),
            'VaultService::store() audits the creation it performed.',
        );
        self::assertSame(
            0,
            $this->countAuditEntries($identifier, AuditAction::AccessDenied->value, false),
        );
    }

    /**
     * An admin is unaffected: the gate asks AccessControlService, which routes
     * the admin decision through the single `adminBypassActive()` seam rather
     * than short-circuiting on the role here.
     */
    #[Test]
    public function adminIsUnaffectedByTheCreateGate(): void
    {
        $this->setUpBackendUser(1);
        $identifier = 'admin_created_' . bin2hex(random_bytes(4));

        $this->processCreate([
            'pid' => self::STORAGE_PID,
            'identifier' => $identifier,
            'description' => 'Created by an administrator',
        ]);

        self::assertIsArray($this->findRecord($identifier));
        self::assertSame(
            0,
            $this->countAuditEntries($identifier, AuditAction::AccessDenied->value, false),
        );
    }

    /**
     * Run one NEW-record datamap through the real DataHandler.
     *
     * @param array<string, mixed> $fieldArray
     */
    private function processCreate(array $fieldArray): DataHandler
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->start([self::SECRET_TABLE => ['NEW1' => $fieldArray]], []);
        $dataHandler->process_datamap();

        return $dataHandler;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function findRecord(string $identifier): ?array
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable(self::SECRET_TABLE);
        $queryBuilder->getRestrictions()->removeAll();
        $row = $queryBuilder
            ->select('uid', 'owner_uid', 'encrypted_value')
            ->from(self::SECRET_TABLE)
            ->where($queryBuilder->expr()->eq(
                'identifier',
                $queryBuilder->createNamedParameter($identifier),
            ))
            ->executeQuery()
            ->fetchAssociative();

        return $row === false ? null : $row;
    }

    private function countRows(string $table): int
    {
        $queryBuilder = $this->getConnectionPool()->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();
        $count = $queryBuilder->count('uid_local')->from($table)->executeQuery()->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
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

    private function errorLogText(DataHandler $dataHandler): string
    {
        /** @phpstan-ignore property.internal */
        $errorLog = $dataHandler->errorLog;

        return implode("\n", array_map(static fn (mixed $line): string => (string) $line, $errorLog));
    }
}
