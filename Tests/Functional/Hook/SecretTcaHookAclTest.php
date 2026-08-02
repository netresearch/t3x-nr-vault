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
 * Functional tests for the write-path authorization in SecretTcaHook: the
 * per-secret object ACL on every update (CWE-862) and the privileged-column
 * policy layered on top of it (CWE-639/CWE-269).
 *
 * ## Why the secret lives on a real page
 *
 * These tests deliberately do NOT seed at pid 0. `tx_nrvault_secret` sets
 * `rootLevel => -1` and `ignorePageTypeRestriction`, but NOT
 * `ignoreRootLevelRestriction` — so core refuses a non-admin's datamap for a
 * pid-0 record before any hook runs ("Attempt to modify record ... without
 * permission or non-existing page"). A test seeding at pid 0 and asserting
 * "the row is unchanged" therefore passes whether the hook works or not: it
 * measures core's refusal, not the vault's.
 *
 * Seeding on page 1, with an editor holding `tables_modify` on the table and
 * a webmount plus edit permission on that page, makes the datamap genuinely
 * reach the hook. Every "unchanged" assertion below is then attributable to
 * the vault gate — and the accompanying audit assertions pin which gate.
 */
#[CoversClass(SecretTcaHook::class)]
final class SecretTcaHookAclTest extends AbstractVaultFunctionalTestCase
{
    private const SECRET_TABLE = 'tx_nrvault_secret';

    private const AUDIT_TABLE = 'tx_nrvault_audit_log';

    private const READ_MM_TABLE = 'tx_nrvault_secret_begroups_mm';

    private const WRITE_MM_TABLE = 'tx_nrvault_secret_writegroups_mm';

    /** Page the secret is stored on; the editors have edit rights here. */
    private const PAGE_UID = 1;

    /** Owner of the seeded secret (a different user than the editors). */
    private const OWNER_UID = 1;

    /**
     * Non-admin editor with table-modify rights on tx_nrvault_secret and no
     * relationship to the secret at all: not its owner, in neither tier.
     * Fails canWrite() — every change of theirs must be refused outright.
     */
    private const EDITOR_UID = 2;

    /**
     * Non-admin editor who IS in the secret's write tier, so canWrite()
     * passes, but who holds no `secret.manage_policy` grant. May change the
     * ordinary columns; must not touch the privileged ones.
     */
    private const WRITER_UID = 4;

    /** Pre-existing read-tier group on the secret. */
    private const EXISTING_READ_GROUP = 41;

    /** Write-tier group on the secret; WRITER_UID is a member. */
    private const EXISTING_WRITE_GROUP = 40;

    /** Group the attacker tries to inject (e.g. one they belong to). */
    private const ATTACKER_GROUP = 30;

    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/be_users_acl_page.csv';

    /** Logged in per test — the scenarios need different actors. */
    protected ?int $backendUserUid = null;

    /**
     * The object ACL covers ORDINARY columns too, which is the whole finding:
     * before it, holding `tables_modify` on the table was enough to rewrite
     * any secret's description, context, expiry or metadata — and the hook
     * then audited the change as a successful metadata_update in the
     * unauthorized editor's name.
     */
    #[Test]
    #[DataProvider('unauthorizedColumnProvider')]
    public function anEditorWithoutWriteAccessCannotChangeAnyColumn(string $column, mixed $submitted): void
    {
        $this->setUpBackendUser(self::EDITOR_UID);
        [$secretUid, $identifier] = $this->seedSecretOwnedByOther();

        $this->submitDatamap($secretUid, [$column => $submitted]);

        self::assertSame(
            $this->seededValue($column),
            $this->currentValue($this->loadSecretRow($secretUid), $column),
            $column . ' must be unchanged by an editor without write access to the secret.',
        );

        self::assertTrue(
            $this->hasAuditEntry($identifier, AuditAction::AccessDenied, false),
            'The refusal must be recorded as access_denied.',
        );
        self::assertFalse(
            $this->hasAuditEntry($identifier, AuditAction::MetadataUpdate, true),
            'A refused change must not also be audited as a successful metadata_update.',
        );
    }

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function unauthorizedColumnProvider(): iterable
    {
        // Backdating denies the secret to every consumer (Secret::isExpired()
        // makes VaultService throw SecretExpiredException); clearing it
        // revives a deliberately retired one.
        yield 'expires_at' => ['expires_at', '2000-01-01T00:00:00+00:00'];
        // The OrphanCleanupTask vector: table+uid are read straight out of
        // metadata to decide whether the scheduler deletes the secret.
        yield 'metadata' => ['metadata', '{"source":"tca_field","table":"tt_content","field":"x","uid":2147483647}'];
        yield 'description' => ['description', 'rewritten by someone else'];
        yield 'context' => ['context', 'staging'];
    }

    /**
     * canWrite() buys the right to maintain the secret, not to re-scope it.
     * The write-tier member's ordinary edit lands; the privileged columns
     * submitted in the same save do not.
     */
    #[Test]
    public function aWriteTierEditorWithoutManagePolicyCannotChangeThePrivilegedColumns(): void
    {
        $this->setUpBackendUser(self::WRITER_UID);
        [$secretUid, $identifier] = $this->seedSecretOwnedByOther();

        $this->submitDatamap($secretUid, [
            'description' => 'documented by the write tier',
            'expires_at' => '2000-01-01T00:00:00+00:00',
            'metadata' => '{"source":"tca_field","table":"tt_content","field":"x","uid":2147483647}',
            'context' => 'staging',
            'frontend_accessible' => 1,
        ]);

        $record = $this->loadSecretRow($secretUid);

        self::assertSame(
            'documented by the write tier',
            $record['description'],
            'A write-tier member may document the secret they maintain.',
        );

        foreach (['expires_at', 'metadata', 'context', 'frontend_accessible'] as $column) {
            self::assertSame(
                $this->seededValue($column),
                $this->currentValue($record, $column),
                $column . ' requires secret.manage_policy and must be unchanged.',
            );
        }

        self::assertTrue(
            $this->hasAuditEntry($identifier, AuditAction::AccessDenied, false),
            'The refused policy change must be recorded as access_denied.',
        );
    }

    #[Test]
    public function nonOwnerEditorCannotWidenMmGroupAcls(): void
    {
        $this->setUpBackendUser(self::WRITER_UID);
        [$secretUid] = $this->seedSecretOwnedByOther();

        // Attacker appends their own group to BOTH tiers.
        $this->submitDatamap($secretUid, [
            'allowed_groups' => self::EXISTING_READ_GROUP . ',' . self::ATTACKER_GROUP,
            'write_groups' => self::EXISTING_WRITE_GROUP . ',' . self::ATTACKER_GROUP,
        ]);

        self::assertSame(
            [self::EXISTING_READ_GROUP],
            $this->loadMmGroups(self::READ_MM_TABLE, $secretUid),
            'Read-tier MM relations must be unchanged without secret.manage_policy.',
        );
        self::assertSame(
            [self::EXISTING_WRITE_GROUP],
            $this->loadMmGroups(self::WRITE_MM_TABLE, $secretUid),
            'Write-tier MM relations must be unchanged without secret.manage_policy.',
        );
    }

    #[Test]
    public function nonOwnerEditorCannotReassignOwnerOrFrontendAccess(): void
    {
        $this->setUpBackendUser(self::WRITER_UID);
        [$secretUid] = $this->seedSecretOwnedByOther();

        // Attacker grabs ownership and flips frontend exposure.
        $this->submitDatamap($secretUid, [
            'owner_uid' => self::WRITER_UID,
            'frontend_accessible' => 1,
        ]);

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
     * The guard against this suite silently regressing to what it replaced:
     * if the datamap never reached the hook, every "unchanged" assertion
     * above would hold for the wrong reason. The owner — who passes both
     * canWrite() and, being seeded without the manage_policy grant, only the
     * ordinary-column path — must be able to save.
     */
    #[Test]
    public function theSetupLetsAnAuthorizedEditReachTheDatabase(): void
    {
        $this->setUpBackendUser(self::WRITER_UID);
        [$secretUid] = $this->seedSecretOwnedByOther();

        $this->submitDatamap($secretUid, ['description' => 'reached the database']);

        self::assertSame(
            'reached the database',
            $this->loadSecretRow($secretUid)['description'],
            'Core must not be refusing these datamaps before the hook runs — '
            . 'otherwise the refusal assertions in this suite prove nothing.',
        );
    }

    /**
     * The column values seedSecretOwnedByOther() writes, as they read back
     * from the database. Shared by the seed and the assertions so a changed
     * seed cannot leave an assertion comparing against a stale constant.
     *
     * @return array<string, mixed>
     */
    private function seededRow(): array
    {
        return [
            'description' => 'seeded description',
            'context' => 'production',
            'expires_at' => 0,
            'metadata' => '{"source":"tca_field"}',
            'frontend_accessible' => 0,
        ];
    }

    /**
     * The seeded value of one column as a string. Stringified because the
     * DBAL driver decides the scalar type a column reads back as (an int
     * column comes back as int on sqlite, as string on others), and the
     * assertion is about the value, not the driver.
     */
    private function seededValue(string $column): string
    {
        $value = $this->seededRow()[$column];

        return \is_scalar($value) ? (string) $value : '';
    }

    /**
     * The current value of one column, stringified to match seededValue().
     *
     * @param array<string, mixed> $record
     */
    private function currentValue(array $record, string $column): string
    {
        $value = $record[$column] ?? null;

        return \is_scalar($value) ? (string) $value : '';
    }

    /**
     * Run a datamap as the logged-in backend user, exactly as FormEngine
     * would. Not a direct hook call: the point of this suite is that the
     * whole DataHandler path is gated, core's permission checks included.
     *
     * @param array<string, mixed> $fields
     */
    private function submitDatamap(int $secretUid, array $fields): void
    {
        $dataHandler = GeneralUtility::makeInstance(DataHandler::class);
        $dataHandler->BE_USER = $GLOBALS['BE_USER'];
        $dataHandler->start([self::SECRET_TABLE => [$secretUid => $fields]], []);
        $dataHandler->process_datamap();
    }

    /**
     * Seed a secret owned by OWNER_UID with one read-tier and one write-tier
     * MM relation, on a page the editors may edit.
     *
     * @return array{int, string} The new secret UID and its identifier
     */
    private function seedSecretOwnedByOther(): array
    {
        $identifier = 'acl_secret_' . bin2hex(random_bytes(4));
        $connection = $this->getConnectionPool()->getConnectionForTable(self::SECRET_TABLE);
        $connection->insert(self::SECRET_TABLE, [
            ...$this->seededRow(),
            'pid' => self::PAGE_UID,
            'identifier' => $identifier,
            'owner_uid' => self::OWNER_UID,
            // DataHandler stores the relation count in the row column.
            'allowed_groups' => 1,
            'write_groups' => 1,
        ]);
        $secretUid = (int) $connection->lastInsertId();

        $this->insertMmRelation(self::READ_MM_TABLE, $secretUid, self::EXISTING_READ_GROUP);
        $this->insertMmRelation(self::WRITE_MM_TABLE, $secretUid, self::EXISTING_WRITE_GROUP);

        return [$secretUid, $identifier];
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

    private function hasAuditEntry(string $identifier, AuditAction $action, bool $success): bool
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
                    $queryBuilder->createNamedParameter($success ? 1 : 0, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        return (int) $count > 0;
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
            ->select(
                'owner_uid',
                'frontend_accessible',
                'description',
                'context',
                'expires_at',
                'metadata',
            )
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
