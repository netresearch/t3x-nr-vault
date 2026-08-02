<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Closure;
use Doctrine\DBAL\Result;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Hook\SecretTcaHook;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use ReflectionClass;
use RuntimeException;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\QueryRestrictionContainerInterface;
use TYPO3\CMS\Core\DataHandling\DataHandler;

#[CoversClass(SecretTcaHook::class)]
#[AllowMockObjectsWithoutExpectations]
final class SecretTcaHookTest extends TestCase
{
    private const TABLE = 'tx_nrvault_secret';

    private const READ_GROUPS_MM = 'tx_nrvault_secret_begroups_mm';

    private const WRITE_GROUPS_MM = 'tx_nrvault_secret_writegroups_mm';

    private VaultServiceInterface&MockObject $vaultService;

    private AuditLogServiceInterface&MockObject $auditService;

    private AccessControlServiceInterface&MockObject $accessControlService;

    private SecretRepositoryInterface&MockObject $secretRepository;

    private SecretTcaHook $hook;

    /**
     * Rows the hook's record reads resolve to, consumed in order.
     *
     * @var list<array<string, mixed>|false>
     */
    private array $backendRecords = [];

    /**
     * The shape of every record read performed so far.
     *
     * @var list<array<int, mixed>>
     */
    private array $recordReads = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->auditService = $this->createMock(AuditLogServiceInterface::class);
        $this->accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $this->secretRepository = $this->createMock(SecretRepositoryInterface::class);

        // Default to an admin actor so the pre-existing field-normalisation
        // tests (NEW records, owner/scope extraction) are not coerced by the
        // privileged-column policy. Policy-specific tests override this.
        $this->accessControlService->method('isCurrentActorAdmin')->willReturn(true);

        // ... and let that actor create. The create gate refuses a NEW record
        // outright (the field array is nulled and core skips the record), so
        // without these the normalisation tests below would assert against a
        // record that never got normalised. The gate has its own tests, each
        // building its own access-control mock.
        $this->accessControlService->method('canCreate')->willReturn(true);
        $this->accessControlService->method('isGranted')->willReturn(true);

        $this->hook = new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $this->accessControlService,
            $this->secretRepository,
        );
    }

    protected function tearDown(): void
    {
        // A path that performs fewer reads than the test queued would
        // otherwise pass silently.
        self::assertSame([], $this->backendRecords, 'queued record reads left unconsumed');

        parent::tearDown();
    }

    #[Test]
    public function preProcessIgnoresOtherTables(): void
    {
        $fieldArray = ['field' => 'value'];
        $dataHandler = $this->createMock(DataHandler::class);

        $this->hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'other_table',
            1,
            $dataHandler,
        );

        // Field array should be unchanged
        self::assertSame(['field' => 'value'], $fieldArray);
    }

    #[Test]
    public function preProcessRemovesSecretInputField(): void
    {
        $fieldArray = [
            'identifier' => 'test-secret',
            'secret_input' => 'secret-value',
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $this->hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        // secret_input should be removed (not a real DB column)
        self::assertArrayNotHasKey('secret_input', $fieldArray);
        self::assertArrayHasKey('identifier', $fieldArray);
    }

    #[Test]
    public function preProcessExtractsOwnerUidFromGroupFormat(): void
    {
        $fieldArray = [
            'owner_uid' => 'be_users_42',
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $this->hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        self::assertIsArray($fieldArray);
        self::assertSame(42, $fieldArray['owner_uid']);
    }

    #[Test]
    public function preProcessExtractsScopePidFromGroupFormat(): void
    {
        $fieldArray = [
            'scope_pid' => 'pages_100',
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $this->hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        self::assertIsArray($fieldArray);
        self::assertSame(100, $fieldArray['scope_pid']);
    }

    #[Test]
    public function preProcessHandlesSimpleNumericOwnerUid(): void
    {
        $fieldArray = [
            'owner_uid' => '15',
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $this->hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        self::assertIsArray($fieldArray);
        self::assertSame(15, $fieldArray['owner_uid']);
    }

    #[Test]
    public function afterDatabaseOperationsIgnoresOtherTables(): void
    {
        $dataHandler = $this->createMock(DataHandler::class);

        // Should not call any vault/audit services
        $this->vaultService->expects($this->never())->method('store');
        $this->auditService->expects($this->never())->method('log');

        $this->hook->processDatamap_afterDatabaseOperations(
            'new',
            'other_table',
            1,
            [],
            $dataHandler,
        );
    }

    #[Test]
    public function cmdmapPreProcessIgnoresOtherTables(): void
    {
        $this->auditService->expects($this->never())->method('log');

        $this->hook->processCmdmap_preProcess('delete', 'other_table', 1);
    }

    #[Test]
    public function cmdmapPreProcessIgnoresNonDeleteCommands(): void
    {
        $this->auditService->expects($this->never())->method('log');

        $this->hook->processCmdmap_preProcess('copy', 'tx_nrvault_secret', 1);
    }

    #[Test]
    public function preProcessHandlesIntegerOwnerUid(): void
    {
        $fieldArray = [
            'owner_uid' => 42, // Integer, not string
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $this->hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        // Integer should pass through unchanged
        self::assertIsArray($fieldArray);
        self::assertSame(42, $fieldArray['owner_uid']);
    }

    #[Test]
    public function preProcessIgnoresScopePidWithoutPagesPrefix(): void
    {
        $fieldArray = [
            'scope_pid' => '99', // No 'pages' prefix
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $this->hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        // Should remain as string without conversion (no 'pages' in value)
        self::assertIsArray($fieldArray);
        self::assertSame('99', $fieldArray['scope_pid']);
    }

    #[Test]
    public function preProcessStoresSecretInputForNewRecord(): void
    {
        $fieldArray = [
            'identifier' => 'test-secret',
            'secret_input' => 'my-secret-value',
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $this->hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        // secret_input should be removed from fieldArray
        self::assertArrayNotHasKey('secret_input', $fieldArray);
        self::assertArrayHasKey('identifier', $fieldArray);
    }

    #[Test]
    public function preProcessIgnoresEmptySecretInput(): void
    {
        $fieldArray = [
            'identifier' => 'test-secret',
            'secret_input' => '',
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $this->hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        // Empty secret_input should just be removed
        self::assertArrayNotHasKey('secret_input', $fieldArray);
    }

    #[Test]
    public function extractUidFromGroupValueWithTablePrefix(): void
    {
        $reflection = new ReflectionClass($this->hook);
        $method = $reflection->getMethod('extractUidFromGroupValue');

        // Test table_uid format
        self::assertSame(123, $method->invoke($this->hook, 'be_users_123'));
        self::assertSame(456, $method->invoke($this->hook, 'pages_456'));
        self::assertSame(789, $method->invoke($this->hook, 'some_table_789'));
    }

    #[Test]
    public function extractUidFromGroupValueWithNumericString(): void
    {
        $reflection = new ReflectionClass($this->hook);
        $method = $reflection->getMethod('extractUidFromGroupValue');

        // Test plain numeric values
        self::assertSame(42, $method->invoke($this->hook, '42'));
        self::assertSame(0, $method->invoke($this->hook, '0'));
        self::assertSame(999, $method->invoke($this->hook, '999'));
    }

    #[Test]
    public function extractUidFromGroupValueWithInvalidFormat(): void
    {
        $reflection = new ReflectionClass($this->hook);
        $method = $reflection->getMethod('extractUidFromGroupValue');

        // Test non-numeric string
        self::assertSame(0, $method->invoke($this->hook, 'not_a_number'));
        self::assertSame(0, $method->invoke($this->hook, ''));
    }

    #[Test]
    public function nonAdminCreatingNewRecordCannotAssignForeignOwnerUid(): void
    {
        // Fresh hook with a NON-admin actor (uid 7); setUp() defaults to admin.
        // The actor holds secret.create — this test is about WHOSE name the
        // created record carries, not about whether it may be created.
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->method('isCurrentActorAdmin')->willReturn(false);
        $accessControl->method('getCurrentActorUid')->willReturn(7);
        $accessControl->method('canCreate')->willReturn(true);
        $accessControl->method('isGranted')->willReturn(true);

        $hook = new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $accessControl,
            $this->secretRepository,
        );

        $fieldArray = [
            'identifier' => 'test-secret',
            // Attempt to plant the secret as owned by user 42.
            'owner_uid' => 'be_users_42',
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        // owner_uid must be forced to the current backend user (7), not 42.
        self::assertIsArray($fieldArray);
        self::assertSame(7, $fieldArray['owner_uid']);
    }

    #[Test]
    public function nonAdminCreatingNewRecordWithoutOwnerUidStillGetsForcedOwnership(): void
    {
        // Regression: owner_uid is an excludefield, so a non-admin creator who
        // lacks that grant submits no owner_uid at all. The hook must STILL
        // force ownership to the current user — otherwise the column defaults
        // to 0 (ownerless) and the creator cannot manage their own secret.
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->method('isCurrentActorAdmin')->willReturn(false);
        $accessControl->method('getCurrentActorUid')->willReturn(7);
        $accessControl->method('canCreate')->willReturn(true);
        $accessControl->method('isGranted')->willReturn(true);

        $hook = new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $accessControl,
            $this->secretRepository,
        );

        $fieldArray = [
            'identifier' => 'test-secret',
            // No owner_uid submitted (excludefield absent for this user).
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        self::assertIsArray($fieldArray);
        self::assertSame(7, $fieldArray['owner_uid']);
    }

    #[Test]
    public function adminCreatingNewRecordKeepsSubmittedOwnerUid(): void
    {
        // setUp() default actor is admin → no coercion.
        $fieldArray = [
            'identifier' => 'test-secret',
            'owner_uid' => 'be_users_42',
        ];
        $dataHandler = $this->createMock(DataHandler::class);

        $this->hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'tx_nrvault_secret',
            'NEW123',
            $dataHandler,
        );

        self::assertIsArray($fieldArray);
        self::assertSame(42, $fieldArray['owner_uid']);
    }

    /**
     * The gate this suite exists for: a create whose value is empty never
     * reaches VaultService::store(), where both create gates live, so it has
     * to be refused before DataHandler inserts anything.
     */
    #[Test]
    public function preProcessRefusesAValuelessCreateWithoutTheSecretCreatePermission(): void
    {
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->method('isCurrentActorAdmin')->willReturn(false);
        $accessControl->method('getCurrentActorUid')->willReturn(7);
        $accessControl->method('canCreate')->willReturn(true);
        $accessControl->expects($this->once())
            ->method('isGranted')
            ->with(VaultPermission::SecretCreate)
            ->willReturn(false);

        // No value is submitted, so store() — and with it every gate inside
        // it — is never called. That is precisely the bypass under test.
        $this->vaultService->expects($this->never())->method('store');

        $this->auditService->expects($this->once())->method('log')->with(
            'squatted-identifier',
            'access_denied',
            false,
            'Create denied: missing secret.create permission',
        );

        $hook = new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $accessControl,
            $this->secretRepository,
        );

        $fieldArray = ['identifier' => 'squatted-identifier', 'description' => 'no value'];
        $messages = [];

        $hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            self::TABLE,
            'NEW123',
            $this->capturingDataHandler($messages),
        );

        // Nulling the by-ref array is what makes core skip the record (its
        // guard is is_array()); an empty array would still be inserted with
        // TCA defaults.
        self::assertNull($fieldArray, 'A refused create must invalidate the field array, not merely empty it.');
        self::assertSame(
            ['Vault secret creation requires the secret.create permission '
                . '(Create denied: missing secret.create permission) — the record was not created.'],
            $messages,
        );
    }

    /**
     * The coarser tier, checked first and audited under its own reason so an
     * operator can tell "may not use the vault at all" from "may use it but
     * not create".
     */
    #[Test]
    public function preProcessRefusesACreateWhenCanCreateDenies(): void
    {
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->method('isCurrentActorAdmin')->willReturn(false);
        $accessControl->method('getCurrentActorUid')->willReturn(7);
        $accessControl->method('canCreate')->willReturn(false);
        // The coarse tier already refused; the operation permission is not
        // consulted.
        $accessControl->expects($this->never())->method('isGranted');

        $this->auditService->expects($this->once())->method('log')->with(
            'denied-identifier',
            'access_denied',
            false,
            'Create access denied',
        );

        $hook = new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $accessControl,
            $this->secretRepository,
        );

        $fieldArray = ['identifier' => 'denied-identifier'];
        $messages = [];

        $hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            self::TABLE,
            'NEW1',
            $this->capturingDataHandler($messages),
        );

        self::assertNull($fieldArray);
        self::assertSame(
            ['Vault secret creation requires the secret.create permission '
                . '(Create access denied) — the record was not created.'],
            $messages,
        );
    }

    /**
     * A value-BEARING create by an unauthorized actor is refused by the same
     * gate, one step earlier than before: the row is never inserted, so it
     * cannot squat the identifier while the compensating revert runs.
     */
    #[Test]
    public function preProcessRefusesAValueBearingCreateWithoutTheSecretCreatePermission(): void
    {
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->method('isCurrentActorAdmin')->willReturn(false);
        $accessControl->method('getCurrentActorUid')->willReturn(7);
        $accessControl->method('canCreate')->willReturn(true);
        $accessControl->method('isGranted')->willReturn(false);

        $this->vaultService->expects($this->never())->method('store');

        $hook = new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $accessControl,
            $this->secretRepository,
        );

        $fieldArray = [
            'identifier' => 'value-bearing',
            'secret_input' => 'must-not-be-stored',
        ];
        $messages = [];

        $hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            self::TABLE,
            'NEW7',
            $this->capturingDataHandler($messages),
        );

        self::assertNull($fieldArray);
        // The refused value must not be parked for afterDatabaseOperations to
        // pick up — the record it belonged to will never exist.
        self::assertSame([], $this->readPrivate($hook, 'pendingSecrets'));
    }

    /**
     * The gate must not fire on an UPDATE: secret.create governs creation, and
     * an existing record's edit is governed by the privileged-column policy
     * and the metadata audit instead.
     */
    #[Test]
    public function preProcessDoesNotApplyTheCreateGateToAnExistingRecord(): void
    {
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->method('isCurrentActorAdmin')->willReturn(true);
        // Would refuse if it were consulted — an update must not consult it.
        $accessControl->method('canCreate')->willReturn(false);
        $accessControl->expects($this->never())->method('isGranted');

        // The update path snapshots the pre-change column values for the
        // compensating rollback, so it needs a readable record.
        $this->stubBackendRecords([['description' => 'stored']]);

        $hook = new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $accessControl,
            $this->secretRepository,
            $this->recordPool(),
        );

        $fieldArray = ['description' => 'edited'];
        $messages = [];

        $hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            self::TABLE,
            5,
            $this->capturingDataHandler($messages),
        );

        self::assertSame(['description' => 'edited'], $fieldArray);
        self::assertSame([], $messages);
    }

    /**
     * The gate is scoped to this extension's own table — every other table's
     * datamap must pass through untouched.
     */
    #[Test]
    public function preProcessDoesNotApplyTheCreateGateToAnotherTable(): void
    {
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->method('canCreate')->willReturn(false);
        $accessControl->expects($this->never())->method('isGranted');

        $hook = new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $accessControl,
            $this->secretRepository,
        );

        $fieldArray = ['title' => 'a page'];

        $hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            'pages',
            'NEW123',
            $this->createMock(DataHandler::class),
        );

        self::assertSame(['title' => 'a page'], $fieldArray);
    }

    /**
     * A granted creator passes both gates and keeps a value-less record —
     * which after this change is the only thing ValueLess can still mean.
     */
    #[Test]
    public function preProcessLetsAGrantedCreatorCreateAValuelessRecord(): void
    {
        $hook = $this->hookForNonAdmin(7);

        $this->auditService->expects($this->never())->method('log');

        $fieldArray = ['identifier' => 'allowed-identifier'];
        $messages = [];

        $hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            self::TABLE,
            'NEW123',
            $this->capturingDataHandler($messages),
        );

        self::assertIsArray($fieldArray);
        self::assertSame('allowed-identifier', $fieldArray['identifier']);
        // ... and the creator owns what they created.
        self::assertSame(7, $fieldArray['owner_uid']);
        self::assertSame([], $messages);
    }

    /**
     * A denial whose audit entry cannot be written must still deny — the
     * refusal is the security control, the audit entry is its record. The
     * failure is surfaced rather than swallowed.
     */
    #[Test]
    public function preProcessStillRefusesTheCreateWhenTheDenialAuditWriteFails(): void
    {
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->method('isCurrentActorAdmin')->willReturn(false);
        $accessControl->method('getCurrentActorUid')->willReturn(7);
        $accessControl->method('canCreate')->willReturn(true);
        $accessControl->method('isGranted')->willReturn(false);

        $this->auditService->method('log')->willThrowException(new RuntimeException('audit sink down'));

        $hook = new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $accessControl,
            $this->secretRepository,
        );

        $fieldArray = ['identifier' => 'audit-fails'];
        $messages = [];

        $hook->processDatamap_preProcessFieldArray(
            $fieldArray,
            self::TABLE,
            'NEW123',
            $this->capturingDataHandler($messages),
        );

        self::assertNull($fieldArray, 'An unauditable denial must still deny.');
        self::assertSame(
            [
                'Vault audit logging of the refused secret creation failed: audit sink down'
                . ' — the creation was refused regardless.',
                'Vault secret creation requires the secret.create permission '
                . '(Create denied: missing secret.create permission) — the record was not created.',
            ],
            $messages,
        );
    }

    #[Test]
    public function cmdmapPreProcessIgnoresUndeleteCommand(): void
    {
        $this->auditService->expects($this->never())->method('log');

        $this->hook->processCmdmap_preProcess('undelete', 'tx_nrvault_secret', 1);
    }

    #[Test]
    public function cmdmapPreProcessIgnoresMoveCommand(): void
    {
        $this->auditService->expects($this->never())->method('log');

        $this->hook->processCmdmap_preProcess('move', 'tx_nrvault_secret', 1);
    }

    #[Test]
    public function snapshotMmRelationsSkipsANewRecordWithoutTouchingTheDatabase(): void
    {
        $calls = [];
        $hook = $this->hookWith($this->queryBuilderPool([], $calls));

        self::assertSame([], $this->invokePrivate($hook, 'snapshotMmRelations', [0, ['allowed_groups']]));
        self::assertSame([], $calls, 'a record without a uid must not be read');
    }

    #[Test]
    public function snapshotMmRelationsYieldsNothingWithoutAConnectionPool(): void
    {
        // $this->hook is built without the optional ConnectionPool — the
        // rollback degrades to logging, so nothing may be snapshotted.
        self::assertSame(
            [],
            $this->invokePrivate($this->hook, 'snapshotMmRelations', [5, ['allowed_groups', 'write_groups']]),
        );
    }

    #[Test]
    public function snapshotMmRelationsOnlyReadsTheTiersTheSaveSubmits(): void
    {
        $calls = [];
        $pool = $this->queryBuilderPool([self::READ_GROUPS_MM => []], $calls);

        $snapshot = $this->invokePrivate(
            $this->hookWith($pool),
            'snapshotMmRelations',
            [5, ['allowed_groups', 'title']],
        );

        self::assertIsArray($snapshot);
        self::assertSame([self::READ_GROUPS_MM], array_keys($snapshot));
        self::assertContains(['from', self::READ_GROUPS_MM], $calls);
    }

    #[Test]
    public function snapshotMmRelationsReadsTheRecordsRowsInSortingOrder(): void
    {
        $calls = [];
        $pool = $this->queryBuilderPool([self::READ_GROUPS_MM => []], $calls);

        $this->invokePrivate($this->hookWith($pool), 'snapshotMmRelations', [5, ['allowed_groups']]);

        // `sorting` is part of the identity of the restored state: the same
        // groups in a different order are a different record.
        self::assertContains(['select', ['uid_foreign', 'sorting', 'sorting_foreign']], $calls);
        self::assertContains(['orderBy', 'sorting', 'ASC'], $calls);
        self::assertContains(['createNamedParameter', 5, Connection::PARAM_INT], $calls);
    }

    #[Test]
    public function snapshotMmRelationsOmitsATierWhoseReadFails(): void
    {
        $calls = [];
        $pool = $this->queryBuilderPool([
            self::READ_GROUPS_MM => new RuntimeException('mm read failed'),
            self::WRITE_GROUPS_MM => [['uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0]],
        ], $calls);

        $snapshot = $this->invokePrivate(
            $this->hookWith($pool),
            'snapshotMmRelations',
            [5, ['allowed_groups', 'write_groups']],
        );

        self::assertIsArray($snapshot);
        // Absent, NOT an empty list: an empty entry would be "restored" by
        // deleting the tier's real relations.
        self::assertArrayNotHasKey(self::READ_GROUPS_MM, $snapshot);
        self::assertSame(
            [['uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0]],
            $snapshot[self::WRITE_GROUPS_MM],
        );
    }

    #[Test]
    public function snapshotMmRelationsCoercesNonNumericRowValuesToZero(): void
    {
        $calls = [];
        $pool = $this->queryBuilderPool([
            self::READ_GROUPS_MM => [['uid_foreign' => '7', 'sorting' => null, 'sorting_foreign' => 'x']],
        ], $calls);

        $snapshot = $this->invokePrivate($this->hookWith($pool), 'snapshotMmRelations', [5, ['allowed_groups']]);

        self::assertIsArray($snapshot);
        self::assertSame(
            [['uid_foreign' => 7, 'sorting' => 0, 'sorting_foreign' => 0]],
            $snapshot[self::READ_GROUPS_MM],
        );
    }

    #[Test]
    public function restoreMmRelationsRefusesARecordWithoutAUid(): void
    {
        $calls = [];
        $pool = $this->poolWith([self::READ_GROUPS_MM => $this->recordingConnection($calls)]);

        $restored = $this->invokePrivate(
            $this->hookWith($pool),
            'restoreMmRelations',
            [0, [self::READ_GROUPS_MM => []]],
        );

        self::assertFalse($restored);
        self::assertSame([], $calls);
    }

    #[Test]
    public function restoreMmRelationsRefusesWithoutAConnectionPool(): void
    {
        self::assertFalse(
            $this->invokePrivate($this->hook, 'restoreMmRelations', [5, [self::READ_GROUPS_MM => []]]),
        );
    }

    #[Test]
    public function restoreMmRelationsReplacesATierInsideOneTransaction(): void
    {
        $calls = [];
        $pool = $this->poolWith([self::READ_GROUPS_MM => $this->recordingConnection($calls)]);

        $restored = $this->invokePrivate($this->hookWith($pool), 'restoreMmRelations', [5, [
            self::READ_GROUPS_MM => [
                ['uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0],
                ['uid_foreign' => 9, 'sorting' => 2, 'sorting_foreign' => 0],
            ],
        ]]);

        self::assertTrue($restored);
        // Order matters twice over: the delete must precede the inserts, and
        // both must sit inside the transaction — a failed insert after a
        // committed delete would leave the tier empty.
        self::assertSame([
            ['transactional'],
            ['delete', self::READ_GROUPS_MM, ['uid_local' => 5]],
            ['insert', self::READ_GROUPS_MM, ['uid_local' => 5, 'uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0]],
            ['insert', self::READ_GROUPS_MM, ['uid_local' => 5, 'uid_foreign' => 9, 'sorting' => 2, 'sorting_foreign' => 0]],
        ], $calls);
    }

    #[Test]
    public function restoreMmRelationsHonoursAnEmptyTierByDeletingWhatTheChangeAdded(): void
    {
        $calls = [];
        $pool = $this->poolWith([self::WRITE_GROUPS_MM => $this->recordingConnection($calls)]);

        $restored = $this->invokePrivate(
            $this->hookWith($pool),
            'restoreMmRelations',
            [5, [self::WRITE_GROUPS_MM => []]],
        );

        self::assertTrue($restored);
        self::assertSame([
            ['transactional'],
            ['delete', self::WRITE_GROUPS_MM, ['uid_local' => 5]],
        ], $calls);
    }

    #[Test]
    public function restoreMmRelationsReportsFailureYetStillRestoresTheOtherTier(): void
    {
        $failingCalls = [];
        $healthyCalls = [];
        $pool = $this->poolWith([
            self::READ_GROUPS_MM => $this->recordingConnection(
                $failingCalls,
                transactionFailure: new RuntimeException('transaction rolled back'),
            ),
            self::WRITE_GROUPS_MM => $this->recordingConnection($healthyCalls),
        ]);

        $restored = $this->invokePrivate($this->hookWith($pool), 'restoreMmRelations', [5, [
            self::READ_GROUPS_MM => [['uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0]],
            self::WRITE_GROUPS_MM => [['uid_foreign' => 4, 'sorting' => 1, 'sorting_foreign' => 0]],
        ]]);

        self::assertFalse($restored);
        // The rolled-back tier keeps its current rows — no half-write leaked.
        self::assertSame([['transactional']], $failingCalls);
        self::assertSame([
            ['transactional'],
            ['delete', self::WRITE_GROUPS_MM, ['uid_local' => 5]],
            ['insert', self::WRITE_GROUPS_MM, ['uid_local' => 5, 'uid_foreign' => 4, 'sorting' => 1, 'sorting_foreign' => 0]],
        ], $healthyCalls);
    }

    #[Test]
    public function purgeMmRelationsRefusesARecordWithoutAUid(): void
    {
        $calls = [];
        $pool = $this->poolWith([self::READ_GROUPS_MM => $this->recordingConnection($calls)]);

        self::assertFalse($this->invokePrivate($this->hookWith($pool), 'purgeMmRelations', [0]));
        self::assertSame([], $calls);
    }

    #[Test]
    public function purgeMmRelationsRefusesWithoutAConnectionPool(): void
    {
        self::assertFalse($this->invokePrivate($this->hook, 'purgeMmRelations', [5]));
    }

    #[Test]
    public function purgeMmRelationsDeletesTheRecordsRowsInBothTiers(): void
    {
        $calls = [];
        $connection = $this->recordingConnection($calls);
        $pool = $this->poolWith([
            self::READ_GROUPS_MM => $connection,
            self::WRITE_GROUPS_MM => $connection,
        ]);

        self::assertTrue($this->invokePrivate($this->hookWith($pool), 'purgeMmRelations', [5]));
        self::assertSame([
            ['delete', self::READ_GROUPS_MM, ['uid_local' => 5]],
            ['delete', self::WRITE_GROUPS_MM, ['uid_local' => 5]],
        ], $calls);
    }

    #[Test]
    public function purgeMmRelationsReportsFailureYetStillPurgesTheOtherTier(): void
    {
        $failingCalls = [];
        $healthyCalls = [];
        $pool = $this->poolWith([
            self::READ_GROUPS_MM => $this->recordingConnection(
                $failingCalls,
                writeFailure: new RuntimeException('delete refused'),
            ),
            self::WRITE_GROUPS_MM => $this->recordingConnection($healthyCalls),
        ]);

        self::assertFalse($this->invokePrivate($this->hookWith($pool), 'purgeMmRelations', [5]));
        self::assertSame([['delete', self::WRITE_GROUPS_MM, ['uid_local' => 5]]], $healthyCalls);
    }

    #[Test]
    public function revertRowRefusesARecordWithoutAUid(): void
    {
        $calls = [];
        $pool = $this->poolWith([self::TABLE => $this->recordingConnection($calls)]);

        self::assertFalse($this->invokePrivate($this->hookWith($pool), 'revertRow', [0, null]));
        self::assertSame([], $calls);
    }

    #[Test]
    public function revertRowRefusesWithoutAConnectionPool(): void
    {
        self::assertFalse($this->invokePrivate($this->hook, 'revertRow', [5, null]));
    }

    #[Test]
    public function revertRowRemovesTheRecordWhenNoOriginalValuesWereCaptured(): void
    {
        $calls = [];
        $pool = $this->poolWith([self::TABLE => $this->recordingConnection($calls)]);

        self::assertTrue($this->invokePrivate($this->hookWith($pool), 'revertRow', [5, null]));
        self::assertSame([['delete', self::TABLE, ['uid' => 5]]], $calls);
    }

    #[Test]
    public function revertRowRefusesAnEmptyValueMapWithoutWriting(): void
    {
        $calls = [];
        $pool = $this->poolWith([self::TABLE => $this->recordingConnection($calls)]);

        // An empty map is not "restore nothing" — it is a failed capture, and
        // writing it would delete every column value.
        self::assertFalse($this->invokePrivate($this->hookWith($pool), 'revertRow', [5, []]));
        self::assertSame([], $calls);
    }

    #[Test]
    public function revertRowRestoresTheCapturedColumnValues(): void
    {
        $calls = [];
        $pool = $this->poolWith([self::TABLE => $this->recordingConnection($calls)]);

        $reverted = $this->invokePrivate(
            $this->hookWith($pool),
            'revertRow',
            [5, ['owner_uid' => 12, 'frontend_accessible' => 0]],
        );

        self::assertTrue($reverted);
        self::assertSame(
            [['update', self::TABLE, ['owner_uid' => 12, 'frontend_accessible' => 0], ['uid' => 5]]],
            $calls,
        );
    }

    #[Test]
    public function revertRowReportsFailureWhenTheWriteThrows(): void
    {
        $calls = [];
        $pool = $this->poolWith([
            self::TABLE => $this->recordingConnection($calls, writeFailure: new RuntimeException('write refused')),
        ]);

        self::assertFalse($this->invokePrivate($this->hookWith($pool), 'revertRow', [5, ['owner_uid' => 12]]));
    }

    #[Test]
    public function metadataAuditFailureReportsTheChangeAsRevertedWhenRowAndRelationsAreRestored(): void
    {
        $this->auditService->method('log')->willThrowException(new RuntimeException('audit sink down'));

        $calls = [];
        $connection = $this->recordingConnection($calls);
        $pool = $this->poolWith([
            self::TABLE => $connection,
            self::READ_GROUPS_MM => $connection,
            self::WRITE_GROUPS_MM => $connection,
        ]);

        $messages = [];
        $this->invokePrivate($this->hookWith($pool), 'auditMetadataUpdateOrCompensate', [
            'api/token',
            5,
            ['allowed_groups', 'write_groups'],
            ['allowed_groups' => 1, 'write_groups' => 0],
            [
                self::READ_GROUPS_MM => [['uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0]],
                self::WRITE_GROUPS_MM => [],
            ],
            $this->capturingDataHandler($messages),
        ]);

        self::assertCount(1, $messages);
        self::assertStringContainsString('audit sink down', $messages[0]);
        self::assertStringContainsString('was reverted (no mutation may persist without an audit entry).', $messages[0]);
    }

    #[Test]
    public function metadataAuditFailureIsNotRevertibleWhenAChangedAclTierIsMissingFromTheSnapshot(): void
    {
        $this->auditService->method('log')->willThrowException(new RuntimeException('audit sink down'));

        $calls = [];
        $pool = $this->poolWith([self::TABLE => $this->recordingConnection($calls)]);

        $messages = [];
        $this->invokePrivate($this->hookWith($pool), 'auditMetadataUpdateOrCompensate', [
            'api/token',
            5,
            ['allowed_groups'],
            ['allowed_groups' => 1],
            // Snapshot read failed for the changed tier: no entry at all.
            [],
            $this->capturingDataHandler($messages),
        ]);

        self::assertCount(1, $messages);
        self::assertStringContainsString('NOT revertible; manual reconciliation required.', $messages[0]);
        // The row half DID succeed — proving the verdict comes from the
        // missing relation snapshot, not from a failed row revert.
        self::assertSame(
            [['update', self::TABLE, ['allowed_groups' => 1], ['uid' => 5]]],
            $calls,
        );
    }

    #[Test]
    public function metadataAuditFailureIsNotRevertibleWhenARelationTierCannotBeRestored(): void
    {
        $this->auditService->method('log')->willThrowException(new RuntimeException('audit sink down'));

        $rowCalls = [];
        $pool = $this->poolWith([
            self::TABLE => $this->recordingConnection($rowCalls),
            self::READ_GROUPS_MM => $this->recordingConnection(
                $rowCalls,
                transactionFailure: new RuntimeException('transaction rolled back'),
            ),
        ]);

        $messages = [];
        $this->invokePrivate($this->hookWith($pool), 'auditMetadataUpdateOrCompensate', [
            'api/token',
            5,
            ['allowed_groups'],
            ['allowed_groups' => 1],
            [self::READ_GROUPS_MM => [['uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0]]],
            $this->capturingDataHandler($messages),
        ]);

        self::assertCount(1, $messages);
        self::assertStringContainsString('NOT revertible; manual reconciliation required.', $messages[0]);
    }

    #[Test]
    public function afterAllOperationsPurgesTheRelationsOfARevertedCreationSilently(): void
    {
        $calls = [];
        $connection = $this->recordingConnection($calls);
        $hook = $this->hookWith($this->poolWith([
            self::READ_GROUPS_MM => $connection,
            self::WRITE_GROUPS_MM => $connection,
        ]));
        $this->queueRevertedCreation($hook, 5);

        $messages = [];
        $hook->processDatamap_afterAllOperations($this->capturingDataHandler($messages));

        self::assertSame([
            ['delete', self::READ_GROUPS_MM, ['uid_local' => 5]],
            ['delete', self::WRITE_GROUPS_MM, ['uid_local' => 5]],
        ], $calls);
        self::assertSame([], $messages);
    }

    #[Test]
    public function afterAllOperationsLogsAnUnpurgeableRevertedCreationOnce(): void
    {
        $calls = [];
        $hook = $this->hookWith($this->poolWith([
            self::READ_GROUPS_MM => $this->recordingConnection($calls, writeFailure: new RuntimeException('delete refused')),
            self::WRITE_GROUPS_MM => $this->recordingConnection($calls),
        ]));
        $this->queueRevertedCreation($hook, 5);

        $messages = [];
        $hook->processDatamap_afterAllOperations($this->capturingDataHandler($messages));

        self::assertCount(1, $messages);
        self::assertStringContainsString('could not be purged; manual reconciliation required.', $messages[0]);

        // The queue is consumed: a second run of a DI-shared instance must not
        // re-log the same uid.
        $secondRun = [];
        $hook->processDatamap_afterAllOperations($this->capturingDataHandler($secondRun));
        self::assertSame([], $secondRun);
    }

    #[Test]
    public function creationAuditFailureRevertsTheRowAndQueuesItsRelationsForPurging(): void
    {
        $this->auditService->method('log')->willThrowException(new RuntimeException('audit sink down'));

        $calls = [];
        $connection = $this->recordingConnection($calls);
        $hook = $this->hookWith($this->poolWith([
            self::TABLE => $connection,
            self::READ_GROUPS_MM => $connection,
            self::WRITE_GROUPS_MM => $connection,
        ]));

        $messages = [];
        $this->invokePrivate($hook, 'auditRecordCreationOrCompensate', [
            'api/token',
            5,
            ['identifier' => 'api/token'],
            $this->capturingDataHandler($messages),
        ]);

        self::assertCount(1, $messages);
        self::assertStringContainsString('was reverted', $messages[0]);

        // DataHandler writes the record's MM rows only after this hook has
        // run, so the purge is queued rather than performed here.
        self::assertSame([5 => true], $this->readPrivate($hook, 'revertedCreations'));

        $purgeMessages = [];
        $hook->processDatamap_afterAllOperations($this->capturingDataHandler($purgeMessages));
        self::assertSame([], $purgeMessages);
        self::assertSame([
            ['delete', self::TABLE, ['uid' => 5]],
            ['delete', self::READ_GROUPS_MM, ['uid_local' => 5]],
            ['delete', self::WRITE_GROUPS_MM, ['uid_local' => 5]],
        ], $calls);
    }

    #[Test]
    public function creationAuditFailureQueuesNoPurgeWhenTheRowSurvives(): void
    {
        $this->auditService->method('log')->willThrowException(new RuntimeException('audit sink down'));

        $calls = [];
        $pool = $this->poolWith([
            self::TABLE => $this->recordingConnection($calls, writeFailure: new RuntimeException('delete refused')),
        ]);
        $hook = $this->hookWith($pool);

        $messages = [];
        $this->invokePrivate($hook, 'auditRecordCreationOrCompensate', [
            'api/token',
            5,
            ['identifier' => 'api/token'],
            $this->capturingDataHandler($messages),
        ]);

        self::assertCount(1, $messages);
        self::assertStringContainsString('NOT revertible', $messages[0]);

        // The record still exists, so its relations rightfully belong to it
        // and nothing is queued for purging.
        self::assertSame([], $this->readPrivate($hook, 'revertedCreations'));

        $purgeMessages = [];
        $hook->processDatamap_afterAllOperations($this->capturingDataHandler($purgeMessages));
        self::assertSame([], $purgeMessages);
        self::assertSame([], $calls);
    }

    #[Test]
    public function preProcessSnapshotsTheRelationsOfEverySubmittedAclTier(): void
    {
        $this->stubBackendRecords([['allowed_groups' => 2]]);

        $queryCalls = [];
        $hook = $this->hookWith($this->queryBuilderPool([
            self::READ_GROUPS_MM => [['uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0]],
        ], $queryCalls));

        $fieldArray = ['allowed_groups' => '3,4'];
        $dataHandler = $this->createMock(DataHandler::class);
        $hook->processDatamap_preProcessFieldArray($fieldArray, self::TABLE, 5, $dataHandler);

        // DataHandler replaces the MM rows during checkValue(), i.e. before
        // afterDatabaseOperations() — only a snapshot taken here can restore
        // the pre-change ACL.
        self::assertSame(
            [self::READ_GROUPS_MM => [['uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0]]],
            $this->readPrivate($hook, 'originalMmRelations')['5'] ?? null,
        );
    }

    #[Test]
    public function preProcessDropsAnMmBackedAclChangeSubmittedByANonOwner(): void
    {
        $this->stubBackendRecords([['owner_uid' => 99, 'frontend_accessible' => 0, 'scope_pid' => 0]]);

        $hook = $this->hookForNonAdmin(7, connectionPool: $this->recordPool());

        $fieldArray = ['allowed_groups' => '3,4'];
        $messages = [];
        $hook->processDatamap_preProcessFieldArray($fieldArray, self::TABLE, 5, $this->capturingDataHandler($messages));

        // Dropped, not reverted: the row column holds only the relation count,
        // so leaving it out makes DataHandler keep the existing MM rows.
        self::assertSame([], $fieldArray);
        self::assertCount(1, $messages);
        self::assertStringContainsString('can only be changed by an administrator', $messages[0]);
    }

    #[Test]
    public function preProcessRevertsAScalarAclChangeSubmittedByANonOwner(): void
    {
        // Two reads: the ACL gate, then the pre-change metadata capture.
        $this->stubBackendRecords([
            ['owner_uid' => 99, 'frontend_accessible' => 0, 'scope_pid' => 0],
            ['owner_uid' => 99],
        ]);

        $hook = $this->hookForNonAdmin(7, connectionPool: $this->recordPool());

        $fieldArray = ['owner_uid' => 'be_users_7'];
        $messages = [];
        $hook->processDatamap_preProcessFieldArray($fieldArray, self::TABLE, 5, $this->capturingDataHandler($messages));

        self::assertSame(['owner_uid' => 99], $fieldArray);
        self::assertCount(1, $messages);
    }

    #[Test]
    public function preProcessLeavesAnUnchangedScalarAclColumnAlone(): void
    {
        // An ordinary save by a non-owner resubmits the stored owner in group
        // notation — that is not tampering and must not be logged as such.
        $this->stubBackendRecords([
            ['owner_uid' => 99, 'frontend_accessible' => 0, 'scope_pid' => 0],
            ['owner_uid' => 99],
        ]);

        $hook = $this->hookForNonAdmin(7, connectionPool: $this->recordPool());

        $fieldArray = ['owner_uid' => 'be_users_99'];
        $messages = [];
        $hook->processDatamap_preProcessFieldArray($fieldArray, self::TABLE, 5, $this->capturingDataHandler($messages));

        self::assertIsArray($fieldArray);
        self::assertSame(99, $fieldArray['owner_uid']);
        self::assertSame([], $messages);
    }

    #[Test]
    public function preProcessLetsTheOwnerWithTheManagePolicyGrantChangeTheAcl(): void
    {
        $this->stubBackendRecords([
            ['owner_uid' => 7, 'frontend_accessible' => 0, 'scope_pid' => 0],
            ['allowed_groups' => 1],
        ]);

        $queryCalls = [];
        $hook = $this->hookForNonAdmin(7, canManagePolicy: true, connectionPool: $this->queryBuilderPool(
            [self::READ_GROUPS_MM => []],
            $queryCalls,
        ));

        $fieldArray = ['allowed_groups' => '3,4'];
        $messages = [];
        $hook->processDatamap_preProcessFieldArray($fieldArray, self::TABLE, 5, $this->capturingDataHandler($messages));

        self::assertSame(['allowed_groups' => '3,4'], $fieldArray);
        self::assertSame([], $messages);
    }

    #[Test]
    public function afterDatabaseOperationsAuditsAMetadataOnlyChange(): void
    {
        $this->stubBackendRecords([['identifier' => 'api/token', 'owner_uid' => 1, 'allowed_groups' => 1, 'scope_pid' => 0]]);

        $this->auditService
            ->expects(self::once())
            ->method('log')
            ->with('api/token', 'metadata_update', true, null, 'FormEngine edit: allowed_groups, frontend_accessible');

        $this->hookWith($this->recordPool())->processDatamap_afterDatabaseOperations(
            'update',
            self::TABLE,
            5,
            ['allowed_groups' => 2, 'frontend_accessible' => 1],
            $this->createMock(DataHandler::class),
        );
    }

    #[Test]
    public function afterDatabaseOperationsSkipsTheAuditWhenNoColumnWasSubmitted(): void
    {
        $this->stubBackendRecords([['identifier' => 'api/token']]);

        $this->auditService->expects(self::never())->method('log');

        $this->hookWith($this->recordPool())->processDatamap_afterDatabaseOperations(
            'update',
            self::TABLE,
            5,
            [],
            $this->createMock(DataHandler::class),
        );
    }

    #[Test]
    public function afterDatabaseOperationsStopsWhenTheRecordIsGone(): void
    {
        $this->stubBackendRecords([false]);

        $this->auditService->expects(self::never())->method('log');

        $this->hookWith($this->recordPool())->processDatamap_afterDatabaseOperations(
            'update',
            self::TABLE,
            5,
            ['allowed_groups' => 2],
            $this->createMock(DataHandler::class),
        );
    }

    #[Test]
    public function recordReadsSelectTheRequestedColumnsOfOneLiveRecord(): void
    {
        $this->stubBackendRecords([['identifier' => 'api/token']]);

        $this->hookWith($this->recordPool())->processDatamap_afterDatabaseOperations(
            'update',
            self::TABLE,
            5,
            [],
            $this->createMock(DataHandler::class),
        );

        // BackendUtility::getRecord() semantics, spelled out so they hold on
        // every supported core version: all restrictions dropped, soft-deleted
        // rows excluded by an explicit predicate, one uid, bound as integers.
        self::assertSame([
            ['removeAll'],
            ['select', ['identifier', 'owner_uid', 'allowed_groups', 'scope_pid']],
            ['from', self::TABLE],
            ['createNamedParameter', 5, Connection::PARAM_INT],
            ['createNamedParameter', 0, Connection::PARAM_INT],
            ['where', ['uid = 5', 'deleted = 0']],
        ], $this->recordReads);
    }

    #[Test]
    public function afterDatabaseOperationsCompensatesAFailedMetadataAuditWithTheCapturedState(): void
    {
        // One read for the pre-change capture, one for the post-write lookup.
        $this->stubBackendRecords([
            ['allowed_groups' => 1],
            ['identifier' => 'api/token', 'owner_uid' => 1, 'allowed_groups' => 2, 'scope_pid' => 0],
        ]);
        $this->auditService->method('log')->willThrowException(new RuntimeException('audit sink down'));

        $writes = [];
        $reads = [];
        $connection = $this->recordingConnection($writes);
        $pool = self::createStub(ConnectionPool::class);
        $pool->method('getConnectionForTable')->willReturn($connection);
        $pool->method('getQueryBuilderForTable')->willReturnCallback($this->queryBuilderFactory(
            [self::READ_GROUPS_MM => [['uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0]]],
            $reads,
        ));
        $hook = $this->hookWith($pool);

        $fieldArray = ['allowed_groups' => '3,4'];
        $dataHandler = $this->createMock(DataHandler::class);
        $hook->processDatamap_preProcessFieldArray($fieldArray, self::TABLE, 5, $dataHandler);
        self::assertIsArray($fieldArray);

        $messages = [];
        $hook->processDatamap_afterDatabaseOperations(
            'update',
            self::TABLE,
            5,
            $fieldArray,
            $this->capturingDataHandler($messages),
        );

        self::assertCount(1, $messages);
        self::assertStringContainsString('was reverted', $messages[0]);
        // Both halves of the rollback ran: the row columns AND the MM rows the
        // widened ACL replaced.
        self::assertSame([
            ['update', self::TABLE, ['allowed_groups' => 1], ['uid' => 5]],
            ['transactional'],
            ['delete', self::READ_GROUPS_MM, ['uid_local' => 5]],
            ['insert', self::READ_GROUPS_MM, ['uid_local' => 5, 'uid_foreign' => 3, 'sorting' => 1, 'sorting_foreign' => 0]],
        ], $writes);
    }

    /**
     * Build the hook with the optional ConnectionPool wired, leaving the
     * services from setUp() in place.
     */
    private function hookWith(ConnectionPool $connectionPool): SecretTcaHook
    {
        return new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $this->accessControlService,
            $this->secretRepository,
            $connectionPool,
        );
    }

    /**
     * @param list<mixed> $arguments
     */
    private function invokePrivate(SecretTcaHook $hook, string $method, array $arguments): mixed
    {
        return (new ReflectionClass($hook))->getMethod($method)->invokeArgs($hook, $arguments);
    }

    /**
     * Queue $uid as a creation this hook rolled back, the state
     * processDatamap_afterAllOperations() acts on.
     */
    private function queueRevertedCreation(SecretTcaHook $hook, int $uid): void
    {
        $property = (new ReflectionClass($hook))->getProperty('revertedCreations');
        $property->setValue($hook, [$uid => true]);
    }

    /**
     * A connection that appends every write to $calls, so a test can assert
     * what was written and in which order — not merely that something was.
     *
     * @param list<array<int, mixed>> $calls
     */
    private function recordingConnection(
        array &$calls,
        ?Throwable $transactionFailure = null,
        ?Throwable $writeFailure = null,
    ): Connection&MockObject {
        $connection = $this->createMock(Connection::class);

        $connection->method('transactional')->willReturnCallback(
            static function (Closure $callback) use (&$calls, $transactionFailure): mixed {
                $calls[] = ['transactional'];
                if ($transactionFailure instanceof Throwable) {
                    throw $transactionFailure;
                }

                return $callback();
            },
        );

        $connection->method('delete')->willReturnCallback(
            static function (string $table, array $identifier) use (&$calls, $writeFailure): int {
                if ($writeFailure instanceof Throwable) {
                    throw $writeFailure;
                }
                $calls[] = ['delete', $table, $identifier];

                return 1;
            },
        );

        $connection->method('insert')->willReturnCallback(
            static function (string $table, array $data) use (&$calls, $writeFailure): int {
                if ($writeFailure instanceof Throwable) {
                    throw $writeFailure;
                }
                $calls[] = ['insert', $table, $data];

                return 1;
            },
        );

        $connection->method('update')->willReturnCallback(
            static function (string $table, array $data, array $identifier) use (&$calls, $writeFailure): int {
                if ($writeFailure instanceof Throwable) {
                    throw $writeFailure;
                }
                $calls[] = ['update', $table, $data, $identifier];

                return 1;
            },
        );

        return $connection;
    }

    /**
     * @param array<string, Connection> $connections table => connection; a request for any
     *                                               other table fails the test
     */
    private function poolWith(array $connections): ConnectionPool
    {
        $pool = self::createStub(ConnectionPool::class);
        $pool->method('getConnectionForTable')->willReturnCallback(
            static function (string $table) use ($connections): Connection {
                self::assertArrayHasKey($table, $connections, 'unexpected connection request for ' . $table);

                return $connections[$table];
            },
        );

        return $pool;
    }

    /**
     * A pool whose query builders return the configured rows per table (or
     * raise the configured failure), recording the query shape into $calls.
     *
     * @param array<string, list<array<string, mixed>>|Throwable> $outcomes
     * @param list<array<int, mixed>> $calls
     */
    private function queryBuilderPool(array $outcomes, array &$calls): ConnectionPool
    {
        $pool = self::createStub(ConnectionPool::class);
        $pool->method('getQueryBuilderForTable')->willReturnCallback($this->queryBuilderFactory($outcomes, $calls));

        return $pool;
    }

    /**
     * The `getQueryBuilderForTable()` implementation behind
     * {@see queryBuilderPool()}, reusable where the pool also has to serve
     * connections.
     *
     * @param array<string, list<array<string, mixed>>|Throwable> $outcomes
     * @param list<array<int, mixed>> $calls
     *
     * @return Closure(string): QueryBuilder
     */
    private function queryBuilderFactory(array $outcomes, array &$calls): Closure
    {
        return function (string $table) use ($outcomes, &$calls): QueryBuilder {
            // The secret table is only ever queried by the hook's record read;
            // the MM tables these outcomes describe are queried by the
            // relation snapshot.
            if ($table === self::TABLE) {
                return $this->recordQueryBuilder();
            }

            self::assertArrayHasKey($table, $outcomes, 'unexpected query builder request for ' . $table);
            $outcome = $outcomes[$table];

            $result = self::createStub(Result::class);
            if (!$outcome instanceof Throwable) {
                $result->method('fetchAllAssociative')->willReturn($outcome);
            }

            $expression = self::createStub(ExpressionBuilder::class);
            $expression->method('eq')->willReturn('uid_local = :p');

            $queryBuilder = $this->createMock(QueryBuilder::class);
            $queryBuilder->method('expr')->willReturn($expression);
            $queryBuilder->method('where')->willReturnSelf();
            $queryBuilder->method('createNamedParameter')->willReturnCallback(
                static function (mixed $value, mixed $type) use (&$calls): string {
                    $calls[] = ['createNamedParameter', $value, $type];

                    return ':p';
                },
            );
            $queryBuilder->method('select')->willReturnCallback(
                static function (string ...$fields) use ($queryBuilder, &$calls): QueryBuilder {
                    $calls[] = ['select', $fields];

                    return $queryBuilder;
                },
            );
            $queryBuilder->method('from')->willReturnCallback(
                static function (string $from) use ($queryBuilder, &$calls): QueryBuilder {
                    $calls[] = ['from', $from];

                    return $queryBuilder;
                },
            );
            $queryBuilder->method('orderBy')->willReturnCallback(
                static function (string $fieldName, ?string $order) use ($queryBuilder, &$calls): QueryBuilder {
                    $calls[] = ['orderBy', $fieldName, $order];

                    return $queryBuilder;
                },
            );
            $queryBuilder->method('executeQuery')->willReturnCallback(
                static function () use ($outcome, $result): Result {
                    if ($outcome instanceof Throwable) {
                        throw $outcome;
                    }

                    return $result;
                },
            );

            return $queryBuilder;
        };
    }

    /**
     * Queue the rows the hook's record reads resolve to, in the order the
     * exercised path performs them (`false` = record gone). The queue is
     * served through the hook's injected ConnectionPool, so the stub is
     * independent of which TYPO3 version's `BackendUtility` internals are
     * installed. tearDown() fails a test that queues more reads than the
     * path performs.
     *
     * @param list<array<string, mixed>|false> $rows
     */
    private function stubBackendRecords(array $rows): void
    {
        $this->backendRecords = [...$this->backendRecords, ...$rows];
    }

    /**
     * A pool that serves nothing but the hook's record reads.
     */
    private function recordPool(): ConnectionPool
    {
        $pool = self::createStub(ConnectionPool::class);
        $pool->method('getQueryBuilderForTable')->willReturnCallback(
            function (string $table): QueryBuilder {
                self::assertSame(self::TABLE, $table, 'unexpected query builder request for ' . $table);

                return $this->recordQueryBuilder();
            },
        );

        return $pool;
    }

    /**
     * A query builder for the secret table answering with the next row
     * {@see stubBackendRecords()} queued, recording the query shape into
     * $recordReads so a test can pin the read itself, not merely its result.
     */
    private function recordQueryBuilder(): QueryBuilder
    {
        self::assertNotSame([], $this->backendRecords, 'unexpected record read on ' . self::TABLE);
        $row = array_shift($this->backendRecords);

        $result = self::createStub(Result::class);
        $result->method('fetchAssociative')->willReturn($row);

        $restrictions = $this->createMock(QueryRestrictionContainerInterface::class);
        $restrictions->method('removeAll')->willReturnCallback(
            function () use ($restrictions): QueryRestrictionContainerInterface {
                $this->recordReads[] = ['removeAll'];

                return $restrictions;
            },
        );

        // Render the placeholder as the bound value so the recorded
        // predicates read as `uid = 5` / `deleted = 0`.
        $expression = self::createStub(ExpressionBuilder::class);
        $expression->method('eq')->willReturnCallback(
            static fn (string $fieldName, string $value): string => $fieldName . ' = ' . $value,
        );

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('getRestrictions')->willReturn($restrictions);
        $queryBuilder->method('expr')->willReturn($expression);
        $queryBuilder->method('executeQuery')->willReturn($result);
        $queryBuilder->method('createNamedParameter')->willReturnCallback(
            function (int $value, mixed $type): string {
                $this->recordReads[] = ['createNamedParameter', $value, $type];

                return (string) $value;
            },
        );
        $queryBuilder->method('select')->willReturnCallback(
            function (string ...$fields) use ($queryBuilder): QueryBuilder {
                $this->recordReads[] = ['select', $fields];

                return $queryBuilder;
            },
        );
        $queryBuilder->method('from')->willReturnCallback(
            function (string $from) use ($queryBuilder): QueryBuilder {
                $this->recordReads[] = ['from', $from];

                return $queryBuilder;
            },
        );
        $queryBuilder->method('where')->willReturnCallback(
            function (string ...$predicates) use ($queryBuilder): QueryBuilder {
                $this->recordReads[] = ['where', $predicates];

                return $queryBuilder;
            },
        );

        return $queryBuilder;
    }

    /**
     * A hook whose actor is a plain backend user — setUp() defaults to an
     * admin, which short-circuits the privileged-column policy.
     */
    private function hookForNonAdmin(
        int $actorUid,
        bool $canManagePolicy = false,
        ?ConnectionPool $connectionPool = null,
        bool $canCreate = true,
    ): SecretTcaHook {
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->method('isCurrentActorAdmin')->willReturn(false);
        $accessControl->method('getCurrentActorUid')->willReturn($actorUid);
        $accessControl->method('canCreate')->willReturn($canCreate);
        // Each gate answers for its own permission — a path that asked for the
        // wrong one falls to `false` and fails the test that expects it to
        // pass, so the permission identity stays asserted.
        $accessControl->method('isGranted')->willReturnCallback(
            static fn (VaultPermission $permission): bool => match ($permission) {
                VaultPermission::SecretManagePolicy => $canManagePolicy,
                VaultPermission::SecretCreate => $canCreate,
                default => false,
            },
        );

        return new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $accessControl,
            $this->secretRepository,
            $connectionPool,
        );
    }

    /**
     * @return array<array-key, mixed>
     */
    private function readPrivate(SecretTcaHook $hook, string $property): array
    {
        $value = (new ReflectionClass($hook))->getProperty($property)->getValue($hook);
        self::assertIsArray($value);

        return $value;
    }

    /**
     * A DataHandler whose log() messages are collected for assertion.
     *
     * @param list<string> $messages
     */
    private function capturingDataHandler(array &$messages): DataHandler&MockObject
    {
        $dataHandler = $this->createMock(DataHandler::class);
        $dataHandler->method('log')->willReturnCallback(
            static function (
                string $table,
                int $recordUid,
                int $action,
                ?int $recordPid,
                int $error,
                string $details,
            ) use (&$messages): int {
                $messages[] = $details;

                return 0;
            },
        );

        return $dataHandler;
    }
}
