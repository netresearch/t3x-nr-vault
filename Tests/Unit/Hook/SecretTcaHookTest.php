<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Hook;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Hook\SecretTcaHook;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use ReflectionClass;
use TYPO3\CMS\Core\DataHandling\DataHandler;

#[CoversClass(SecretTcaHook::class)]
#[AllowMockObjectsWithoutExpectations]
final class SecretTcaHookTest extends TestCase
{
    private VaultServiceInterface&MockObject $vaultService;

    private AuditLogServiceInterface&MockObject $auditService;

    private AccessControlServiceInterface&MockObject $accessControlService;

    private SecretRepositoryInterface&MockObject $secretRepository;

    private SecretTcaHook $hook;

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

        $this->hook = new SecretTcaHook(
            $this->vaultService,
            $this->auditService,
            $this->accessControlService,
            $this->secretRepository,
        );
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
        $accessControl = $this->createMock(AccessControlServiceInterface::class);
        $accessControl->method('isCurrentActorAdmin')->willReturn(false);
        $accessControl->method('getCurrentActorUid')->willReturn(7);

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

        self::assertSame(42, $fieldArray['owner_uid']);
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
}
