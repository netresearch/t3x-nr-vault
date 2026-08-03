<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service;

use DateTimeImmutable;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptedData;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\AuditWriteException;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\SecretExpiredException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Http\VaultHttpClientFactoryInterface;
use Netresearch\NrVault\Http\VaultHttpClientInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;

#[CoversClass(VaultService::class)]
#[AllowMockObjectsWithoutExpectations]
final class VaultServiceTest extends TestCase
{
    private const TEST_DESCRIPTION = 'Test description';

    private const AUDIT_WRITE_ERROR = 'audit down';

    private VaultService $subject;

    private VaultAdapterInterface&MockObject $adapter;

    private EncryptionServiceInterface&MockObject $encryptionService;

    private AccessControlServiceInterface&MockObject $accessControlService;

    private AuditLogServiceInterface&MockObject $auditLogService;

    private ExtensionConfigurationInterface&MockObject $configuration;

    private VaultHttpClientFactoryInterface&MockObject $httpClientFactory;

    protected function setUp(): void
    {
        parent::setUp();

        $this->adapter = $this->createMock(VaultAdapterInterface::class);
        // VaultAdapterInterface::store() returns the persisted Secret. PHPUnit
        // cannot auto-generate a return value for a `final readonly` class, so
        // default the mock to pass the input through. Per-test `expects()->with(...)`
        // assertions still apply because the more specific matcher takes precedence.
        $this->adapter->method('store')->willReturnArgument(0);
        // The two adapter lookups differ only in which database restrictions
        // they honour — a distinction a mock cannot express, and one that is
        // pinned where it is real: Tests/Functional/Service/SecretAvailabilityTest.
        // Here the double answers both identically, so a test stubbing
        // `retrieve()` also describes what the administrative paths see. The
        // callback resolves lazily, so the per-test stub set after setUp() is
        // the one that answers.
        $this->adapter
            ->method('retrieveIncludingDisabled')
            ->willReturnCallback(fn (string $identifier): ?Secret => $this->adapter->retrieve($identifier));
        $this->encryptionService = $this->createMock(EncryptionServiceInterface::class);
        $this->accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $this->auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->httpClientFactory = $this->createMock(VaultHttpClientFactoryInterface::class);

        $this->accessControlService
            ->method('getCurrentActorUid')
            ->willReturn(1);

        $this->accessControlService
            ->method('getCurrentActorType')
            ->willReturn('cli');

        // Default canCreate to true so the happy-path store tests do not need
        // to stub it; tests that exercise the denial branch override locally.
        $this->accessControlService
            ->method('canCreate')
            ->willReturn(true);

        // Default the operation permissions (secret.create/rotate/delete,
        // secret.manage_policy) to granted; the denial-branch tests build
        // their own access-control mock instead.
        $this->accessControlService
            ->method('isGranted')
            ->willReturn(true);

        $this->subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $this->accessControlService,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );
    }

    #[Test]
    public function storeEncryptsAndSavesSecret(): void
    {
        $identifier = 'myApiKey';
        $secretValue = 'super-secret-value';

        $this->encryptionService
            ->expects(self::once())
            ->method('encrypt')
            ->with($secretValue, $identifier)
            ->willReturn(new EncryptedData('enc_value', 'enc_dek', 'nonce1', 'nonce2', 'checksum'));

        $this->adapter
            ->method('retrieve')
            ->with($identifier)
            ->willReturn(null);

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $secret): bool => $secret->getIdentifier() === $identifier
                && $secret->getEncryptedValue() === 'enc_value'
                && $secret->getEncryptedDek() === 'enc_dek'))
            ->willReturnArgument(0);

        $this->auditLogService
            ->expects(self::once())
            ->method('log');

        $this->subject->store($identifier, $secretValue);
    }

    #[Test]
    public function storeRejectsEmptyIdentifier(): void
    {
        $this->expectException(ValidationException::class);

        $this->subject->store('', 'secret');
    }

    #[Test]
    public function storeRejectsEmptySecret(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('empty');

        $this->subject->store('validIdentifier', '');
    }

    #[Test]
    public function storeDeniesCreationWhenCanCreateReturnsFalse(): void
    {
        $denyingAccessControl = $this->createMock(AccessControlServiceInterface::class);
        $denyingAccessControl->method('getCurrentActorUid')->willReturn(1);
        $denyingAccessControl->method('getCurrentActorType')->willReturn('backend');
        $denyingAccessControl->method('canCreate')->willReturn(false);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $denyingAccessControl,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->adapter->method('retrieve')->willReturn(null);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('newSecret', 'access_denied', false, 'Create access denied');

        $this->adapter->expects(self::never())->method('store');
        $this->encryptionService->expects(self::never())->method('encrypt');

        $this->expectException(AccessDeniedException::class);

        $subject->store('newSecret', 'plaintext');
    }

    #[Test]
    public function storeDeniesUpdateWhenCanWriteReturnsFalse(): void
    {
        $existing = $this->createSecretEntity('existing');

        $denyingAccessControl = $this->createMock(AccessControlServiceInterface::class);
        $denyingAccessControl->method('getCurrentActorUid')->willReturn(1);
        $denyingAccessControl->method('getCurrentActorType')->willReturn('backend');
        $denyingAccessControl->method('canWrite')->with($existing)->willReturn(false);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $denyingAccessControl,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->adapter->method('retrieve')->willReturn($existing);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('existing', 'access_denied', false, 'Update access denied');

        $this->adapter->expects(self::never())->method('store');
        $this->encryptionService->expects(self::never())->method('encrypt');

        $this->expectException(AccessDeniedException::class);

        $subject->store('existing', 'new-value');
    }

    #[Test]
    public function storeDeniesCreateWithoutSecretCreatePermission(): void
    {
        // Per-secret ACL passes (canCreate), but the actor lacks the
        // secret.create operation permission: both gates must hold.
        $noGrantAccess = $this->createMock(AccessControlServiceInterface::class);
        $noGrantAccess->method('getCurrentActorUid')->willReturn(1);
        $noGrantAccess->method('getCurrentActorType')->willReturn('backend');
        $noGrantAccess->method('canCreate')->willReturn(true);
        $noGrantAccess->method('isGranted')->willReturn(false);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $noGrantAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->adapter->method('retrieve')->willReturn(null);
        $this->adapter->expects(self::never())->method('store');
        $this->encryptionService->expects(self::never())->method('encrypt');

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('opGate', 'access_denied', false, 'Create denied: missing secret.create permission');

        $this->expectException(AccessDeniedException::class);

        $subject->store('opGate', 'plaintext');
    }

    #[Test]
    public function storeDeniesUpdateWithoutSecretRotatePermission(): void
    {
        $existing = $this->createSecretEntity('opGateUpdate', uid: 42);

        $noGrantAccess = $this->createMock(AccessControlServiceInterface::class);
        $noGrantAccess->method('getCurrentActorUid')->willReturn(1);
        $noGrantAccess->method('getCurrentActorType')->willReturn('backend');
        $noGrantAccess->method('canWrite')->willReturn(true);
        $noGrantAccess->method('isGranted')->willReturn(false);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $noGrantAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->adapter->method('retrieve')->willReturn($existing);
        $this->adapter->expects(self::never())->method('store');

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('opGateUpdate', 'access_denied', false, 'Update denied: missing secret.rotate permission');

        $this->expectException(AccessDeniedException::class);

        $subject->store('opGateUpdate', 'new-value');
    }

    #[Test]
    public function storeDeniesPolicyChangeWithoutManagePolicyPermission(): void
    {
        $existing = $this->createSecretEntity('opGatePolicy', uid: 42);

        // secret.rotate is granted, secret.manage_policy is not: replacing
        // the value is fine, widening the group ACL alongside it is not.
        $rotateOnlyAccess = $this->createMock(AccessControlServiceInterface::class);
        $rotateOnlyAccess->method('getCurrentActorUid')->willReturn(1);
        $rotateOnlyAccess->method('getCurrentActorType')->willReturn('cli');
        $rotateOnlyAccess->method('canWrite')->willReturn(true);
        $rotateOnlyAccess->method('isGranted')->willReturnCallback(
            static fn (VaultPermission $permission): bool => $permission === VaultPermission::SecretRotate,
        );

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $rotateOnlyAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->adapter->method('retrieve')->willReturn($existing);
        $this->adapter->expects(self::never())->method('store');

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('opGatePolicy', 'access_denied', false, 'Policy change denied: missing secret.manage_policy permission');

        $this->expectException(AccessDeniedException::class);

        $subject->store('opGatePolicy', 'new-value', ['groups' => [5, 6]]);
    }

    #[Test]
    public function storeAllowsUpdateWithoutManagePolicyWhenPolicyIsUnchanged(): void
    {
        $existing = $this->createSecretEntity('opGateNoPolicy', uid: 42);

        // Same grant profile as above — but no policy option changes, so
        // secret.rotate alone must suffice for a plain value update.
        $rotateOnlyAccess = $this->createMock(AccessControlServiceInterface::class);
        $rotateOnlyAccess->method('getCurrentActorUid')->willReturn(1);
        $rotateOnlyAccess->method('getCurrentActorType')->willReturn('cli');
        $rotateOnlyAccess->method('canWrite')->willReturn(true);
        $rotateOnlyAccess->method('isGranted')->willReturnCallback(
            static fn (VaultPermission $permission): bool => $permission === VaultPermission::SecretRotate,
        );

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $rotateOnlyAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn($existing);

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->willReturnArgument(0);

        $subject->store('opGateNoPolicy', 'new-value');
    }

    #[Test]
    public function rotateDeniesWithoutSecretRotatePermission(): void
    {
        $existing = $this->createSecretEntity('opGateRotate', uid: 42);

        $noGrantAccess = $this->createMock(AccessControlServiceInterface::class);
        $noGrantAccess->method('getCurrentActorUid')->willReturn(1);
        $noGrantAccess->method('getCurrentActorType')->willReturn('backend');
        $noGrantAccess->method('canWrite')->willReturn(true);
        $noGrantAccess->method('isGranted')->willReturn(false);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $noGrantAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->adapter->method('retrieve')->willReturn($existing);
        $this->adapter->expects(self::never())->method('store');

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('opGateRotate', 'access_denied', false, 'Rotate denied: missing secret.rotate permission');

        $this->expectException(AccessDeniedException::class);

        $subject->rotate('opGateRotate', 'new-value');
    }

    #[Test]
    public function deleteDeniesWithoutSecretDeletePermission(): void
    {
        $existing = $this->createSecretEntity('opGateDelete', uid: 42);

        $noGrantAccess = $this->createMock(AccessControlServiceInterface::class);
        $noGrantAccess->method('getCurrentActorUid')->willReturn(1);
        $noGrantAccess->method('getCurrentActorType')->willReturn('backend');
        $noGrantAccess->method('canDelete')->willReturn(true);
        $noGrantAccess->method('isGranted')->willReturn(false);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $noGrantAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->adapter->method('retrieve')->willReturn($existing);
        $this->adapter->expects(self::never())->method('delete');

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('opGateDelete', 'access_denied', false, 'Delete denied: missing secret.delete permission');

        $this->expectException(AccessDeniedException::class);

        $subject->delete('opGateDelete');
    }

    #[Test]
    public function storeUpdatePreservesUnsubmittedMetadata(): void
    {
        // Preserve semantics: a value update without options must not reset
        // description, ACL tiers, context, expiry or frontend availability —
        // those are policy fields whose CHANGE is gated by
        // secret.manage_policy, so an accidental reset would be a policy
        // change without its permission.
        $existing = new Secret(
            identifier: 'preserve',
            uid: 42,
            scopePid: 7,
            description: 'Keep me',
            encryptedValue: 'encrypted',
            encryptedDek: 'dek',
            dekNonce: 'n1',
            valueNonce: 'n2',
            valueChecksum: 'cs',
            ownerUid: 1,
            allowedGroups: [5, 6],
            writeGroups: [6],
            context: 'prod',
            frontendAccessible: true,
            version: 3,
            expiresAt: 2000000000,
            metadata: ['team' => 'ops'],
        );

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc2', 'dek2', 'n3', 'n4', 'cs2'));

        $this->adapter->method('retrieve')->willReturn($existing);
        $this->accessControlService->method('canWrite')->willReturn(true);

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $s): bool => $s->getDescription() === 'Keep me'
                && $s->getScopePid() === 7
                && $s->getAllowedGroups() === [5, 6]
                && $s->getWriteGroups() === [6]
                && $s->getContext() === 'prod'
                && $s->isFrontendAccessible()
                && $s->getExpiresAt() === 2000000000
                && $s->getMetadata() === ['team' => 'ops']))
            ->willReturnArgument(0);

        $this->subject->store('preserve', 'new-value');
    }

    #[Test]
    public function storeOnValueLessExistingRecordIsACreation(): void
    {
        // The FormEngine path: DataHandler inserts the tx_nrvault_secret row
        // (metadata only), then hands the value to store(). A record without
        // an encrypted value is a creation in progress — it must face
        // secret.create (not secret.rotate), be audited as create, and keep
        // the metadata the row already carries.
        $existing = new Secret(
            identifier: 'formCreate',
            uid: 42,
            description: 'Entered in the form',
            ownerUid: 1,
        );

        $createOnlyAccess = $this->createMock(AccessControlServiceInterface::class);
        $createOnlyAccess->method('getCurrentActorUid')->willReturn(1);
        $createOnlyAccess->method('getCurrentActorType')->willReturn('cli');
        $createOnlyAccess->method('canWrite')->willReturn(true);
        $createOnlyAccess->method('isGranted')->willReturnCallback(
            static fn (VaultPermission $permission): bool => $permission === VaultPermission::SecretCreate,
        );

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $createOnlyAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn($existing);

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $s): bool => $s->getUid() === 42
                && $s->getDescription() === 'Entered in the form'))
            ->willReturnArgument(0);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('formCreate', 'create', true);

        $subject->store('formCreate', 'first-value');
    }

    /**
     * Regression: DataHandler inserts the row and defers its MM writes until
     * after the hook that calls store() has returned, so the read behind
     * $existing reports no groups for a record that is about to have several.
     * Persisting those empty tiers zeroed the count columns while the
     * relation rows landed moments later.
     */
    #[Test]
    public function storeCompletingAFormEngineCreationLeavesTheGroupTiersUntouched(): void
    {
        $existing = new Secret(
            identifier: 'formCreateAcl',
            uid: 42,
            ownerUid: 1,
        );

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn($existing);
        $this->accessControlService->method('canWrite')->willReturn(true);

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::isInstanceOf(Secret::class), false)
            ->willReturnArgument(0);

        $this->subject->store('formCreateAcl', 'first-value');
    }

    #[Test]
    public function storeManagesTheGroupTiersWhenTheCallerSubmitsThem(): void
    {
        // Same value-less record, but a caller that states the tiers itself
        // owns them — the option must not be silently dropped.
        $existing = new Secret(
            identifier: 'formCreateAcl',
            uid: 42,
            ownerUid: 1,
        );

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn($existing);
        $this->accessControlService->method('canWrite')->willReturn(true);

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(
                self::callback(static fn (Secret $secret): bool => $secret->getAllowedGroups() === [5, 6]),
                true,
            )
            ->willReturnArgument(0);

        $this->subject->store('formCreateAcl', 'first-value', ['groups' => [5, 6]]);
    }

    #[Test]
    public function storeManagesTheGroupTiersOnAnOrdinaryUpdate(): void
    {
        // A record that already holds a value was read with its relations
        // complete, so the tiers it carries are authoritative.
        $existing = new Secret(
            identifier: 'update',
            uid: 42,
            encryptedValue: 'encrypted',
            encryptedDek: 'dek',
            dekNonce: 'n1',
            valueNonce: 'n2',
            valueChecksum: 'cs',
            ownerUid: 1,
            allowedGroups: [5],
            writeGroups: [6],
        );

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc2', 'dek2', 'n3', 'n4', 'cs2'));

        $this->adapter->method('retrieve')->willReturn($existing);
        $this->accessControlService->method('canWrite')->willReturn(true);

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::isInstanceOf(Secret::class), true)
            ->willReturnArgument(0);

        $this->subject->store('update', 'new-value');
    }

    #[Test]
    public function storeCoercesOwnerUidForNonAdminBackendActor(): void
    {
        $beActorAccess = $this->createMock(AccessControlServiceInterface::class);
        $beActorAccess->method('getCurrentActorUid')->willReturn(7);
        $beActorAccess->method('getCurrentActorType')->willReturn('backend');
        $beActorAccess->method('canCreate')->willReturn(true);
        $beActorAccess->method('isGranted')->willReturn(true);
        $beActorAccess->method('isCurrentActorAdmin')->willReturn(false);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $beActorAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn(null);

        // Non-admin BE actor passing owner=99 must be coerced to current actor UID (7).
        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $s): bool => $s->getOwnerUid() === 7))
            ->willReturnArgument(0);

        $subject->store('coerce', 'plaintext', ['owner' => 99]);
    }

    #[Test]
    public function storeCoercesFrontendAccessibleForNonAdminBackendActor(): void
    {
        $beActorAccess = $this->createMock(AccessControlServiceInterface::class);
        $beActorAccess->method('getCurrentActorUid')->willReturn(7);
        $beActorAccess->method('getCurrentActorType')->willReturn('backend');
        $beActorAccess->method('canCreate')->willReturn(true);
        $beActorAccess->method('isGranted')->willReturn(true);
        $beActorAccess->method('isCurrentActorAdmin')->willReturn(false);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $beActorAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn(null);

        // Non-admin BE actor marking frontendAccessible=true must be coerced
        // back to false (privileged flag, SEC-ACCESS-11).
        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $s): bool => $s->isFrontendAccessible() === false))
            ->willReturnArgument(0);

        $subject->store('coerce_fe', 'plaintext', ['frontendAccessible' => true]);
    }

    #[Test]
    public function storeAllowsFrontendAccessibleForAdminBackendActor(): void
    {
        $adminAccess = $this->createMock(AccessControlServiceInterface::class);
        $adminAccess->method('getCurrentActorUid')->willReturn(1);
        $adminAccess->method('getCurrentActorType')->willReturn('backend');
        $adminAccess->method('canCreate')->willReturn(true);
        $adminAccess->method('isGranted')->willReturn(true);
        $adminAccess->method('isCurrentActorAdmin')->willReturn(true);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $adminAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn(null);

        // Admin BE actor may mark a secret frontend-accessible.
        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $s): bool => $s->isFrontendAccessible()))
            ->willReturnArgument(0);

        $subject->store('admin_fe', 'plaintext', ['frontendAccessible' => true]);
    }

    #[Test]
    public function retrieveDecryptsAndReturnsSecret(): void
    {
        $identifier = 'myApiKey';
        $expectedValue = 'decrypted-secret';

        $secret = $this->createSecretEntity($identifier);

        $this->adapter
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($secret);

        $this->accessControlService
            ->method('canRead')
            ->with($secret)
            ->willReturn(true);

        $this->encryptionService
            ->expects(self::once())
            ->method('decrypt')
            ->willReturn($expectedValue);

        $this->adapter
            ->expects(self::once())
            ->method('incrementReadCount')
            ->with($secret->getUid());

        $result = $this->subject->retrieve($identifier);

        self::assertEquals($expectedValue, $result);
    }

    #[Test]
    public function retrieveReturnsNullForNonExistentSecret(): void
    {
        $this->adapter
            ->method('retrieve')
            ->with('nonexistent')
            ->willReturn(null);

        $result = $this->subject->retrieve('nonexistent');

        self::assertNull($result);
    }

    #[Test]
    public function retrieveThrowsAccessDeniedWithoutPermission(): void
    {
        $secret = $this->createSecretEntity('restricted');

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canRead')
            ->willReturn(false);

        $this->auditLogService
            ->expects(self::once())
            ->method('log');

        $this->expectException(AccessDeniedException::class);

        $this->subject->retrieve('restricted');
    }

    /**
     * On top of the per-secret `canRead()` tier, an interactively authenticated
     * NON-admin backend user needs the `secret.use` operation permission for
     * every plaintext read — the FormEngine widget, FlexForm resolution and the
     * reveal endpoint alike.
     */
    #[Test]
    public function retrieveDeniesNonAdminBackendUserWithoutSecretUsePermission(): void
    {
        $secret = $this->createSecretEntity('usable');

        $access = $this->createMock(AccessControlServiceInterface::class);
        $access->method('getCurrentActorUid')->willReturn(7);
        $access->method('getCurrentActorType')->willReturn('backend');
        $access->method('isCurrentActorAdmin')->willReturn(false);
        // Per-secret read access granted; the operation permission is not.
        $access->method('canRead')->willReturn(true);
        $access->method('isGranted')->willReturn(false);

        $subject = $this->createSubjectWith($access);

        $this->adapter->method('retrieve')->willReturn($secret);
        $this->encryptionService->expects(self::never())->method('decrypt');

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('usable', 'access_denied', false, self::stringContains('secret.use'));

        $this->expectException(AccessDeniedException::class);

        $subject->retrieve('usable');
    }

    #[Test]
    public function retrieveAllowsNonAdminBackendUserHoldingSecretUsePermission(): void
    {
        $secret = $this->createSecretEntity('usable');

        $access = $this->createMock(AccessControlServiceInterface::class);
        $access->method('getCurrentActorUid')->willReturn(7);
        $access->method('getCurrentActorType')->willReturn('backend');
        $access->method('isCurrentActorAdmin')->willReturn(false);
        $access->method('canRead')->willReturn(true);
        $access
            ->method('isGranted')
            ->willReturnCallback(
                static fn (VaultPermission $permission): bool => $permission === VaultPermission::SecretUse,
            );

        $subject = $this->createSubjectWith($access);

        $this->adapter->method('retrieve')->willReturn($secret);
        $this->encryptionService->method('decrypt')->willReturn('plaintext');

        self::assertSame('plaintext', $subject->retrieve('usable'));
    }

    /**
     * Admins are exempt from the operation gate — the branch is expressed via
     * `isCurrentActorAdmin()`, so `isGranted()` is never consulted for them.
     */
    #[Test]
    public function retrieveDoesNotGateAdminBackendUsersOnSecretUse(): void
    {
        $secret = $this->createSecretEntity('usable');

        $access = $this->createMock(AccessControlServiceInterface::class);
        $access->method('getCurrentActorUid')->willReturn(1);
        $access->method('getCurrentActorType')->willReturn('backend');
        $access->method('isCurrentActorAdmin')->willReturn(true);
        $access->method('canRead')->willReturn(true);
        $access->expects(self::never())->method('isGranted');

        $subject = $this->createSubjectWith($access);

        $this->adapter->method('retrieve')->willReturn($secret);
        $this->encryptionService->method('decrypt')->willReturn('plaintext');

        self::assertSame('plaintext', $subject->retrieve('usable'));
    }

    /**
     * The frontend path must keep its exact previous behaviour: a page render's
     * output is shared via the page cache, so it may not depend on whichever
     * backend user happens to hold a session. `frontend_accessible` decides.
     */
    #[Test]
    public function retrieveForFrontendIsNotGatedOnSecretUse(): void
    {
        $secret = $this->createSecretEntity('publicKey', frontendAccessible: true);

        $access = $this->createMock(AccessControlServiceInterface::class);
        $access->method('getCurrentActorUid')->willReturn(7);
        $access->method('getCurrentActorType')->willReturn('backend');
        $access->method('isCurrentActorAdmin')->willReturn(false);
        $access->method('canRead')->willReturn(true);
        $access->method('isGranted')->willReturn(false);

        $subject = $this->createSubjectWith($access);

        $this->adapter->method('retrieve')->willReturn($secret);
        $this->encryptionService->method('decrypt')->willReturn('plaintext');

        self::assertSame('plaintext', $subject->retrieveForFrontend('publicKey'));
    }

    #[Test]
    public function retrieveThrowsExceptionForExpiredSecret(): void
    {
        $secret = $this->createSecretEntity('expired', expiresAt: time() - 3600); // Expired 1 hour ago

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canRead')
            ->willReturn(true);

        $this->expectException(SecretExpiredException::class);

        $this->subject->retrieve('expired');
    }

    #[Test]
    public function retrieveForFrontendReturnsFrontendAccessibleSecret(): void
    {
        $identifier = 'publicApiKey';
        $secret = $this->createSecretEntity($identifier, frontendAccessible: true);

        $this->adapter
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($secret);

        $this->accessControlService
            ->method('canRead')
            ->willReturn(true);

        $this->encryptionService
            ->method('decrypt')
            ->willReturn('decrypted-secret');

        self::assertSame('decrypted-secret', $this->subject->retrieveForFrontend($identifier));
    }

    #[Test]
    public function retrieveForFrontendDeniesSecretThatIsNotFrontendAccessible(): void
    {
        $identifier = 'smtpPassword';
        $secret = $this->createSecretEntity($identifier);

        $this->adapter
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($secret);

        // A privileged ambient actor (admin backend user browsing the
        // frontend) — the frontend gate must deny regardless.
        $this->accessControlService
            ->method('canRead')
            ->willReturn(true);

        $this->encryptionService
            ->expects(self::never())
            ->method('decrypt');

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with($identifier, 'access_denied', false, self::isString());

        $this->expectException(AccessDeniedException::class);

        $this->subject->retrieveForFrontend($identifier);
    }

    #[Test]
    public function retrieveForFrontendReturnsNullForNonExistentSecret(): void
    {
        $this->adapter
            ->method('retrieve')
            ->with('nonexistent')
            ->willReturn(null);

        self::assertNull($this->subject->retrieveForFrontend('nonexistent'));
    }

    #[Test]
    public function deleteRemovesSecretWithPermission(): void
    {
        $identifier = 'toDelete';
        $secret = $this->createSecretEntity($identifier);

        $this->adapter
            ->method('retrieve')
            ->with($identifier)
            ->willReturn($secret);

        $this->accessControlService
            ->method('canDelete')
            ->with($secret)
            ->willReturn(true);

        $this->adapter
            ->expects(self::once())
            ->method('delete')
            ->with($identifier);

        $this->auditLogService
            ->expects(self::once())
            ->method('log');

        $this->subject->delete($identifier, 'Test deletion');
    }

    #[Test]
    public function deleteThrowsNotFoundForNonExistent(): void
    {
        $this->adapter
            ->method('retrieve')
            ->willReturn(null);

        $this->expectException(SecretNotFoundException::class);

        $this->subject->delete('nonexistent');
    }

    #[Test]
    public function deleteThrowsAccessDeniedWithoutPermission(): void
    {
        $secret = $this->createSecretEntity('protected');

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canDelete')
            ->willReturn(false);

        $this->expectException(AccessDeniedException::class);

        $this->subject->delete('protected');
    }

    #[Test]
    public function assertDeletableAcceptsADeletableSecretWithoutDeletingIt(): void
    {
        $identifier = 'preflightOk';
        $secret = $this->createSecretEntity($identifier);

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canDelete')
            ->willReturn(true);

        // A preflight that mutates would defeat its own purpose.
        $this->adapter->expects(self::never())->method('delete');
        $this->auditLogService->expects(self::never())->method('log');

        $this->subject->assertDeletable($identifier);
    }

    #[Test]
    public function assertDeletableAcceptsAnAbsentSecret(): void
    {
        // The goal state — nothing stored under this identifier — already
        // holds, so a caller batching several deletes must not be blocked.
        $this->adapter
            ->method('retrieve')
            ->willReturn(null);

        $this->adapter->expects(self::never())->method('delete');

        $this->subject->assertDeletable('gone');
    }

    #[Test]
    public function assertDeletableRejectsASecretTheActorMayNotDelete(): void
    {
        $secret = $this->createSecretEntity('protected');

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canDelete')
            ->willReturn(false);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('protected', 'access_denied', false, 'Delete access denied');

        $this->expectException(AccessDeniedException::class);

        $this->subject->assertDeletable('protected');
    }

    #[Test]
    public function assertDeletableRejectsAnActorWithoutTheDeleteOperationPermission(): void
    {
        // Separation of duties: owning the secret is not enough, and the
        // preflight must apply the same second gate delete() does.
        $existing = $this->createSecretEntity('opGatePreflight', uid: 42);

        $noGrantAccess = $this->createMock(AccessControlServiceInterface::class);
        $noGrantAccess->method('getCurrentActorUid')->willReturn(1);
        $noGrantAccess->method('getCurrentActorType')->willReturn('backend');
        $noGrantAccess->method('canDelete')->willReturn(true);
        $noGrantAccess->method('isGranted')->willReturn(false);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $noGrantAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->adapter->method('retrieve')->willReturn($existing);
        $this->adapter->expects(self::never())->method('delete');

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('opGatePreflight', 'access_denied', false, 'Delete denied: missing secret.delete permission');

        $this->expectException(AccessDeniedException::class);

        $subject->assertDeletable('opGatePreflight');
    }

    #[Test]
    public function rotateUpdatesSecretValue(): void
    {
        $identifier = 'toRotate';
        $newSecret = 'new-secret-value';
        $secret = $this->createSecretEntity($identifier, version: 1);

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canWrite')
            ->willReturn(true);

        $this->encryptionService
            ->expects(self::once())
            ->method('encrypt')
            ->with($newSecret, $identifier)
            ->willReturn(new EncryptedData('new_enc', 'new_dek', 'new_nonce1', 'new_nonce2', 'new_checksum'));

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $s): bool => $s->getVersion() === 2
                && $s->getLastRotatedAt() > 0
                && $s->getEncryptedValue() === 'new_enc'))
            ->willReturnArgument(0);

        $this->subject->rotate($identifier, $newSecret, 'Annual rotation');
    }

    #[Test]
    public function rotateThrowsNotFoundForNonExistent(): void
    {
        $this->adapter
            ->method('retrieve')
            ->willReturn(null);

        $this->expectException(SecretNotFoundException::class);

        $this->subject->rotate('nonexistent', 'newsecret');
    }

    #[Test]
    public function rotateThrowsAccessDeniedWithoutPermission(): void
    {
        $secret = $this->createSecretEntity('protected');

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canWrite')
            ->willReturn(false);

        $this->expectException(AccessDeniedException::class);

        $this->subject->rotate('protected', 'newsecret');
    }

    #[Test]
    public function rotateRejectsEmptyNewSecret(): void
    {
        $secret = $this->createSecretEntity('mySecret');

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canWrite')
            ->willReturn(true);

        $this->expectException(ValidationException::class);

        $this->subject->rotate('mySecret', '');
    }

    #[Test]
    public function setEnabledDisablesTheSecretAndAuditsAMetadataUpdate(): void
    {
        $this->adapter->method('retrieve')->willReturn($this->createSecretEntity('availability', 7));
        $this->accessControlService->method('canWrite')->willReturn(true);

        // The availability column is written on its own, addressed by UID.
        // `store()` would round-trip every scalar column of the entity read a
        // moment earlier and undo whatever else committed in between.
        $this->adapter->expects(self::once())->method('setHidden')->with(7, true);
        $this->adapter->expects(self::never())->method('store');

        // `metadata_update` is the same action the FormEngine path writes for
        // this column, so the two write paths answer one audit query.
        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with(
                'availability',
                AuditAction::MetadataUpdate->value,
                true,
                null,
                'Secret disabled: key leaked',
            );

        $this->subject->setEnabled('availability', false, 'key leaked');
    }

    /**
     * The reason is optional, and its absence must not leave the entry
     * without the direction of the change.
     */
    #[Test]
    public function setEnabledNamesTheDirectionEvenWithoutAReason(): void
    {
        $this->adapter->method('retrieve')->willReturn(
            $this->createSecretEntity('availability', hidden: true),
        );
        $this->accessControlService->method('canWrite')->willReturn(true);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('availability', AuditAction::MetadataUpdate->value, true, null, 'Secret enabled');

        $this->subject->setEnabled('availability', true);
    }

    /**
     * Availability is set, not toggled. Asking for the state a secret already
     * has changes nothing, so nothing is written and nothing is audited — an
     * entry would put a mutation into the chain that never happened.
     */
    #[Test]
    public function setEnabledIsANoOpWhenTheSecretIsAlreadyInTheRequestedState(): void
    {
        $this->adapter->method('retrieve')->willReturn(
            $this->createSecretEntity('availability', hidden: true),
        );
        $this->accessControlService->method('canWrite')->willReturn(true);

        $this->adapter->expects(self::never())->method('setHidden');
        $this->adapter->expects(self::never())->method('store');
        $this->auditLogService->expects(self::never())->method('log');

        $this->subject->setEnabled('availability', false);
    }

    #[Test]
    public function setEnabledThrowsNotFoundForAnUnknownSecret(): void
    {
        $this->adapter->method('retrieve')->willReturn(null);
        $this->adapter->expects(self::never())->method('setHidden');

        $this->expectException(SecretNotFoundException::class);

        $this->subject->setEnabled('nonexistent', false);
    }

    #[Test]
    public function setEnabledDeniesAnActorWithoutWriteAccessToTheSecret(): void
    {
        $this->adapter->method('retrieve')->willReturn($this->createSecretEntity('protected'));
        $this->accessControlService->method('canWrite')->willReturn(false);

        $this->adapter->expects(self::never())->method('setHidden');
        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('protected', AuditAction::AccessDenied->value, false, 'Availability change access denied');

        $this->expectException(AccessDeniedException::class);

        $this->subject->setEnabled('protected', false);
    }

    /**
     * The second gate, refusing on its own: this actor may write the secret
     * but holds no `secret.manage_policy`.
     */
    #[Test]
    public function setEnabledDeniesAnActorWithoutTheManagePolicyPermission(): void
    {
        $noGrantAccess = $this->createMock(AccessControlServiceInterface::class);
        $noGrantAccess->method('getCurrentActorUid')->willReturn(1);
        $noGrantAccess->method('getCurrentActorType')->willReturn('cli');
        $noGrantAccess->method('canWrite')->willReturn(true);
        $noGrantAccess->method('isGranted')->willReturn(false);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $noGrantAccess,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $this->adapter->method('retrieve')->willReturn($this->createSecretEntity('opGatePolicy'));
        $this->adapter->expects(self::never())->method('setHidden');

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with(
                'opGatePolicy',
                AuditAction::AccessDenied->value,
                false,
                'Availability change denied: missing secret.manage_policy permission',
            );

        $this->expectException(AccessDeniedException::class);

        $subject->setEnabled('opGatePolicy', false);
    }

    /**
     * SEC-3 atomicity: an availability change whose audit write fails must be
     * reverted to the state captured before it, so a silent revocation of
     * access never persists with nothing in the chain to explain it.
     */
    #[Test]
    public function setEnabledRollsBackWhenAuditWriteFails(): void
    {
        $this->adapter->method('retrieve')->willReturn($this->createSecretEntity('rollback_availability', 7));
        $this->accessControlService->method('canWrite')->willReturn(true);

        // Both the change and its revert go through the targeted write, so the
        // compensation cannot restore anything but the availability either.
        $this->adapter->expects(self::never())->method('store');

        $storedStates = [];
        $this->adapter
            ->expects(self::exactly(2))
            ->method('setHidden')
            ->willReturnCallback(static function (int $uid, bool $hidden) use (&$storedStates): void {
                self::assertSame(7, $uid);
                $storedStates[] = $hidden;
            });

        $this->auditLogService
            ->method('log')
            ->willThrowException(new AuditWriteException('audit down', 1234567890));

        // The failure must surface; `finally` runs the state assertion before
        // it propagates into the expectation declared above.
        $this->expectException(AuditWriteException::class);

        try {
            $this->subject->setEnabled('rollback_availability', false);
        } finally {
            self::assertSame(
                [true, false],
                $storedStates,
                'The change must be applied and then reverted to the captured prior state.',
            );
        }
    }

    #[Test]
    public function existsReturnsTrueForExistingSecret(): void
    {
        $this->adapter
            ->method('exists')
            ->with('existing')
            ->willReturn(true);

        self::assertTrue($this->subject->exists('existing'));
    }

    #[Test]
    public function existsReturnsFalseForNonExistent(): void
    {
        $this->adapter
            ->method('exists')
            ->with('nonexistent')
            ->willReturn(false);

        self::assertFalse($this->subject->exists('nonexistent'));
    }

    #[Test]
    public function listReturnsAccessibleSecrets(): void
    {
        $secret1 = $this->createSecretEntity('secret1');
        $secret2 = $this->createSecretEntity('secret2');

        $this->adapter
            ->method('listSecrets')
            ->willReturn([$secret1, $secret2]);

        $this->accessControlService
            ->method('canRead')
            ->willReturnCallback(static fn (Secret $s): bool => $s->getIdentifier() !== 'secret2');

        $result = $this->subject->list();

        self::assertCount(1, $result);
        self::assertEquals('secret1', $result[0]->identifier);
    }

    #[Test]
    public function getMetadataReturnsSecretMetadata(): void
    {
        $identifier = 'metaSecret';
        $secret = $this->createSecretEntity(
            $identifier,
            version: 3,
            description: self::TEST_DESCRIPTION,
            context: 'testing',
            metadata: ['key' => 'value'],
        );

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canRead')
            ->willReturn(true);

        $result = $this->subject->getMetadata($identifier);

        self::assertEquals($identifier, $result->identifier);
        self::assertEquals(self::TEST_DESCRIPTION, $result->description);
        self::assertEquals('testing', $result->context);
        self::assertEquals(3, $result->version);
        self::assertEquals(['key' => 'value'], $result->metadata);
    }

    #[Test]
    public function getMetadataThrowsNotFoundForNonExistent(): void
    {
        $this->adapter
            ->method('retrieve')
            ->willReturn(null);

        $this->expectException(SecretNotFoundException::class);

        $this->subject->getMetadata('nonexistent');
    }

    #[Test]
    public function httpReturnsVaultHttpClient(): void
    {
        $mockClient = $this->createMock(VaultHttpClientInterface::class);
        $this->httpClientFactory
            ->expects(self::once())
            ->method('create')
            ->with($this->subject)
            ->willReturn($mockClient);

        $result = $this->subject->http();

        self::assertSame($mockClient, $result);
    }

    #[Test]
    public function storeWithAllOptions(): void
    {
        $identifier = 'fullOptions';
        $secretValue = 'test-secret';

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn(null);

        $expiresAt = new DateTimeImmutable('+1 day');

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $s): bool => $s->getOwnerUid() === 5
                && $s->getDescription() === self::TEST_DESCRIPTION
                && $s->getContext() === 'testing'
                && $s->getScopePid() === 100
                && $s->isFrontendAccessible()
                && $s->getExpiresAt() === $expiresAt->getTimestamp()))
            ->willReturnArgument(0);

        $this->subject->store($identifier, $secretValue, [
            'owner' => 5,
            'groups' => [1, 2, 3],
            'context' => 'testing',
            'description' => self::TEST_DESCRIPTION,
            'metadata' => ['key' => 'value'],
            'scopePid' => 100,
            'expiresAt' => $expiresAt,
            'frontendAccessible' => true,
        ]);
    }

    #[Test]
    public function storeWithIntegerExpiresAt(): void
    {
        $identifier = 'intExpires';
        $secretValue = 'test-secret';
        $expiresTimestamp = time() + 3600;

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn(null);

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $s): bool => $s->getExpiresAt() === $expiresTimestamp))
            ->willReturnArgument(0);

        $this->subject->store($identifier, $secretValue, [
            'expiresAt' => $expiresTimestamp,
        ]);
    }

    #[Test]
    public function storeUpdatesExistingSecret(): void
    {
        $identifier = 'existing';
        $secretValue = 'new-value';

        $existing = $this->createSecretEntity(
            $identifier,
            uid: 42,
            version: 2,
            crdate: 1000,
        );

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn($existing);

        // Updates use canWrite, not canCreate.
        $this->accessControlService
            ->method('canWrite')
            ->willReturn(true);

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $s): bool => $s->getUid() === 42
                && $s->getCrdate() === 1000
                && $s->getVersion() === 2))
            ->willReturnArgument(0);

        $this->subject->store($identifier, $secretValue);
    }

    #[Test]
    public function getMetadataThrowsAccessDenied(): void
    {
        $secret = $this->createSecretEntity('restricted');

        $this->adapter->method('retrieve')->willReturn($secret);
        $this->accessControlService->method('canRead')->willReturn(false);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('restricted', 'access_denied', false, 'Metadata access denied');

        $this->expectException(AccessDeniedException::class);

        $this->subject->getMetadata('restricted');
    }

    #[Test]
    public function listWithPattern(): void
    {
        $secret = $this->createSecretEntity('api-key-1');

        $this->adapter
            ->method('listSecrets')
            ->with(self::callback(static fn ($filters): bool => $filters instanceof SecretFilters && $filters->prefix === 'api-*'))
            ->willReturn([$secret]);

        $this->accessControlService
            ->method('canRead')
            ->willReturn(true);

        $result = $this->subject->list('api-*');

        self::assertCount(1, $result);
        self::assertEquals('api-key-1', $result[0]->identifier);
    }

    #[Test]
    public function retrieveNeverCachesPlaintextAcrossCalls(): void
    {
        // Security invariant: there is NO plaintext cache. Every retrieve()
        // must re-load the record, re-run the ACL decision and re-decrypt —
        // a cached plaintext handed to a later caller would bypass
        // authorization, expiry and the audit trail (cross-actor leak in
        // long-running worker processes).
        $secret = $this->createSecretEntity('uncached');

        $this->adapter
            ->expects(self::exactly(2))
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->expects(self::exactly(2))
            ->method('canRead')
            ->willReturn(true);

        $this->encryptionService
            ->expects(self::exactly(2))
            ->method('decrypt')
            ->willReturn('plain-value');

        self::assertSame('plain-value', $this->subject->retrieve('uncached'));
        self::assertSame('plain-value', $this->subject->retrieve('uncached'));
    }

    #[Test]
    public function retrieveDeniesSecondCallWhenAclRevokedBetweenReads(): void
    {
        // The cross-actor regression: actor A reads the secret, then the ACL
        // decision changes (e.g. a technical-actor switch in the same
        // process). The second retrieve() must be denied — never served from
        // a previous caller's plaintext.
        $secret = $this->createSecretEntity('switched');

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canRead')
            ->willReturnOnConsecutiveCalls(true, false);

        $this->encryptionService
            ->expects(self::once())
            ->method('decrypt')
            ->willReturn('plain-value');

        self::assertSame('plain-value', $this->subject->retrieve('switched'));

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('switched', 'access_denied', false, 'Read access denied');

        $this->expectException(AccessDeniedException::class);

        $this->subject->retrieve('switched');
    }

    #[Test]
    public function retrieveLogsDecryptionFailure(): void
    {
        $secret = $this->createSecretEntity('failDecrypt');

        $this->adapter->method('retrieve')->willReturn($secret);
        $this->accessControlService->method('canRead')->willReturn(true);

        $this->encryptionService
            ->method('decrypt')
            ->willThrowException(new EncryptionException('Decrypt failed', 1234567890));

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('failDecrypt', 'read', false, self::stringContains('Decrypt failed'));

        $this->expectException(EncryptionException::class);

        $this->subject->retrieve('failDecrypt');
    }

    #[Test]
    public function deleteLogsAccessDeniedWhenNoPermission(): void
    {
        $secret = $this->createSecretEntity('protected');

        $this->adapter->method('retrieve')->willReturn($secret);
        $this->accessControlService->method('canDelete')->willReturn(false);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('protected', 'access_denied', false, 'Delete access denied');

        $this->expectException(AccessDeniedException::class);

        $this->subject->delete('protected');
    }

    #[Test]
    public function rotateLogsAccessDeniedWhenNoPermission(): void
    {
        $secret = $this->createSecretEntity('protected');

        $this->adapter->method('retrieve')->willReturn($secret);
        $this->accessControlService->method('canWrite')->willReturn(false);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('protected', 'access_denied', false, 'Rotate access denied');

        $this->expectException(AccessDeniedException::class);

        $this->subject->rotate('protected', 'newValue');
    }

    #[Test]
    public function retrieveLogsExpiredSecretAccess(): void
    {
        $secret = $this->createSecretEntity('expired', expiresAt: time() - 3600);

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canRead')
            ->willReturn(true);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with('expired', 'read', false, 'Secret has expired');

        $this->expectException(SecretExpiredException::class);

        $this->subject->retrieve('expired');
    }

    #[Test]
    public function listHandlesEmptyPattern(): void
    {
        $this->adapter
            ->method('listSecrets')
            ->with(null)
            ->willReturn([]);

        $result = $this->subject->list();

        self::assertSame([], $result);
    }

    #[Test]
    public function storeWithGroupsOption(): void
    {
        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn(null);

        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with(self::callback(static fn (Secret $s): bool => $s->getAllowedGroups() === [1, 2, 3]))
            ->willReturnArgument(0);

        $this->subject->store('test', 'secret', [
            'groups' => [1, 2, 3],
        ]);
    }

    #[Test]
    public function storeRollsBackCreateWhenAuditWriteFails(): void
    {
        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn(null);

        // SEC-3: a failing audit write must trigger a compensating delete of
        // the just-inserted record so it never persists without an audit entry.
        $this->auditLogService
            ->method('log')
            ->willThrowException(new AuditWriteException(self::AUDIT_WRITE_ERROR, 1747825331));

        $this->adapter
            ->expects(self::once())
            ->method('delete')
            ->with('rollback_create');

        $this->expectException(AuditWriteException::class);

        $this->subject->store('rollback_create', 'plaintext');
    }

    #[Test]
    public function storeRollsBackUpdateWhenAuditWriteFails(): void
    {
        $existing = $this->createSecretEntity('rollback_update', uid: 42, version: 2, crdate: 1000);

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('enc', 'dek', 'n1', 'n2', 'cs'));

        $this->adapter->method('retrieve')->willReturn($existing);
        $this->accessControlService->method('canWrite')->willReturn(true);

        $this->auditLogService
            ->method('log')
            ->willThrowException(new AuditWriteException(self::AUDIT_WRITE_ERROR, 1747825331));

        // On update, the compensating action restores the prior instance:
        // store() is called twice — once for the mutation, once to restore.
        $storeArgs = [];
        $this->adapter
            ->expects(self::exactly(2))
            ->method('store')
            ->willReturnCallback(static function (Secret $s) use (&$storeArgs): Secret {
                $storeArgs[] = $s;

                return $s;
            });

        $this->expectException(AuditWriteException::class);

        try {
            $this->subject->store('rollback_update', 'new-value');
        } finally {
            // The second (compensating) store must be the original $existing.
            self::assertSame($existing, $storeArgs[1] ?? null);
        }
    }

    #[Test]
    public function deleteRollsBackWhenAuditWriteFails(): void
    {
        $secret = $this->createSecretEntity('rollback_delete');

        $this->adapter->method('retrieve')->willReturn($secret);
        $this->accessControlService->method('canDelete')->willReturn(true);

        $this->adapter->expects(self::once())->method('delete')->with('rollback_delete');

        $this->auditLogService
            ->method('log')
            ->willThrowException(new AuditWriteException(self::AUDIT_WRITE_ERROR, 1747825331));

        // Compensating action: re-insert the just-deleted record.
        $this->adapter
            ->expects(self::once())
            ->method('store')
            ->with($secret)
            ->willReturnArgument(0);

        $this->expectException(AuditWriteException::class);

        $this->subject->delete('rollback_delete', 'reason');
    }

    #[Test]
    public function rotateRollsBackWhenAuditWriteFails(): void
    {
        $secret = $this->createSecretEntity('rollback_rotate', version: 1);

        $this->adapter->method('retrieve')->willReturn($secret);
        $this->accessControlService->method('canWrite')->willReturn(true);

        $this->encryptionService
            ->method('encrypt')
            ->willReturn(new EncryptedData('new_enc', 'new_dek', 'n1', 'n2', 'new_cs'));

        $this->auditLogService
            ->method('log')
            ->willThrowException(new AuditWriteException(self::AUDIT_WRITE_ERROR, 1747825331));

        // store() called twice: rotated value, then compensating restore of
        // the pre-rotation instance.
        $storeArgs = [];
        $this->adapter
            ->expects(self::exactly(2))
            ->method('store')
            ->willReturnCallback(static function (Secret $s) use (&$storeArgs): Secret {
                $storeArgs[] = $s;

                return $s;
            });

        $this->expectException(AuditWriteException::class);

        try {
            $this->subject->rotate('rollback_rotate', 'new-value', 'reason');
        } finally {
            // The compensating store must be the original pre-rotation secret.
            self::assertSame($secret, $storeArgs[1] ?? null);
        }
    }

    /**
     * Build a subject wired to a different access-control seam, reusing the
     * remaining collaborators from setUp().
     *
     * `createMock()` allows a method to be configured only once, so tests that
     * need other actor semantics than the CLI default must bring their own
     * access-control mock rather than re-stubbing the shared one.
     */
    private function createSubjectWith(AccessControlServiceInterface $accessControlService): VaultService
    {
        return new VaultService(
            $this->adapter,
            $this->encryptionService,
            $accessControlService,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );
    }

    /**
     * Build a Secret with sensible test defaults plus optional per-test
     * overrides. The immutable entity forces a single ctor call, so any
     * deviation from defaults (expiresAt, version, uid, …) is passed
     * through here as a named argument.
     */
    private function createSecretEntity(
        string $identifier,
        ?int $uid = 1,
        int $version = 1,
        int $expiresAt = 0,
        int $crdate = 0,
        string $description = '',
        string $context = '',
        array $metadata = [],
        bool $frontendAccessible = false,
        bool $hidden = false,
    ): Secret {
        return new Secret(
            identifier: $identifier,
            uid: $uid,
            description: $description,
            encryptedValue: 'encrypted',
            encryptedDek: 'dek',
            dekNonce: 'nonce1',
            valueNonce: 'nonce2',
            valueChecksum: 'checksum',
            ownerUid: 1,
            context: $context,
            frontendAccessible: $frontendAccessible,
            version: $version,
            expiresAt: $expiresAt,
            metadata: $metadata,
            crdate: $crdate,
            hidden: $hidden,
        );
    }
}
