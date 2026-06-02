<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service;

use DateTimeImmutable;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
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

        $this->configuration
            ->method('isCacheEnabled')
            ->willReturn(false);

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
    public function storeCoercesOwnerUidForNonAdminBackendActor(): void
    {
        $beActorAccess = $this->createMock(AccessControlServiceInterface::class);
        $beActorAccess->method('getCurrentActorUid')->willReturn(7);
        $beActorAccess->method('getCurrentActorType')->willReturn('backend');
        $beActorAccess->method('canCreate')->willReturn(true);
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
    public function clearCacheClearsInternalCache(): void
    {
        // This test verifies clearCache doesn't throw
        $this->subject->clearCache();
        $this->expectNotToPerformAssertions();
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
    public function retrieveWithCacheEnabled(): void
    {
        // Create service with cache enabled
        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->configuration->method('isCacheEnabled')->willReturn(true);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $this->accessControlService,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $secret = $this->createSecretEntity('cached');

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canRead')
            ->willReturn(true);

        $this->encryptionService
            ->expects(self::once()) // Only once due to caching
            ->method('decrypt')
            ->willReturn('cached-value');

        // First call - should decrypt
        $result1 = $subject->retrieve('cached');
        // Second call - should use cache
        $result2 = $subject->retrieve('cached');

        self::assertSame('cached-value', $result1);
        self::assertSame('cached-value', $result2);
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
    public function clearCacheWipesSecureMemory(): void
    {
        // Enable cache for this test
        $this->configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $this->configuration->method('isCacheEnabled')->willReturn(true);

        $subject = new VaultService(
            $this->adapter,
            $this->encryptionService,
            $this->accessControlService,
            $this->auditLogService,
            $this->configuration,
            $this->httpClientFactory,
        );

        $secret = $this->createSecretEntity('cached');

        $this->adapter
            ->method('retrieve')
            ->willReturn($secret);

        $this->accessControlService
            ->method('canRead')
            ->willReturn(true);

        $this->encryptionService
            ->method('decrypt')
            ->willReturn('secret-value');

        // First retrieve to populate cache
        $subject->retrieve('cached');

        // Clear cache should not throw
        $subject->clearCache();

        // Verify by retrieving again - should call decrypt again
        $this->encryptionService
            ->expects(self::once())
            ->method('decrypt')
            ->willReturn('secret-value');

        $subject->retrieve('cached');
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
            version: $version,
            expiresAt: $expiresAt,
            metadata: $metadata,
            crdate: $crdate,
        );
    }
}
