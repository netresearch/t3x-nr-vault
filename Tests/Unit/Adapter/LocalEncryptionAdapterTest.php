<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Adapter;

use Netresearch\NrVault\Adapter\LocalEncryptionAdapter;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(LocalEncryptionAdapter::class)]
#[AllowMockObjectsWithoutExpectations]
final class LocalEncryptionAdapterTest extends TestCase
{
    #[Test]
    public function implementsVaultAdapterInterface(): void
    {
        $repository = $this->createStub(SecretRepositoryInterface::class);
        $adapter = new LocalEncryptionAdapter($repository);

        self::assertInstanceOf(VaultAdapterInterface::class, $adapter);
    }

    #[Test]
    public function getIdentifierReturnsLocal(): void
    {
        $repository = $this->createStub(SecretRepositoryInterface::class);
        $adapter = new LocalEncryptionAdapter($repository);

        self::assertEquals('local', $adapter->getIdentifier());
    }

    #[Test]
    public function isAvailableAlwaysReturnsTrue(): void
    {
        $repository = $this->createStub(SecretRepositoryInterface::class);
        $adapter = new LocalEncryptionAdapter($repository);

        self::assertTrue($adapter->isAvailable());
    }

    #[Test]
    public function storeDelegatesToRepository(): void
    {
        $secret = new Secret(identifier: 'test');

        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->expects(self::once())
            ->method('save')
            ->with($secret)
            ->willReturn($secret);

        $adapter = new LocalEncryptionAdapter($repository);
        $adapter->store($secret);
    }

    #[Test]
    public function retrieveDelegatesToRepository(): void
    {
        $secret = new Secret(identifier: 'test');

        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->expects(self::once())
            ->method('findByIdentifier')
            ->with('test')
            ->willReturn($secret);

        $adapter = new LocalEncryptionAdapter($repository);
        $result = $adapter->retrieve('test');

        self::assertSame($secret, $result);
    }

    #[Test]
    public function retrieveReturnsNullWhenNotFound(): void
    {
        $repository = $this->createStub(SecretRepositoryInterface::class);
        $repository->method('findByIdentifier')->willReturn(null);

        $adapter = new LocalEncryptionAdapter($repository);

        self::assertNull($adapter->retrieve('nonexistent'));
    }

    /**
     * The two lookups are separate seams on purpose, and the adapter must not
     * quietly route one to the other: the read path resolves through
     * `findByIdentifier()`, which cannot see a disabled record, while the
     * administrative path resolves through the lookup that can.
     */
    #[Test]
    public function retrieveIncludingDisabledDelegatesToTheDisabledVisibleLookup(): void
    {
        $secret = new Secret(identifier: 'test');

        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->expects(self::once())
            ->method('findByIdentifierIncludingDisabled')
            ->with('test')
            ->willReturn($secret);
        $repository->expects(self::never())->method('findByIdentifier');

        $adapter = new LocalEncryptionAdapter($repository);

        self::assertSame($secret, $adapter->retrieveIncludingDisabled('test'));
    }

    #[Test]
    public function retrieveIncludingDisabledReturnsNullWhenNotFound(): void
    {
        $repository = $this->createStub(SecretRepositoryInterface::class);
        $repository->method('findByIdentifierIncludingDisabled')->willReturn(null);

        $adapter = new LocalEncryptionAdapter($repository);

        self::assertNull($adapter->retrieveIncludingDisabled('nonexistent'));
    }

    #[Test]
    public function deleteRemovesExistingSecret(): void
    {
        $secret = new Secret(identifier: 'test');

        $repository = $this->createMock(SecretRepositoryInterface::class);
        // The disabled-visible lookup, deliberately: a disabled secret is
        // still a secret, and resolving the delete through the restricted
        // lookup would make it a silent no-op for exactly those records.
        $repository->method('findByIdentifierIncludingDisabled')
            ->with('test')
            ->willReturn($secret);
        $repository->expects(self::never())->method('findByIdentifier');
        $repository->expects(self::once())
            ->method('delete')
            ->with($secret);

        $adapter = new LocalEncryptionAdapter($repository);
        $adapter->delete('test');
    }

    #[Test]
    public function deleteDoesNothingWhenSecretNotFound(): void
    {
        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->method('findByIdentifierIncludingDisabled')->willReturn(null);
        $repository->expects(self::never())->method('delete');

        $adapter = new LocalEncryptionAdapter($repository);
        $adapter->delete('nonexistent');
    }

    #[Test]
    public function existsDelegatesToRepository(): void
    {
        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->expects(self::once())
            ->method('exists')
            ->with('test')
            ->willReturn(true);

        $adapter = new LocalEncryptionAdapter($repository);

        self::assertTrue($adapter->exists('test'));
    }

    #[Test]
    public function listDelegatesToRepository(): void
    {
        $identifiers = ['secret-1', 'secret-2', 'secret-3'];
        $filters = new SecretFilters(context: 'payment');

        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->expects(self::once())
            ->method('findIdentifiers')
            ->with($filters)
            ->willReturn($identifiers);

        $adapter = new LocalEncryptionAdapter($repository);

        self::assertEquals($identifiers, $adapter->list($filters));
    }

    #[Test]
    public function getMetadataReturnsNullWhenSecretNotFound(): void
    {
        $repository = $this->createStub(SecretRepositoryInterface::class);
        $repository->method('findByIdentifier')->willReturn(null);

        $adapter = new LocalEncryptionAdapter($repository);

        self::assertNull($adapter->getMetadata('nonexistent'));
    }

    #[Test]
    public function getMetadataReturnsSecretMetadata(): void
    {
        $secret = new Secret(
            identifier: 'api-key',
            description: 'Payment API key',
            ownerUid: 5,
            allowedGroups: [1, 2],
            context: 'payment',
            version: 3,
            expiresAt: 1735689600,
            metadata: ['service' => 'stripe'],
            adapter: 'local',
        );

        $repository = $this->createStub(SecretRepositoryInterface::class);
        $repository->method('findByIdentifier')->willReturn($secret);

        $adapter = new LocalEncryptionAdapter($repository);
        $metadata = $adapter->getMetadata('api-key');

        self::assertNotNull($metadata);
        self::assertEquals('api-key', $metadata['identifier']);
        self::assertEquals('Payment API key', $metadata['description']);
        self::assertEquals(5, $metadata['owner']);
        self::assertEquals([1, 2], $metadata['groups']);
        self::assertEquals('payment', $metadata['context']);
        self::assertEquals(3, $metadata['version']);
        self::assertEquals(1735689600, $metadata['expiresAt']);
        self::assertEquals(['service' => 'stripe'], $metadata['metadata']);
        self::assertEquals('local', $metadata['adapter']);
    }

    #[Test]
    public function getMetadataReturnsNullExpiresAtWhenZero(): void
    {
        $secret = new Secret(identifier: 'test', expiresAt: 0);

        $repository = $this->createStub(SecretRepositoryInterface::class);
        $repository->method('findByIdentifier')->willReturn($secret);

        $adapter = new LocalEncryptionAdapter($repository);
        $metadata = $adapter->getMetadata('test');

        self::assertNull($metadata['expiresAt']);
    }

    #[Test]
    public function updateMetadataDoesNothingWhenSecretNotFound(): void
    {
        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->method('findByIdentifier')->willReturn(null);
        $repository->expects(self::never())->method('setMetadata');
        $repository->expects(self::never())->method('save');

        $adapter = new LocalEncryptionAdapter($repository);
        $adapter->updateMetadata('nonexistent', ['key' => 'value']);
    }

    /**
     * A record without a UID cannot be addressed by the targeted write, and
     * the fallback of saving the entity instead is precisely what this method
     * must not do. Refusing is the only correct answer: an unsaved entity has
     * no persisted metadata to merge into either.
     */
    #[Test]
    public function updateMetadataDoesNothingWhenTheRecordHasNoUid(): void
    {
        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->method('findByIdentifier')->willReturn(new Secret(identifier: 'test'));
        $repository->expects(self::never())->method('setMetadata');
        $repository->expects(self::never())->method('save');

        $adapter = new LocalEncryptionAdapter($repository);
        $adapter->updateMetadata('test', ['key' => 'value']);
    }

    /**
     * The merge is the adapter's; the write is one column. Asserting the
     * absence of `save()` is the load-bearing half — a full entity save would
     * produce the same metadata while restoring every other column to the
     * state the `findByIdentifier()` above saw.
     */
    #[Test]
    public function updateMetadataMergesAndWritesOnlyTheMetadataColumn(): void
    {
        $secret = new Secret(identifier: 'test', uid: 42, metadata: ['existing' => 'value']);

        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->method('findByIdentifier')->willReturn($secret);
        $repository->expects(self::once())
            ->method('setMetadata')
            ->with(42, ['existing' => 'value', 'new' => 'data']);
        $repository->expects(self::never())->method('save');

        $adapter = new LocalEncryptionAdapter($repository);
        $adapter->updateMetadata('test', ['new' => 'data']);

        // Original entity is immutable — its metadata must not change.
        self::assertSame(['existing' => 'value'], $secret->getMetadata());
    }

    #[Test]
    public function incrementReadCountDelegatesToRepository(): void
    {
        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->expects(self::once())
            ->method('incrementReadCount')
            ->with(42);

        $adapter = new LocalEncryptionAdapter($repository);
        $adapter->incrementReadCount(42);
    }

    /**
     * Availability goes to the repository's targeted write, not through
     * `store()`: the adapter must not turn a one-column change into a save of
     * a whole entity it would first have to read.
     */
    #[Test]
    public function setHiddenDelegatesToRepository(): void
    {
        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->expects(self::once())
            ->method('setHidden')
            ->with(42, true);
        $repository->expects(self::never())->method('save');

        $adapter = new LocalEncryptionAdapter($repository);
        $adapter->setHidden(42, true);
    }

    #[Test]
    public function listSecretsDelegatesToRepository(): void
    {
        $secret1 = new Secret(identifier: 'secret-1');
        $secret2 = new Secret(identifier: 'secret-2');

        $filters = new SecretFilters(prefix: 'test');

        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->expects(self::once())
            ->method('findAllWithFilters')
            ->with($filters)
            ->willReturn([$secret1, $secret2]);

        $adapter = new LocalEncryptionAdapter($repository);
        $result = $adapter->listSecrets($filters);

        self::assertCount(2, $result);
        self::assertSame($secret1, $result[0]);
        self::assertSame($secret2, $result[1]);
    }

    #[Test]
    public function listSecretsWithNullFilters(): void
    {
        $repository = $this->createMock(SecretRepositoryInterface::class);
        $repository->expects(self::once())
            ->method('findAllWithFilters')
            ->with(null)
            ->willReturn([]);

        $adapter = new LocalEncryptionAdapter($repository);
        $result = $adapter->listSecrets();

        self::assertSame([], $result);
    }
}
