<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Documentation;

use Closure;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\EncryptedData;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Http\VaultHttpClientFactoryInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Throwable;

#[CoversClass(VaultService::class)]
#[AllowMockObjectsWithoutExpectations]
final class SecretMetadataUsageTest extends TestCase
{
    #[Test]
    public function literalMetadataFilterUsesActualListingDtosWithoutDecryption(): void
    {
        $adapter = $this->createMock(VaultAdapterInterface::class);
        $adapter
            ->expects(self::once())
            ->method('listSecrets')
            ->willReturn(
                [
                    new Secret(
                        'matching_one',
                        metadata: ['source' => 'tca_field', 'uid' => 42],
                    ),
                    new Secret('unrelated', metadata: ['source' => 'scheduler']),
                    new Secret('denied', metadata: ['source' => 'tca_field']),
                    new Secret('missing_source'),
                    new Secret(
                        'matching_two',
                        metadata: ['source' => 'tca_field', 'uid' => 43],
                    ),
                ],
            );
        $access = $this->createMock(AccessControlServiceInterface::class);
        $access
            ->method('canRead')
            ->willReturnCallback(static fn (Secret $secret): bool => $secret->identifier !== 'denied');
        $encryption = $this->createMock(EncryptionServiceInterface::class);
        $encryption->expects(self::never())->method('decrypt');
        $vault = new VaultService(
            $adapter,
            $encryption,
            $access,
            $this->createMock(AuditLogServiceInterface::class),
            $this->createMock(ExtensionConfigurationInterface::class),
            $this->createMock(VaultHttpClientFactoryInterface::class),
        );

        /** @var Closure(VaultServiceInterface): list<SecretMetadata> $filter */
        $filter = require \dirname(__DIR__, 3) . '/Documentation/Developer/Adr/_SecretMetadataFilter.php';
        $failure = null;
        $result = [];

        try {
            $result = $filter($vault);
        } catch (Throwable $caught) {
            $failure = $caught;
        }

        self::assertNull(
            $failure,
            'The literal documentation filter must execute on actual public DTOs.',
        );
        self::assertSame(
            ['matching_one', 'matching_two'],
            array_map(
                static fn (SecretMetadata $secret): string => $secret->identifier,
                $result,
            ),
        );
        self::assertSame([0, 1], array_keys($result));
        self::assertSame(
            ['source' => 'tca_field', 'uid' => 42],
            $result[0]->metadata,
        );
        self::assertSame(
            ['source' => 'tca_field', 'uid' => 43],
            $result[1]->metadata,
        );
    }

    #[Test]
    public function detailedMetadataKeepsExpiredDisabledCustodyWithoutReadingTheValue(): void
    {
        $identifier = 'disabled_meta';
        $secret = new Secret(
            identifier: $identifier,
            uid: 42,
            scopePid: 27,
            description: 'Service credential',
            ownerUid: 10,
            allowedGroups: [5],
            writeGroups: [6],
            context: 'payment',
            expiresAt: 1,
            metadata: ['source' => 'tca_field', 'environment' => 'production'],
            hidden: true,
            readCount: 7,
            lastReadAt: 100,
        );
        $adapter = $this->createMock(VaultAdapterInterface::class);
        $adapter
            ->expects(self::once())
            ->method('retrieveIncludingDisabled')
            ->with($identifier)
            ->willReturn($secret);
        $adapter->expects(self::never())->method('retrieve');
        $adapter->expects(self::never())->method('incrementReadCount');
        $access = $this->createMock(AccessControlServiceInterface::class);
        $access
            ->expects(self::once())
            ->method('canRead')
            ->with($secret)
            ->willReturn(true);
        $encryption = $this->createMock(EncryptionServiceInterface::class);
        $encryption->expects(self::never())->method('decrypt');
        $audit = $this->createMock(AuditLogServiceInterface::class);
        $audit->expects(self::never())->method('log');
        $vault = new VaultService(
            $adapter,
            $encryption,
            $access,
            $audit,
            $this->createMock(ExtensionConfigurationInterface::class),
            $this->createMock(VaultHttpClientFactoryInterface::class),
        );

        $details = $vault->getMetadata($identifier);

        self::assertSame($identifier, $details->identifier);
        self::assertSame(42, $details->uid);
        self::assertSame('Service credential', $details->description);
        self::assertSame([5], $details->groups);
        self::assertSame('payment', $details->context);
        self::assertSame(27, $details->scopePid);
        self::assertSame(7, $details->readCount);
        self::assertSame(100, $details->lastReadAt);
        self::assertSame(
            ['source' => 'tca_field', 'environment' => 'production'],
            $details->metadata,
        );
        self::assertFalse($details->enabled);
        self::assertTrue($details->isExpired());
        self::assertSame(
            [
                'uid' => 42,
                'identifier' => $identifier,
                'description' => 'Service credential',
                'owner' => 10,
                'owner_uid' => 10,
                'groups' => [5],
                'context' => 'payment',
                'frontend_accessible' => false,
                'version' => 1,
                'createdAt' => 0,
                'updatedAt' => 0,
                'expiresAt' => 1,
                'expires_at' => 1,
                'lastRotatedAt' => null,
                'read_count' => 7,
                'last_read_at' => 100,
                'metadata' => ['source' => 'tca_field', 'environment' => 'production'],
                'scopePid' => 27,
                'enabled' => false,
            ],
            $details->toArray(),
        );
    }

    /**
     * @param array<string, mixed> $metadata
     */
    #[Test]
    #[DataProvider('explicitCustomMetadataProvider')]
    public function storeReplacesExplicitCustomMetadata(
        array $metadata,
    ): void {
        $identifier = 'metadata_replace';
        $existing = new Secret(
            identifier: $identifier,
            uid: 42,
            encryptedValue: 'old-ciphertext',
            encryptedDek: 'old-dek',
            dekNonce: 'old-dek-nonce',
            valueNonce: 'old-value-nonce',
            valueChecksum: 'old-checksum',
            metadata: ['source' => 'old', 'obsolete' => 'remove'],
        );
        $adapter = $this->createMock(VaultAdapterInterface::class);
        $adapter
            ->expects(self::once())
            ->method('retrieveIncludingDisabled')
            ->with($identifier)
            ->willReturn($existing);
        $stored = null;
        $adapter
            ->expects(self::once())
            ->method('store')
            ->willReturnCallback(
                static function (Secret $secret) use (&$stored): Secret {
                    $stored = $secret;

                    return $secret;
                },
            );
        $access = $this->createMock(AccessControlServiceInterface::class);
        $access->method('canWrite')->willReturn(true);
        $access->method('isGranted')->willReturn(true);
        $access->method('getCurrentActorType')->willReturn('cli');
        $encryption = $this->createMock(EncryptionServiceInterface::class);
        $encryption
            ->expects(self::once())
            ->method('encrypt')
            ->with('new-value', $identifier)
            ->willReturn(
                new EncryptedData(
                    'new-ciphertext',
                    'new-dek',
                    'new-dek-nonce',
                    'new-value-nonce',
                    'new-checksum',
                ),
            );
        $audit = $this->createMock(AuditLogServiceInterface::class);
        $audit
            ->expects(self::once())
            ->method('log')
            ->with($identifier, 'update', true);
        $vault = new VaultService(
            $adapter,
            $encryption,
            $access,
            $audit,
            $this->createMock(ExtensionConfigurationInterface::class),
            $this->createMock(VaultHttpClientFactoryInterface::class),
        );

        $vault->store($identifier, 'new-value', ['metadata' => $metadata]);

        self::assertInstanceOf(Secret::class, $stored);
        self::assertSame($metadata, $stored->metadata);
        self::assertSame('new-ciphertext', $stored->encryptedValue);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function explicitCustomMetadataProvider(): iterable
    {
        yield 'replace the entire custom map' => [['source' => 'tca_field']];
        yield 'clear the entire custom map' => [[]];
    }
}
