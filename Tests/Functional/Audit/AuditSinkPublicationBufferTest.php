<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Audit;

use ArrayObject;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\AuditSinkPublicationBuffer;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Command\VaultRotateMasterKeyCommand;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Deferred sink publication reads the row again at flush time, so master-key
 * rotation publishes the hashes its re-key wrote, not the ones the row was
 * inserted with (#499).
 */
final class AuditSinkPublicationBufferTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../../Functional/Service/Fixtures/be_users.csv';

    #[Test]
    public function aFlushedEntryIsPublishedWithTheHashStoredAtFlushTime(): void
    {
        /** @var ArrayObject<int, AuditLogEntry> $published */
        $published = new ArrayObject();
        $sinks     = self::createStub(AuditSinkRegistryInterface::class);
        $sinks->method('dispatch')->willReturnCallback(static function (AuditLogEntry $entry) use ($published): int {
            $published->append($entry);

            return 0;
        });

        $buffer = new AuditSinkPublicationBuffer();
        $audit  = new AuditLogService(
            $this->get(ConnectionPool::class),
            $this->get(AccessControlServiceInterface::class),
            $this->get(MasterKeyProviderInterface::class),
            $this->get(ExtensionConfigurationInterface::class),
            $this->get(AuditChainAnchorStoreInterface::class),
            $sinks,
            publicationBuffer: $buffer,
        );

        $buffer->collect();
        $audit->log('publication-buffer-test', 'read', true);
        self::assertCount(0, $published, 'Nothing is published while the buffer collects.');

        // What the rotation's re-key does: the stored hash changes before the
        // commit, after the row was written.
        $connection = $this->get(ConnectionPool::class)->getConnectionForTable(AuditLogService::TABLE_NAME);
        $uid        = (int) $connection->select(['uid'], AuditLogService::TABLE_NAME, ['secret_identifier' => 'publication-buffer-test'])->fetchOne();
        self::assertGreaterThan(0, $uid);
        $rekeyed = str_repeat('ab', 32);
        $connection->update(AuditLogService::TABLE_NAME, ['entry_hash' => $rekeyed], ['uid' => $uid]);

        $buffer->flush();

        self::assertCount(1, $published);
        $entry = $published[0];
        self::assertInstanceOf(AuditLogEntry::class, $entry);
        self::assertSame($rekeyed, $entry->entryHash);
        self::assertSame('publication-buffer-test', $entry->secretIdentifier);
    }

    /**
     * The command starts and ends collection, the audit service defers to
     * it: both must hold the one shared instance, or the rotation's entries
     * would still be published at once.
     */
    #[Test]
    public function theRotationCommandAndTheAuditServiceShareTheBuffer(): void
    {
        $commandBuffer = (new ReflectionProperty(VaultRotateMasterKeyCommand::class, 'publicationBuffer'))
            ->getValue($this->get(VaultRotateMasterKeyCommand::class));
        $serviceBuffer = (new ReflectionProperty(AuditLogService::class, 'publicationBuffer'))
            ->getValue($this->get(AuditLogServiceInterface::class));

        self::assertInstanceOf(AuditSinkPublicationBuffer::class, $commandBuffer);
        self::assertSame($commandBuffer, $serviceBuffer);
    }
}
