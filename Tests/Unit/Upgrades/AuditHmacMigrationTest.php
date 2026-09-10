<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Upgrades;

use Doctrine\DBAL\Platforms\MySQLPlatform;
use Doctrine\DBAL\Result;
use Netresearch\NrVault\Audit\AuditChainAnchorStoreInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Upgrades\AuditHmacMigration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

#[CoversClass(AuditHmacMigration::class)]
final class AuditHmacMigrationTest extends TestCase
{
    private ConnectionPool&Stub $connectionPool;

    private MasterKeyProviderInterface&Stub $masterKeyProvider;

    private ExtensionConfigurationInterface&Stub $configuration;

    private AuditChainAnchorStoreInterface&Stub $anchorStore;

    private AuditHmacMigration $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionPool = self::createStub(ConnectionPool::class);
        $this->masterKeyProvider = self::createStub(MasterKeyProviderInterface::class);
        $this->configuration = self::createStub(ExtensionConfigurationInterface::class);
        // Default: chain is safe to re-seal (verifyChainForReseal() returns null).
        $auditLogService = self::createStub(AuditLogServiceInterface::class);
        $this->anchorStore = self::createStub(AuditChainAnchorStoreInterface::class);

        $this->subject = new AuditHmacMigration(
            $this->connectionPool,
            $this->masterKeyProvider,
            $this->configuration,
            $auditLogService,
            $this->anchorStore,
        );
    }

    #[Test]
    public function titleIsDescriptive(): void
    {
        self::assertStringContainsString('HMAC', $this->subject->getTitle());
    }

    #[Test]
    public function descriptionExplainsPurpose(): void
    {
        self::assertStringContainsString('tamper resistance', $this->subject->getDescription());
    }

    #[Test]
    public function updateNotNecessaryWhenEpochIsZero(): void
    {
        $this->configuration->method('getAuditHmacEpoch')->willReturn(0);

        self::assertFalse($this->subject->updateNecessary());
    }

    #[Test]
    public function updateNotNecessaryWhenNoLegacyEntries(): void
    {
        $this->configuration->method('getAuditHmacEpoch')->willReturn(1);

        $this->mockCountQuery(0);

        self::assertFalse($this->subject->updateNecessary());
    }

    #[Test]
    public function updateNecessaryWhenLegacyEntriesExist(): void
    {
        $this->configuration->method('getAuditHmacEpoch')->willReturn(1);

        $this->mockCountQuery(5);

        self::assertTrue($this->subject->updateNecessary());
    }

    #[Test]
    public function executeUpdateReturnsTrueWhenEpochIsZero(): void
    {
        $this->configuration->method('getAuditHmacEpoch')->willReturn(0);

        self::assertTrue($this->subject->executeUpdate());
    }

    #[Test]
    public function prerequisitesAreEmpty(): void
    {
        self::assertSame([], $this->subject->getPrerequisites());
    }

    #[Test]
    public function executeUpdateReturnsTrueAndProcessesRows(): void
    {
        $masterKey = str_repeat("\x42", 32);
        $this->configuration->method('getAuditHmacEpoch')->willReturn(1);
        $this->masterKeyProvider->method('getMasterKey')->willReturn($masterKey);

        $rows = [
            ['uid' => 1, 'secret_identifier' => 'secret-1', 'action' => 'store', 'actor_uid' => 5, 'crdate' => 1700000000],
            ['uid' => 2, 'secret_identifier' => 'secret-2', 'action' => 'retrieve', 'actor_uid' => 5, 'crdate' => 1700000001],
        ];

        $queryResult = self::createStub(Result::class);
        $queryResult->method('fetchAssociative')->willReturnOnConsecutiveCalls(
            $rows[0],
            $rows[1],
            false,
        );

        $queryBuilder = self::createStub(QueryBuilder::class);
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->method('executeQuery')->willReturn($queryResult);

        $connection = $this->createMock(Connection::class);
        $connection->method('createQueryBuilder')->willReturn($queryBuilder);
        $connection->expects(self::exactly(2))->method('update');
        $this->stubLockAcquisition($connection);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $result = $this->subject->executeUpdate();

        self::assertTrue($result);
    }

    #[Test]
    public function executeUpdateHandlesNonNumericRowValues(): void
    {
        $masterKey = str_repeat("\x55", 32);
        $this->configuration->method('getAuditHmacEpoch')->willReturn(1);
        $this->masterKeyProvider->method('getMasterKey')->willReturn($masterKey);

        // Row with non-numeric/non-string fields to exercise defensive casting
        $rows = [
            ['uid' => '3', 'secret_identifier' => null, 'action' => null, 'actor_uid' => '7', 'crdate' => '1700000005'],
        ];

        $queryResult = self::createStub(Result::class);
        $queryResult->method('fetchAssociative')->willReturnOnConsecutiveCalls($rows[0], false);

        $queryBuilder = self::createStub(QueryBuilder::class);
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->method('executeQuery')->willReturn($queryResult);

        $connection = $this->createMock(Connection::class);
        $connection->method('createQueryBuilder')->willReturn($queryBuilder);
        $connection->expects(self::once())->method('update');
        $this->stubLockAcquisition($connection);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $result = $this->subject->executeUpdate();

        self::assertTrue($result);
    }

    #[Test]
    public function executeUpdateReturnsTrueWhenNoRows(): void
    {
        $masterKey = str_repeat("\x33", 32);
        $this->configuration->method('getAuditHmacEpoch')->willReturn(1);
        $this->masterKeyProvider->method('getMasterKey')->willReturn($masterKey);

        $queryResult = self::createStub(Result::class);
        $queryResult->method('fetchAssociative')->willReturn(false);

        $queryBuilder = self::createStub(QueryBuilder::class);
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('orderBy')->willReturnSelf();
        $queryBuilder->method('executeQuery')->willReturn($queryResult);

        $connection = $this->createMock(Connection::class);
        $connection->method('createQueryBuilder')->willReturn($queryBuilder);
        $connection->expects(self::never())->method('update');
        $this->stubLockAcquisition($connection);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $result = $this->subject->executeUpdate();

        self::assertTrue($result);
    }

    #[Test]
    public function executeUpdateReturnsFalseWhenLockCannotBeAcquired(): void
    {
        // GET_LOCK returning 0 = timeout, NULL = error; both must abort the migration
        // rather than silently proceed without the lock.
        $this->configuration->method('getAuditHmacEpoch')->willReturn(1);
        $this->masterKeyProvider->method('getMasterKey')->willReturn(str_repeat("\x42", 32));

        $lockResult = self::createStub(Result::class);
        $lockResult->method('fetchOne')->willReturn(0); // timeout

        $connection = $this->createMock(Connection::class);
        $platform = self::createStub(MySQLPlatform::class);
        $connection->method('getDatabasePlatform')->willReturn($platform);
        $connection->method('executeQuery')->willReturn($lockResult);
        $connection->expects(self::never())->method('beginTransaction');
        $connection->expects(self::never())->method('update');

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        $result = $this->subject->executeUpdate();

        self::assertFalse($result, 'Wizard must abort when GET_LOCK returns 0 (timeout)');
    }

    /**
     * Stub the GET_LOCK acquisition path so existing tests reach the re-hash loop.
     * Tests that explicitly cover lock failure should NOT use this helper.
     */
    private function stubLockAcquisition(Connection&MockObject $connection): void
    {
        $lockResult = self::createStub(Result::class);
        $lockResult->method('fetchOne')->willReturn(1);
        $platform = self::createStub(MySQLPlatform::class);
        $connection->method('getDatabasePlatform')->willReturn($platform);
        $connection->method('executeQuery')->willReturn($lockResult);
    }

    private function mockCountQuery(int $count): void
    {
        $expressionBuilder = self::createStub(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('hmac_key_epoch = 0');

        $result = self::createStub(Result::class);
        $result->method('fetchOne')->willReturn($count);

        $queryBuilder = self::createStub(QueryBuilder::class);
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $queryBuilder->method('executeQuery')->willReturn($result);

        $connection = self::createStub(Connection::class);
        $connection->method('createQueryBuilder')->willReturn($queryBuilder);

        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);
    }
}
