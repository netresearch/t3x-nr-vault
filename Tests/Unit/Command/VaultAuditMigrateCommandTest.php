<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Doctrine\DBAL\Result;
use Netresearch\NrVault\Command\VaultAuditMigrateCommand;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

#[CoversClass(VaultAuditMigrateCommand::class)]
final class VaultAuditMigrateCommandTest extends TestCase
{
    private ConnectionPool $connectionPool;

    private MasterKeyProviderInterface $masterKeyProvider;

    private ExtensionConfigurationInterface $extensionConfiguration;

    private QueryBuilder $queryBuilder;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionPool = $this->createStub(ConnectionPool::class);
        $this->masterKeyProvider = $this->createStub(MasterKeyProviderInterface::class);
        $this->extensionConfiguration = $this->createStub(ExtensionConfigurationInterface::class);
        $this->queryBuilder = $this->createStub(QueryBuilder::class);

        $this->masterKeyProvider
            ->method('getMasterKey')
            ->willReturn(str_repeat("\x01", 32));

        $this->extensionConfiguration
            ->method('getAuditHmacEpoch')
            ->willReturn(1);

        $expressionBuilder = $this->createStub(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('hmac_key_epoch = 0');
        $this->queryBuilder->method('expr')->willReturn($expressionBuilder);

        $command = new VaultAuditMigrateCommand(
            $this->connectionPool,
            $this->masterKeyProvider,
            $this->extensionConfiguration,
        );

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultAuditMigrateCommand(
            $this->connectionPool,
            $this->masterKeyProvider,
            $this->extensionConfiguration,
        );

        self::assertSame('vault:audit-migrate-hmac', $command->getName());
    }

    #[Test]
    public function dryRunReportsChangesWithoutModifying(): void
    {
        // Count epoch-0 entries returns 1
        $countResult = $this->createStub(Result::class);
        $countResult->method('fetchOne')->willReturn(1);

        // Count total entries returns 1
        $totalCountResult = $this->createStub(Result::class);
        $totalCountResult->method('fetchOne')->willReturn(1);

        // Select query streams rows via fetchAssociative
        $selectResult = $this->createStub(Result::class);
        $selectResult->method('fetchAssociative')
            ->willReturnOnConsecutiveCalls(
                [
                    'uid' => 1,
                    'secret_identifier' => 'test',
                    'action' => 'create',
                    'actor_uid' => 1,
                    'crdate' => 1704067200,
                    'previous_hash' => '',
                    'entry_hash' => 'oldhash',
                    'hmac_key_epoch' => 0,
                ],
                false,
            );

        $this->queryBuilder->method('count')->willReturnSelf();
        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('where')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('createNamedParameter')->willReturn('0');

        // Return count results then select result
        $this->queryBuilder->method('executeQuery')
            ->willReturnOnConsecutiveCalls($countResult, $totalCountResult, $selectResult);

        // update must NOT be called in dry-run
        $connection = $this->wireConnectionMock();
        $connection
            ->expects(self::never())
            ->method('update');

        $exitCode = $this->commandTester->execute(['--dry-run' => true]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('DRY RUN', $display);
        self::assertStringContainsString('Would migrate 1 entries', $display);
    }

    #[Test]
    public function migrationUpdatesHashesAndEpoch(): void
    {
        // Count epoch-0 entries returns 1
        $countResult = $this->createStub(Result::class);
        $countResult->method('fetchOne')->willReturn(1);

        // Count total entries returns 1
        $totalCountResult = $this->createStub(Result::class);
        $totalCountResult->method('fetchOne')->willReturn(1);

        // Select query streams rows via fetchAssociative
        $selectResult = $this->createStub(Result::class);
        $selectResult->method('fetchAssociative')
            ->willReturnOnConsecutiveCalls(
                [
                    'uid' => 1,
                    'secret_identifier' => 'test',
                    'action' => 'create',
                    'actor_uid' => 1,
                    'crdate' => 1704067200,
                    'previous_hash' => '',
                    'entry_hash' => 'oldhash',
                    'hmac_key_epoch' => 0,
                ],
                false,
            );

        $this->queryBuilder->method('count')->willReturnSelf();
        $this->queryBuilder->method('select')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('where')->willReturnSelf();
        $this->queryBuilder->method('orderBy')->willReturnSelf();
        $this->queryBuilder->method('createNamedParameter')->willReturn('0');

        $this->queryBuilder->method('executeQuery')
            ->willReturnOnConsecutiveCalls($countResult, $totalCountResult, $selectResult);

        // update must be called with HMAC hash and epoch 1
        $connection = $this->wireConnectionMock();
        $connection
            ->expects(self::once())
            ->method('update')
            ->with(
                'tx_nrvault_audit_log',
                self::callback(static fn (array $data): bool => $data['hmac_key_epoch'] === 1
                    && isset($data['entry_hash'])
                    && $data['entry_hash'] !== 'oldhash'
                    && $data['entry_hash'] !== ''),
                ['uid' => 1],
            );

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Migrated 1 entries', $display);
    }

    #[Test]
    public function noEntriesReportsSuccess(): void
    {
        $countResult = $this->createStub(Result::class);
        $countResult->method('fetchOne')->willReturn(0);

        $this->queryBuilder->method('count')->willReturnSelf();
        $this->queryBuilder->method('from')->willReturnSelf();
        $this->queryBuilder->method('where')->willReturnSelf();
        $this->queryBuilder->method('createNamedParameter')->willReturn('0');
        $this->queryBuilder->method('executeQuery')->willReturn($countResult);

        $exitCode = $this->commandTester->execute([]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Nothing to migrate', $this->commandTester->getDisplay());
    }

    #[Test]
    public function epoch0ConfigurationReturnsFailure(): void
    {
        $extensionConfig = $this->createStub(ExtensionConfigurationInterface::class);
        $extensionConfig->method('getAuditHmacEpoch')->willReturn(0);

        $command = new VaultAuditMigrateCommand(
            $this->connectionPool,
            $this->masterKeyProvider,
            $extensionConfig,
        );

        $application = new Application();
        $application->addCommand($command);

        $tester = new CommandTester($command);
        $exitCode = $tester->execute([]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Cannot migrate to epoch 0', $tester->getDisplay());
    }

    /**
     * Creates a Connection mock, wires it into the ConnectionPool stub and the
     * queryBuilder, and returns it so the caller can set expectations.
     */
    private function wireConnectionMock(): Connection&MockObject
    {
        $connection = $this->createMock(Connection::class);
        $connection->method('createQueryBuilder')->willReturn($this->queryBuilder);
        $this->connectionPool->method('getConnectionForTable')->willReturn($connection);

        // GET_LOCK acquisition: command calls $connection->executeQuery() directly
        // (not via QueryBuilder). Return 1 = lock acquired.
        $lockResult = $this->createMock(Result::class);
        $lockResult->method('fetchOne')->willReturn(1);
        $connection->method('executeQuery')->willReturn($lockResult);

        return $connection;
    }
}
