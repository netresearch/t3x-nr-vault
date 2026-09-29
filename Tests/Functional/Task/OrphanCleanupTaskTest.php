<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Task;

use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Task\OrphanCleanupTask;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Functional tests for OrphanCleanupTask scheduler task.
 *
 * Creates orphaned secrets (secrets whose source TCA records are deleted),
 * runs the task, and verifies cleanup behavior.
 */
#[CoversClass(OrphanCleanupTask::class)]
final class OrphanCleanupTaskTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/../Fixtures/Users/be_users.csv';

    /**
     * Load scheduler core extension — AbstractTask::__construct() reaches
     * for Scheduler\Scheduler via GeneralUtility::makeInstance, so the
     * scheduler container entry must be wired before the task is
     * instantiated.
     *
     * @var list<string>
     */
    protected array $coreExtensionsToLoad = ['backend', 'scheduler'];

    /** @var array<string, mixed> */
    protected array $extensionConfiguration = [
        'auditHmacEpoch' => 1,
    ];

    #[Test]
    public function executeReturnsTrueWhenNoOrphansExist(): void
    {
        $connectionPool = $this->get(ConnectionPool::class);
        $vaultService = $this->get(VaultServiceInterface::class);

        $task = new OrphanCleanupTask($connectionPool, $vaultService);
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);

        $result = $task->execute();

        self::assertTrue($result, 'Task must return true when no orphans exist');
    }

    #[Test]
    public function executeDeletesOrphanedSecretsWhenRetentionPeriodHasPassed(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $connectionPool = $this->get(ConnectionPool::class);

        // Store a secret with tca_field source metadata
        $identifier = $this->generateUuidV7();
        // Store it with metadata indicating it belongs to a TCA record
        $vaultService->store($identifier, 'orphan_value', [
            'metadata' => [
                'table' => 'be_users',
                'field' => 'some_field',
                'uid' => 99999, // non-existent UID
                'source' => 'tca_field',
            ],
        ]);

        // Artificially back-date the created_at time so retention period has passed
        $secretConn = $connectionPool->getConnectionForTable('tx_nrvault_secret');
        $secretConn->update(
            'tx_nrvault_secret',
            ['crdate' => time() - (30 * 86400)],
            ['identifier' => $identifier],
        );

        // Run task with 0 retention days (delete immediately)
        $task = new OrphanCleanupTask($connectionPool, $vaultService);
        $task->setTaskParameters([
            'nr_vault_retention_days' => 0,
            'nr_vault_table_filter' => '',
        ]);

        $result = $task->execute();
        self::assertTrue($result, $result ? 'ok' : 'Task execution failed');

        // The orphan should be deleted
        $retrieved = $vaultService->retrieve($identifier);
        self::assertNull($retrieved, 'Orphaned secret must be deleted after cleanup task runs');
    }

    #[Test]
    public function executeKeepsNonOrphanedSecrets(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $connectionPool = $this->get(ConnectionPool::class);

        // Store a secret without TCA metadata (not an orphan candidate)
        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'nonorphan_value');

        $task = new OrphanCleanupTask($connectionPool, $vaultService);
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);

        $task->execute();

        // Non-TCA secrets must not be deleted
        $retrieved = $vaultService->retrieve($identifier);
        self::assertSame('nonorphan_value', $retrieved, 'Non-orphaned secrets must not be deleted');

        // Cleanup
        $vaultService->delete($identifier, 'test cleanup');
    }

    #[Test]
    public function executeDoesNotDeleteOrphansWithinRetentionPeriod(): void
    {
        $vaultService = $this->get(VaultServiceInterface::class);
        $connectionPool = $this->get(ConnectionPool::class);

        // Store a secret with tca_field source for a non-existent record
        $identifier = $this->generateUuidV7();
        $vaultService->store($identifier, 'freshorphan_value', [
            'metadata' => [
                'table' => 'be_users',
                'field' => 'some_field',
                'uid' => 99999, // non-existent UID
                'source' => 'tca_field',
            ],
        ]);

        // Run with 30 day retention — secret is new, should NOT be deleted
        $task = new OrphanCleanupTask($connectionPool, $vaultService);
        $task->setTaskParameters(['nr_vault_retention_days' => 30]);

        $task->execute();

        // Secret must still exist (within retention period)
        $retrieved = $vaultService->retrieve($identifier);
        self::assertSame(
            'freshorphan_value',
            $retrieved,
            'Orphan within retention period must not be deleted',
        );

        // Cleanup
        $vaultService->delete($identifier, 'test cleanup');
    }

    #[Test]
    public function getAdditionalInformationContainsRetentionDays(): void
    {
        $task = new OrphanCleanupTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 14]);

        $info = $task->getAdditionalInformation();

        self::assertStringContainsString('14', $info);
        self::assertStringContainsString('days', $info);
    }

    #[Test]
    public function getAdditionalInformationContainsTableFilterWhenSet(): void
    {
        $task = new OrphanCleanupTask();
        $task->setTaskParameters([
            'nr_vault_retention_days' => 7,
            'nr_vault_table_filter' => 'tt_content',
        ]);

        $info = $task->getAdditionalInformation();

        self::assertStringContainsString('tt_content', $info);
    }
}
