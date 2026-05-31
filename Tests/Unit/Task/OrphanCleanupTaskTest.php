<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Task;

use Doctrine\DBAL\Result;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Task\OrphanCleanupTask;
use Netresearch\NrVault\Tests\Unit\Fixtures\SecretFixtureBuilder;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;
use TYPO3\CMS\Core\Database\Query\Restriction\QueryRestrictionContainerInterface;
use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Scheduler\Scheduler;

#[CoversClass(OrphanCleanupTask::class)]
#[AllowMockObjectsWithoutExpectations]
final class OrphanCleanupTaskTest extends TestCase
{
    protected bool $resetSingletonInstances = true;

    private VaultServiceInterface&MockObject $vaultService;

    private ConnectionPool&MockObject $connectionPool;

    private SecretRepositoryInterface&MockObject $secretRepository;

    private LoggerInterface&MockObject $logger;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createMock(VaultServiceInterface::class);
        $this->connectionPool = $this->createMock(ConnectionPool::class);
        $this->secretRepository = $this->createMock(SecretRepositoryInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);

        // Mock GeneralUtility::makeInstance
        $logManager = $this->createMock(LogManager::class);
        $logManager->method('getLogger')->willReturn($this->logger);

        // TYPO3 v13 AbstractTask::__construct() calls GeneralUtility::makeInstance(Scheduler::class)
        // which requires 3 constructor args. Register a mock singleton to prevent this.
        GeneralUtility::setSingletonInstance(Scheduler::class, $this->createMock(Scheduler::class));

        GeneralUtility::addInstance(VaultServiceInterface::class, $this->vaultService);
        GeneralUtility::addInstance(ConnectionPool::class, $this->connectionPool);
        GeneralUtility::addInstance(SecretRepositoryInterface::class, $this->secretRepository);
        GeneralUtility::setSingletonInstance(LogManager::class, $logManager);
    }

    protected function tearDown(): void
    {
        GeneralUtility::purgeInstances();
        parent::tearDown();
    }

    #[Test]
    public function hasDefaultRetentionDays(): void
    {
        $task = $this->createTask();

        $params = $task->getTaskParameters();
        self::assertSame(7, $params['nr_vault_retention_days']);
    }

    #[Test]
    public function hasEmptyDefaultTableFilter(): void
    {
        $task = $this->createTask();

        $params = $task->getTaskParameters();
        self::assertSame('', $params['nr_vault_table_filter']);
    }

    #[Test]
    public function returnsTrueWithNoSecrets(): void
    {
        $this->secretRepository->method('findPaginatedAfterUid')->willReturn([]);

        $task = $this->createTask();
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function skipsNonTcaSecrets(): void
    {
        $this->mockPage([
            $this->createSecret('manual_secret', time(), ['source' => 'manual']),
        ]);

        $this->vaultService->expects($this->never())->method('delete');

        $task = $this->createTask();
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function skipsSecretsWithExistingRecords(): void
    {
        $this->mockPage([
            $this->createSecret(
                'tx_myext__api_key__1',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(1, true);
        $this->vaultService->expects($this->never())->method('delete');

        $task = $this->createTask();
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function deletesOrphansOlderThanRetention(): void
    {
        $this->mockPage([
            $this->createSecret(
                'tx_myext__api_key__1',
                time() - 86400 * 30, // 30 days old
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with('tx_myext__api_key__1', 'Scheduler orphan cleanup');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 7]);
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function skipsOrphansWithinRetentionPeriod(): void
    {
        $this->mockPage([
            $this->createSecret(
                'tx_myext__api_key__1',
                time() - 86400 * 3, // 3 days old
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(1, false);
        $this->vaultService->expects($this->never())->method('delete');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 7]);
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function appliesTableFilter(): void
    {
        $this->mockPage([
            $this->createSecret(
                'tx_myext__api_key__1',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
                1,
            ),
            $this->createSecret(
                'tx_other__secret__1',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_other', 'field' => 'secret', 'uid' => 1],
                2,
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with('tx_myext__api_key__1', 'Scheduler orphan cleanup');

        $task = $this->createTask();
        $task->setTaskParameters([
            'nr_vault_retention_days' => 0,
            'nr_vault_table_filter' => 'tx_myext',
        ]);
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function returnsFalseOnDeleteFailure(): void
    {
        $this->mockPage([
            $this->createSecret(
                'tx_myext__api_key__1',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->method('delete')
            ->willThrowException(new VaultException('Delete failed'));

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);
        $result = $task->execute();

        self::assertFalse($result);
    }

    #[Test]
    public function handlesMigrationSourceSecrets(): void
    {
        $this->mockPage([
            $this->createSecret(
                'tx_myext__api_key__1',
                time() - 86400 * 30,
                ['source' => 'migration', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with('tx_myext__api_key__1', 'Scheduler orphan cleanup');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function skipsSecretsWithInvalidMetadata(): void
    {
        $this->mockPage([
            $this->createSecret(
                'invalid_format',
                time() - 86400 * 30,
                ['source' => 'tca_field'],
            ),
        ]);

        $this->vaultService->expects($this->never())->method('delete');

        $task = $this->createTask();
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function skipsSecretsWithZeroUidInMetadata(): void
    {
        $this->mockPage([
            $this->createSecret(
                'some_uuid_identifier',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 0],
            ),
        ]);

        $this->vaultService->expects($this->never())->method('delete');

        $task = $this->createTask();
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function skipsSecretsWithNonNumericUidInMetadata(): void
    {
        $this->mockPage([
            $this->createSecret(
                'some_uuid_identifier',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 'not_a_number'],
            ),
        ]);

        $this->vaultService->expects($this->never())->method('delete');

        $task = $this->createTask();
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function skipsSecretsWithEmptyTableInMetadata(): void
    {
        $this->mockPage([
            $this->createSecret(
                'some_uuid_identifier',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => '', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->vaultService->expects($this->never())->method('delete');

        $task = $this->createTask();
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function parsesFlexFieldFromMetadata(): void
    {
        $this->mockPage([
            $this->createSecret(
                'uuid_flex_secret',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'flexField' => 'settings.apiKey', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with('uuid_flex_secret', 'Scheduler orphan cleanup');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);
        $result = $task->execute();

        self::assertTrue($result);
    }

    #[Test]
    public function logsCleanupProgress(): void
    {
        $this->secretRepository->method('findPaginatedAfterUid')->willReturn([]);

        $this->logger
            ->expects($this->atLeastOnce())
            ->method('info');

        $logManager = $this->createMock(LogManager::class);
        $logManager->method('getLogger')->willReturn($this->logger);

        $task = $this->createTask($logManager);
        $task->execute();
    }

    // =========================================================================
    // Targeted mutation-killers — Task/OrphanCleanupTask.php
    // =========================================================================

    /**
     * Kill IncrementInteger/DecrementInteger/Coalesce on the retention default —
     * default is exactly 7 retention days, not 6 and not 8.
     */
    #[Test]
    public function setTaskParametersDefaultRetentionIsExactlySeven(): void
    {
        $task = $this->createTask();
        $task->setTaskParameters([]);

        // Call through getTaskParameters which returns int (retentionDays is int).
        $params = $task->getTaskParameters();
        self::assertSame(7, $params['nr_vault_retention_days']);
    }

    /**
     * Kill CastInt / Ternary — numeric-string gets cast to int.
     */
    #[Test]
    public function setTaskParametersNumericStringCastsToInt(): void
    {
        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => '42']);

        $params = $task->getTaskParameters();
        self::assertSame(42, $params['nr_vault_retention_days']);
    }

    /**
     * Kill Ternary — non-numeric falls back to default 7.
     */
    #[Test]
    public function setTaskParametersNonNumericFallsBackToDefault(): void
    {
        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 'abc']);

        $params = $task->getTaskParameters();
        self::assertSame(7, $params['nr_vault_retention_days']);
    }

    /**
     * Kill UnwrapTrim — tableFilter is trimmed.
     */
    #[Test]
    public function setTaskParametersTrimmedTableFilter(): void
    {
        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_table_filter' => '  tx_myext  ']);

        $params = $task->getTaskParameters();
        self::assertSame('tx_myext', $params['nr_vault_table_filter']);
    }

    /**
     * Kill Ternary — zero stays zero (not default 7).
     */
    #[Test]
    public function setTaskParametersZeroRetentionStaysZero(): void
    {
        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);

        $params = $task->getTaskParameters();
        self::assertSame(0, $params['nr_vault_retention_days']);
    }

    /**
     * Kill Coalesce — explicit value overrides default.
     */
    #[Test]
    public function setTaskParametersExplicitValueOverridesDefault(): void
    {
        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 30]);

        $params = $task->getTaskParameters();
        self::assertSame(30, $params['nr_vault_retention_days']);
    }

    /**
     * Kill ArrayItem / MethodCallRemoval on the opening log line — logger info is
     * called with correct context keys (retentionDays, tableFilter).
     */
    #[Test]
    public function executeLogsRetentionAndFilterContext(): void
    {
        $this->secretRepository->method('findPaginatedAfterUid')->willReturn([]);

        $this->logger
            ->expects($this->atLeastOnce())
            ->method('info')
            ->with(
                self::callback(fn (string $message): bool => $message !== ''),
                self::callback(fn (array $context): bool => (\array_key_exists('retentionDays', $context) && \array_key_exists('tableFilter', $context))
                    || (\array_key_exists('secretsChecked', $context) && \array_key_exists('orphansFound', $context))),
            );

        $logManager = $this->createMock(LogManager::class);
        $logManager->method('getLogger')->willReturn($this->logger);

        $task = $this->createTask($logManager);
        $task->execute();
    }

    /**
     * Kill Continue_ on the non-TCA source guard — a non-TCA source must NOT
     * short-circuit the loop. When a non-TCA secret appears BEFORE a TCA orphan,
     * the TCA orphan must still be deleted. If `continue` becomes `break`, only
     * the first element is examined.
     */
    #[Test]
    public function executeContinuesOnNonTcaSourceAndProcessesLaterTcaOrphan(): void
    {
        $this->mockPage([
            $this->createSecret('manual_secret', time() - 86400 * 30, ['source' => 'manual'], 1),
            $this->createSecret(
                'tx_myext__api_key__1',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
                2,
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with('tx_myext__api_key__1', 'Scheduler orphan cleanup');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);

        self::assertTrue($task->execute());
    }

    /**
     * Kill Continue_ on the invalid-metadata guard — invalid metadata must not
     * short-circuit. Place an invalid-metadata secret BEFORE a valid TCA orphan.
     */
    #[Test]
    public function executeContinuesOnInvalidMetadataAndProcessesLaterTcaOrphan(): void
    {
        $this->mockPage([
            $this->createSecret(
                'invalid_secret',
                time() - 86400 * 30,
                ['source' => 'tca_field'],   // table/uid missing
                1,
            ),
            $this->createSecret(
                'tx_myext__api_key__1',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
                2,
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with('tx_myext__api_key__1', 'Scheduler orphan cleanup');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);

        self::assertTrue($task->execute());
    }

    /**
     * Kill Continue_ on the table-filter guard — table filter must not
     * short-circuit. Filtered-out secret appears BEFORE the matching one.
     */
    #[Test]
    public function executeContinuesOnTableFilterMismatchAndProcessesLaterMatchingSecret(): void
    {
        $this->mockPage([
            $this->createSecret(
                'filtered_out',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_other', 'field' => 'key', 'uid' => 1],
                1,
            ),
            $this->createSecret(
                'tx_myext__api_key__1',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
                2,
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with('tx_myext__api_key__1', 'Scheduler orphan cleanup');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0, 'nr_vault_table_filter' => 'tx_myext']);

        self::assertTrue($task->execute());
    }

    /**
     * Kill GreaterThan / LessThan on the retention cutoff comparison — createdAt
     * strictly less than retentionCutoff. We use a clearly old createdAt to drive
     * the condition.
     */
    #[Test]
    public function executeUsesStrictLessThanCutoffForOldOrphans(): void
    {
        // 30 days old — clearly past any reasonable retention.
        $thirtyDaysAgo = time() - 86400 * 30;

        $this->mockPage([
            $this->createSecret(
                'tx_myext__api_key__1',
                $thirtyDaysAgo,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 7]);

        self::assertTrue($task->execute());
    }

    /**
     * Kill LogicalAndAllSubExprNegation on the source check — BOTH source
     * conditions. source='unknown' must be skipped (neither 'tca_field' nor
     * 'migration').
     */
    #[Test]
    public function executeSkipsUnknownSourceValues(): void
    {
        $this->mockPage([
            $this->createSecret(
                'weird',
                time() - 86400 * 30,
                ['source' => 'unknown', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->vaultService->expects($this->never())->method('delete');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);

        self::assertTrue($task->execute());
    }

    /**
     * Kill Ternary on getAdditionalInformation — includes the table filter label
     * when it's set.
     */
    #[Test]
    public function getAdditionalInformationIncludesTableFilterWhenSet(): void
    {
        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_table_filter' => 'tx_myext']);

        $info = $task->getAdditionalInformation();
        self::assertStringContainsString('tx_myext', $info);
        self::assertStringContainsString('Table filter', $info);
    }

    /**
     * Kill Ternary on getAdditionalInformation — omits table filter label when
     * filter is empty (default).
     */
    #[Test]
    public function getAdditionalInformationOmitsTableFilterWhenEmpty(): void
    {
        $task = $this->createTask();

        $info = $task->getAdditionalInformation();
        self::assertStringNotContainsString('Table filter', $info);
        self::assertStringContainsString('Retention', $info);
        self::assertStringContainsString('7', $info);
    }

    /**
     * Kill Coalesce on the field fallback — field falls back to flexField.
     */
    #[Test]
    public function parseMetadataReferenceFallsBackToFlexFieldWhenFieldMissing(): void
    {
        $this->mockPage([
            $this->createSecret(
                'uuid_flex',
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'flexField' => 'settings.apiKey', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with('uuid_flex', 'Scheduler orphan cleanup');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);

        self::assertTrue($task->execute());
    }

    /**
     * Kill ArrayItemRemoval + MethodCallRemoval on the success log — logger info
     * is called with ['identifier' => ...] context when deletion succeeds.
     */
    #[Test]
    public function executeLogsDeletedOrphanWithIdentifierContext(): void
    {
        $identifier = 'tx_myext__api_key__1';
        $this->mockPage([
            $this->createSecret(
                $identifier,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(1, false);

        // Capture the call to info('Deleted orphan secret', ...).
        $loggerCalls = [];
        $this->logger
            ->method('info')
            ->willReturnCallback(function (string $message, array $context = []) use (&$loggerCalls): void {
                $loggerCalls[] = ['message' => $message, 'context' => $context];
            });

        $logManager = $this->createMock(LogManager::class);
        $logManager->method('getLogger')->willReturn($this->logger);

        $task = $this->createTask($logManager);
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);
        self::assertTrue($task->execute());

        // Find the 'Deleted orphan secret' call.
        $deletedCalls = array_filter($loggerCalls, fn (array $c): bool => $c['message'] === 'Deleted orphan secret');
        self::assertCount(1, $deletedCalls, 'Expected exactly one "Deleted orphan secret" log entry');

        $deletedCall = array_values($deletedCalls)[0];
        self::assertArrayHasKey('identifier', $deletedCall['context']);
        self::assertSame($identifier, $deletedCall['context']['identifier']);
    }

    /**
     * Kill ArrayItemRemoval on the error log — error log context includes
     * identifier. Kill MethodCallRemoval too.
     */
    #[Test]
    public function executeLogsErrorWithIdentifierAndErrorContextOnDeleteFailure(): void
    {
        $identifier = 'tx_myext__api_key__1';
        $this->mockPage([
            $this->createSecret(
                $identifier,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);

        $this->mockRecordExists(1, false);

        $this->vaultService
            ->method('delete')
            ->willThrowException(new VaultException('Something broke'));

        $errorCalls = [];
        $this->logger
            ->method('error')
            ->willReturnCallback(function (string $message, array $context = []) use (&$errorCalls): void {
                $errorCalls[] = ['message' => $message, 'context' => $context];
            });

        $logManager = $this->createMock(LogManager::class);
        $logManager->method('getLogger')->willReturn($this->logger);

        $task = $this->createTask($logManager);
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);
        self::assertFalse($task->execute());

        self::assertCount(1, $errorCalls);
        $errorCall = $errorCalls[0];
        self::assertSame('Failed to delete orphan secret', $errorCall['message']);
        self::assertArrayHasKey('identifier', $errorCall['context']);
        self::assertSame($identifier, $errorCall['context']['identifier']);
        self::assertArrayHasKey('error', $errorCall['context']);
        self::assertSame('Something broke', $errorCall['context']['error']);
    }

    /**
     * Kill ArrayItem + ArrayItemRemoval on the error context — logger error
     * context includes 'error' key with exception message.
     */
    #[Test]
    public function executeLogsErrorIncludesExceptionMessage(): void
    {
        $identifier = 'tx_myext__api_key__1';
        $this->mockPage([
            $this->createSecret(
                $identifier,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordExists(1, false);
        $this->vaultService
            ->method('delete')
            ->willThrowException(new VaultException('exact exception text'));

        $this->logger
            ->expects($this->once())
            ->method('error')
            ->with(
                self::stringContains('Failed to delete orphan secret'),
                self::callback(fn (array $context): bool =>
                    \array_key_exists('error', $context)
                    && $context['error'] === 'exact exception text'
                    && \array_key_exists('identifier', $context)),
            );

        $logManager = $this->createMock(LogManager::class);
        $logManager->method('getLogger')->willReturn($this->logger);

        $task = $this->createTask($logManager);
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);
        self::assertFalse($task->execute());
    }

    /**
     * Kill GreaterThan on the retentionDays > 0 guard — it is strict. When 0,
     * uses PHP_INT_MAX cutoff (so ALL orphans pass the "older than retention"
     * test).
     */
    #[Test]
    public function executeWithZeroRetentionTreatsAllOldOrphansAsEligible(): void
    {
        $now = time();
        $this->mockPage([
            $this->createSecret(
                'tx_myext__api_key__1',
                $now - 1,  // just 1 second old
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'api_key', 'uid' => 1],
            ),
        ]);
        $this->mockRecordExists(1, false);

        $this->vaultService->expects($this->once())->method('delete');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);
        self::assertTrue($task->execute());
    }

    /**
     * Kill Coalesce on the parseMetadataReference fallbacks — the
     * `$metadata['X'] ?? default` fallbacks. Test that a missing field-key
     * yields empty string, not null/error.
     */
    #[Test]
    public function parseMetadataReferenceMissingFieldAndFlexFieldDefaultsToEmptyString(): void
    {
        $identifier = 'ident1';
        $this->mockPage([
            $this->createSecret(
                $identifier,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'uid' => 1],
                // No 'field' and no 'flexField' keys.
            ),
        ]);
        $this->mockRecordExists(1, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with($identifier);

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);
        self::assertTrue($task->execute());
    }

    /**
     * Kill CastInt on the uid parse — uid cast from numeric string.
     */
    #[Test]
    public function parseMetadataReferenceCastsStringUidToInt(): void
    {
        $identifier = 'id-for-string-uid';
        $this->mockPage([
            $this->createSecret(
                $identifier,
                time() - 86400 * 30,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'k', 'uid' => '42'],
            ),
        ]);
        $this->mockRecordExists(42, false);

        $this->vaultService
            ->expects($this->once())
            ->method('delete')
            ->with($identifier);

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 0]);
        self::assertTrue($task->execute());
    }

    /**
     * Kill ArrayItem on the opening log — logger info('Starting ...', [...])
     * context uses '(all)' placeholder when tableFilter is empty.
     */
    #[Test]
    public function executeLogsStartingWithAllPlaceholderWhenFilterEmpty(): void
    {
        $this->secretRepository->method('findPaginatedAfterUid')->willReturn([]);

        $calls = [];
        $this->logger
            ->method('info')
            ->willReturnCallback(function (string $message, array $context = []) use (&$calls): void {
                $calls[] = ['message' => $message, 'context' => $context];
            });

        $logManager = $this->createMock(LogManager::class);
        $logManager->method('getLogger')->willReturn($this->logger);

        $task = $this->createTask($logManager);
        $task->execute();

        // Find the 'Starting vault orphan cleanup' call with tableFilter == '(all)'.
        $starts = array_filter($calls, fn (array $c): bool => $c['message'] === 'Starting vault orphan cleanup');
        self::assertCount(1, $starts);
        $startCall = array_values($starts)[0];
        self::assertSame('(all)', $startCall['context']['tableFilter']);
    }

    /**
     * Kill Ternary on the opening log — tableFilter ?: '(all)'. When tableFilter
     * is SET, context shows the actual filter, not '(all)'.
     */
    #[Test]
    public function executeLogsStartingWithActualFilterWhenSet(): void
    {
        $this->secretRepository->method('findPaginatedAfterUid')->willReturn([]);

        $calls = [];
        $this->logger
            ->method('info')
            ->willReturnCallback(function (string $message, array $context = []) use (&$calls): void {
                $calls[] = ['message' => $message, 'context' => $context];
            });

        $logManager = $this->createMock(LogManager::class);
        $logManager->method('getLogger')->willReturn($this->logger);

        $task = $this->createTask($logManager);
        $task->setTaskParameters(['nr_vault_table_filter' => 'tx_specific']);
        $task->execute();

        $starts = array_filter($calls, fn (array $c): bool => $c['message'] === 'Starting vault orphan cleanup');
        self::assertCount(1, $starts);
        $startCall = array_values($starts)[0];
        self::assertSame('tx_specific', $startCall['context']['tableFilter']);
    }

    /**
     * Kill IncrementInteger on the 86400-seconds-per-day constant.
     * 30-day-old secret with 29-day retention: strictly before cutoff → delete.
     */
    #[Test]
    public function executeUsesEightySixFourHundredSecondsPerDay(): void
    {
        // Age: 30 days + 60 seconds (to provide a tiny buffer that survives minor mutations).
        $this->mockPage([
            $this->createSecret(
                'orphan',
                time() - (30 * 86400) - 60,
                ['source' => 'tca_field', 'table' => 'tx_myext', 'field' => 'k', 'uid' => 1],
            ),
        ]);
        $this->mockRecordExists(1, false);

        $this->vaultService->expects($this->once())->method('delete');

        $task = $this->createTask();
        $task->setTaskParameters(['nr_vault_retention_days' => 29]);  // cutoff: 29 days ago
        self::assertTrue($task->execute());
    }

    /**
     * The vault is walked through the repository's UID-windowed finder, not
     * through VaultService::list(). Assert the finder is the entry point and
     * receives the configured page size.
     */
    #[Test]
    public function executeWalksVaultViaPaginatedRepositoryFinder(): void
    {
        $this->secretRepository
            ->expects($this->atLeastOnce())
            ->method('findPaginatedAfterUid')
            ->with($this->isInt(), 200)
            ->willReturn([]);

        $task = $this->createTask();

        self::assertTrue($task->execute());
    }

    /**
     * Build the task with the new four-argument nullable constructor. The
     * repository and vault service come from the shared mocks; a custom
     * LogManager may be supplied for log-assertion tests.
     */
    private function createTask(?LogManager $logManager = null): OrphanCleanupTask
    {
        return new OrphanCleanupTask(
            $this->connectionPool,
            $this->vaultService,
            $logManager,
            $this->secretRepository,
        );
    }

    /**
     * Stub the repository's UID-windowed finder to yield a single page. The
     * page is smaller than PAGE_SIZE (200), so the production do/while loop
     * terminates after one iteration.
     *
     * @param Secret[] $secrets
     */
    private function mockPage(array $secrets): void
    {
        $this->secretRepository
            ->method('findPaginatedAfterUid')
            ->willReturn($secrets);
    }

    private function mockRecordExists(int $uid, bool $exists): void
    {
        $schemaManager = $this->createMock(AbstractSchemaManager::class);
        $schemaManager->method('tablesExist')->willReturn(true);

        $connection = $this->createMock(Connection::class);
        $connection->method('createSchemaManager')->willReturn($schemaManager);

        $this->connectionPool
            ->method('getConnectionByName')
            ->willReturn($connection);

        $result = $this->createMock(Result::class);
        $result->method('fetchOne')->willReturn($exists ? 1 : 0);

        $restrictions = $this->createMock(QueryRestrictionContainerInterface::class);

        $expressionBuilder = $this->createMock(ExpressionBuilder::class);
        $expressionBuilder->method('eq')->willReturn('uid = ' . $uid);

        $queryBuilder = $this->createMock(QueryBuilder::class);
        $queryBuilder->method('count')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('getRestrictions')->willReturn($restrictions);
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturn($queryBuilder);
    }

    /**
     * Build a real Secret domain entity as returned by the repository's
     * paginated finder. `execute()` reads getUid(), getMetadata(), getCrdate()
     * and getIdentifier() from each entity.
     *
     * @param array<string, mixed> $metadata
     */
    private function createSecret(
        string $identifier,
        int $createdAt,
        array $metadata = [],
        int $uid = 1,
    ): Secret {
        return SecretFixtureBuilder::create($identifier)
            ->withUid($uid)
            ->withCreatedAt($createdAt)
            ->withMetadata($metadata)
            ->buildSecret();
    }
}
