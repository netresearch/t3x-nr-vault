<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use Doctrine\DBAL\Result;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Types\Type;
use Doctrine\DBAL\Types\Types;
use Netresearch\NrVault\Command\VaultMigrateFieldCommand;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\IdentifierValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

/**
 * Unit tests for {@see VaultMigrateFieldCommand}.
 *
 * NOTE: {@see \PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations} is
 * intentionally NOT used — it would mask orphaned mocks (i.e. real wiring bugs).
 * If a mock here triggers "unused" it's a bug in the test, not noise to be silenced.
 */
#[CoversClass(VaultMigrateFieldCommand::class)]
final class VaultMigrateFieldCommandTest extends TestCase
{
    private const MSG_SUCCESSFULLY_MIGRATED = 'Successfully migrated';

    private VaultServiceInterface $vaultService;

    private ConnectionPool $connectionPool;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService = $this->createStub(VaultServiceInterface::class);
        $this->connectionPool = $this->createStub(ConnectionPool::class);

        $this->rebuildCommandTester();
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultMigrateFieldCommand(
            $this->vaultService,
            $this->connectionPool,
        );

        self::assertSame('vault:migrate-field', $command->getName());
    }

    /**
     * Combines the two "does not exist" failure paths (table missing and field
     * missing) via a data provider since the structure is identical.
     *
     * @param array<string, Column> $columns
     */
    #[Test]
    #[DataProvider('missingSchemaProvider')]
    public function failsWhenSchemaObjectDoesNotExist(
        bool $tableExists,
        array $columns,
        string $table,
        string $field,
    ): void {
        $schemaManager = $this->createStub(AbstractSchemaManager::class);
        $schemaManager->method('tablesExist')->willReturn($tableExists);
        $schemaManager->method('listTableColumns')->willReturn($columns);

        $connection = $this->createStub(Connection::class);
        $connection->method('createSchemaManager')->willReturn($schemaManager);

        $this->connectionPool
            ->method('getConnectionByName')
            ->willReturn($connection);

        $exitCode = $this->commandTester->execute([
            'table' => $table,
            'field' => $field,
        ]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('does not exist', $this->commandTester->getDisplay());
    }

    /**
     * @return iterable<string, array{bool, array<string, Column>, string, string}>
     */
    public static function missingSchemaProvider(): iterable
    {
        yield 'table missing' => [false, [], 'nonexistent_table', 'secret_field'];
        yield 'field missing' => [true, [], 'tx_myext_settings', 'nonexistent_field'];
    }

    #[Test]
    public function succeedsWithNoRecordsToMigrate(): void
    {
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([]);

        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('No records found to migrate', $this->commandTester->getDisplay());
    }

    #[Test]
    public function dryRunShowsRecordsWithoutMigrating(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => 'secret123'],
            ['uid' => 2, 'api_key' => 'secret456'],
        ]);

        $vaultService->expects(self::never())->method('store');

        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
            '--dry-run' => true,
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Dry Run', $display);
        self::assertStringContainsString('would be migrated', $display);
    }

    #[Test]
    public function migratesRecordsWhenConfirmed(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => 'secret123'],
        ]);

        $capturedIdentifier = null;
        $vaultService
            ->expects(self::once())
            ->method('store')
            ->with(
                self::callback(static function (string $id) use (&$capturedIdentifier): bool {
                    $capturedIdentifier = $id;

                    return true;
                }),
                'secret123',
                self::callback(static fn (array $metadata): bool => $metadata['table'] === 'tx_myext_settings'
                    && $metadata['field'] === 'api_key'
                    && $metadata['uid'] === 1
                    && $metadata['source'] === 'migration'),
            );

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::MSG_SUCCESSFULLY_MIGRATED, $this->commandTester->getDisplay());
        // Use the canonical validator instead of an ad-hoc regex so the test
        // stays aligned with production's definition of "valid UUID v7".
        self::assertIsString($capturedIdentifier);
        self::assertTrue(
            IdentifierValidator::looksLikeVaultIdentifier($capturedIdentifier),
            \sprintf('Generated identifier "%s" must be a valid vault identifier', $capturedIdentifier),
        );
    }

    #[Test]
    public function cancelsWhenNotConfirmed(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => 'secret123'],
        ]);

        $vaultService->expects(self::never())->method('store');

        $this->commandTester->setInputs(['no']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('cancelled', $this->commandTester->getDisplay());
    }

    #[Test]
    public function handlesVaultExceptionDuringMigration(): void
    {
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => 'secret123'],
        ]);

        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException('Storage failed'));

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(1, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Failed', $display);
        self::assertStringContainsString('Storage failed', $display);
        // Stronger assertions: summary counts must reflect the failure.
        self::assertMatchesRegularExpression('/Total records\s*\|?\s*1/', $display);
        self::assertMatchesRegularExpression('/Successfully migrated\s*\|?\s*0/', $display);
        self::assertMatchesRegularExpression('/Failed\s*\|?\s*1/', $display);
    }

    #[Test]
    public function showsDryRunResultsWithMultipleRecords(): void
    {
        $this->mockTableAndFieldExist('api_key');
        $records = [];
        for ($i = 1; $i <= 25; $i++) {
            $records[] = ['uid' => $i, 'api_key' => 'secret' . $i];
        }
        $this->mockQueryReturnsRecords($records);

        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
            '--dry-run' => true,
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('25 records to migrate', $display);
        self::assertStringContainsString('and 5 more records', $display);
    }

    #[Test]
    public function acceptsBatchSizeOption(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => 'secret1'],
            ['uid' => 2, 'api_key' => 'secret2'],
        ]);

        $vaultService->expects(self::exactly(2))->method('store');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
            '--batch-size' => 1,
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::MSG_SUCCESSFULLY_MIGRATED, $this->commandTester->getDisplay());
    }

    #[Test]
    public function displaysNextStepsAfterMigration(): void
    {
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => 'secret123'],
        ]);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Next Steps', $display);
        self::assertStringContainsString('Update TCA configuration', $display);
    }

    #[Test]
    public function displaysMigrationSummary(): void
    {
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => 'secret123'],
            ['uid' => 2, 'api_key' => 'secret456'],
        ]);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(0, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('Migration Summary', $display);
        self::assertStringContainsString('Total records', $display);
    }

    #[Test]
    public function migratesWithClearSourceOption(): void
    {
        $schemaManager = $this->createStub(AbstractSchemaManager::class);
        $schemaManager->method('tablesExist')->willReturn(true);
        $schemaManager->method('listTableColumns')->willReturn([
            'api_key' => $this->createColumn('api_key'),
        ]);

        $connection = $this->createStub(Connection::class);
        $connection->method('createSchemaManager')->willReturn($schemaManager);

        $this->connectionPool
            ->method('getConnectionByName')
            ->willReturn($connection);

        $result = $this->createStub(Result::class);
        $result->method('fetchAllAssociative')->willReturn([
            ['uid' => 1, 'api_key' => 'secret123'],
        ]);

        $expressionBuilder = $this->createStub(ExpressionBuilder::class);
        $expressionBuilder->method('neq')->willReturn('field != ""');
        $expressionBuilder->method('isNotNull')->willReturn('field IS NOT NULL');
        $expressionBuilder->method('notLike')->willReturn('field NOT LIKE pattern');
        $expressionBuilder->method('eq')->willReturn('uid = 1');

        $readQueryBuilder = $this->createStub(QueryBuilder::class);
        $readQueryBuilder->method('select')->willReturnSelf();
        $readQueryBuilder->method('from')->willReturnSelf();
        $readQueryBuilder->method('where')->willReturnSelf();
        $readQueryBuilder->method('andWhere')->willReturnSelf();
        $readQueryBuilder->method('expr')->willReturn($expressionBuilder);
        $readQueryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $readQueryBuilder->method('executeQuery')->willReturn($result);

        $updateQueryBuilder = $this->createStub(QueryBuilder::class);
        $updateQueryBuilder->method('update')->willReturnSelf();
        $updateQueryBuilder->method('set')->willReturnSelf();
        $updateQueryBuilder->method('where')->willReturnSelf();
        $updateQueryBuilder->method('expr')->willReturn($expressionBuilder);
        $updateQueryBuilder->method('createNamedParameter')->willReturn(':dcValue2');
        $updateQueryBuilder->method('executeStatement')->willReturn(1);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturnOnConsecutiveCalls($readQueryBuilder, $updateQueryBuilder);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
            '--clear-source' => true,
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Source field has been cleared', $this->commandTester->getDisplay());
    }

    #[Test]
    public function migratesWithForceOption(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');

        // With --force, records with UUID v7 values should also be returned
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => '01234567-89ab-7cde-f012-3456789abcde'],
        ]);

        $vaultService
            ->expects(self::once())
            ->method('store');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
            '--force' => true,
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::MSG_SUCCESSFULLY_MIGRATED, $this->commandTester->getDisplay());
    }

    #[Test]
    public function migratesWithWhereClause(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 5, 'api_key' => 'secret5'],
        ]);

        $vaultService->expects(self::once())->method('store');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
            '--where' => 'pid=1',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::MSG_SUCCESSFULLY_MIGRATED, $this->commandTester->getDisplay());
    }

    #[Test]
    public function displaysMoreThanTenErrors(): void
    {
        $this->mockTableAndFieldExist('api_key');
        $records = [];
        for ($i = 1; $i <= 15; $i++) {
            $records[] = ['uid' => $i, 'api_key' => 'secret' . $i];
        }
        $this->mockQueryReturnsRecords($records);

        $this->vaultService
            ->method('store')
            ->willThrowException(new VaultException('Store failed'));

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(1, $exitCode);
        $display = $this->commandTester->getDisplay();
        self::assertStringContainsString('and 5 more errors', $display);
    }

    #[Test]
    public function dryRunShowsNonStringValueAsNonString(): void
    {
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => 42],
        ]);

        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
            '--dry-run' => true,
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('(non-string)', $this->commandTester->getDisplay());
    }

    // ------------------------------------------------------------------
    // Negative-path tests (added to cover edge cases & guard assertions).
    // ------------------------------------------------------------------

    /**
     * Batch size is typed `int` and asserted `>= 1`, so <= 0 input is a
     * programmer error that must not silently pass. Non-numeric / <=0 input
     * should be rejected either by Symfony option parsing or by the assert().
     */
    #[Test]
    public function failsWithInvalidBatchSize(): void
    {
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => 'secret'],
        ]);

        $this->expectException(Throwable::class);

        $this->commandTester->setInputs(['yes']);
        $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
            '--batch-size' => 0,
        ]);
    }

    /**
     * Empty `--uid-field` is a user error and is rejected up-front by
     * VaultMigrateFieldCommand::execute() with a clear error message,
     * before any DB work is done.
     */
    #[Test]
    public function failsWithEmptyUidField(): void
    {
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
            '--uid-field' => '',
        ]);

        self::assertNotSame(0, $exitCode, 'Empty --uid-field must be rejected');
        self::assertStringContainsString(
            '--uid-field must be a non-empty column name',
            $this->commandTester->getDisplay(),
        );
    }

    /**
     * Doctrine drivers may return NULL for a nullable text column. The command
     * casts with `(string) $value`, so a null value should be stored as '' —
     * and MUST NOT throw. Records with NULL are still included in the batch.
     */
    #[Test]
    public function handlesNullFieldValue(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 7, 'api_key' => null],
        ]);

        $vaultService
            ->expects(self::once())
            ->method('store')
            ->with(
                self::isString(),
                '',                                 // null cast to empty string
                self::callback(static fn (array $metadata): bool => $metadata['uid'] === 7),
            );

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(0, $exitCode);
    }

    /**
     * Doctrine/PDO sometimes returns integer columns as strings
     * (e.g. "1" instead of 1). The command must cope — UID should be coerced
     * to int before being passed to `$vaultService->store()` in metadata.
     */
    #[Test]
    public function handlesStringUidField(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => '42', 'api_key' => 'secret-str-uid'],
        ]);

        $vaultService
            ->expects(self::once())
            ->method('store')
            ->with(
                self::isString(),
                'secret-str-uid',
                self::callback(static fn (array $metadata): bool => $metadata['uid'] === 42
                    && \is_int($metadata['uid'])),
            );

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(0, $exitCode);
    }

    /**
     * Rebuilds the command tester using the current $vaultService / $connectionPool
     * doubles. Tests that need to upgrade $vaultService to a mock with expects()
     * call {@see useStrictVaultServiceMock()} first, which swaps the double and
     * rebuilds the tester.
     */
    private function rebuildCommandTester(): void
    {
        $command = new VaultMigrateFieldCommand(
            $this->vaultService,
            $this->connectionPool,
        );

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    private function useStrictVaultServiceMock(): VaultServiceInterface&MockObject
    {
        $mock = $this->createMock(VaultServiceInterface::class);
        $this->vaultService = $mock;
        $this->rebuildCommandTester();

        return $mock;
    }

    private function mockTableAndFieldExist(string $field): void
    {
        $schemaManager = $this->createStub(AbstractSchemaManager::class);
        $schemaManager->method('tablesExist')->willReturn(true);
        $schemaManager->method('listTableColumns')->willReturn([
            $field => $this->createColumn($field),
        ]);

        $connection = $this->createStub(Connection::class);
        $connection->method('createSchemaManager')->willReturn($schemaManager);

        $this->connectionPool
            ->method('getConnectionByName')
            ->willReturn($connection);
    }

    /**
     * @param array<int, array<string, mixed>> $records
     */
    private function mockQueryReturnsRecords(array $records): void
    {
        $result = $this->createStub(Result::class);
        $result->method('fetchAllAssociative')->willReturn($records);

        $expressionBuilder = $this->createStub(ExpressionBuilder::class);
        $expressionBuilder->method('neq')->willReturn('field != ""');
        $expressionBuilder->method('isNotNull')->willReturn('field IS NOT NULL');
        $expressionBuilder->method('notLike')->willReturn('field NOT LIKE pattern');
        $expressionBuilder->method('eq')->willReturn('deleted = 0');

        $queryBuilder = $this->createStub(QueryBuilder::class);
        $queryBuilder->method('select')->willReturnSelf();
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('andWhere')->willReturnSelf();
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturn(':dcValue1');
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturn($queryBuilder);
    }

    /**
     * Build a real Doctrine Column so the SUT's `isset($columns[$field])` check
     * exercises actual schema-object semantics rather than a brittle stdClass.
     */
    private function createColumn(string $name): Column
    {
        return new Column($name, Type::getType(Types::STRING));
    }
}
