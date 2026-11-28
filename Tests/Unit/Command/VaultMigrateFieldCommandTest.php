<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Command;

use ArrayObject;
use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Result;
use Doctrine\DBAL\Schema\AbstractSchemaManager;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Types\Type;
use Doctrine\DBAL\Types\Types;
use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Command\VaultMigrateFieldCommand;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\RecordLinkStateUnknownException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\FieldValueMigrator;
use Netresearch\NrVault\Service\SecretRecordLinkWriterInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\IdentifierValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use Psr\Log\AbstractLogger;
use Psr\Log\LogLevel;
use RuntimeException;
use Stringable;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Expression\ExpressionBuilder;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

use function array_filter;
use function array_intersect_key;
use function array_keys;
use function array_values;
use function is_array;
use function is_int;
use function is_scalar;
use function sprintf;
use function substr;

/**
 * Unit tests for {@see VaultMigrateFieldCommand}.
 *
 * NOTE: {@see \PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations} is
 * intentionally NOT used — it would mask orphaned mocks (i.e. real wiring bugs).
 * If a mock here triggers "unused" it's a bug in the test, not noise to be silenced.
 */
#[CoversClass(VaultMigrateFieldCommand::class)]
#[CoversClass(FieldValueMigrator::class)]
final class VaultMigrateFieldCommandTest extends TestCase
{
    private const MSG_SUCCESSFULLY_MIGRATED = 'Successfully migrated';

    /** What the field holds: the first record's value until an UPDATE succeeds. */
    private mixed $lastWrittenValue = null;

    /** @var array<int|string, string> The rows: key => field value. */
    private array $rows = [];

    /** What the UPDATE being built would write. */
    private mixed $pendingValue = null;

    /** Whether an UPDATE that throws has still changed the row (connection lost after the write). */
    private bool $failedUpdateApplied = false;

    /** @var list<string> exceptions rendered with their trace inside the database and link doubles */
    private array $renderedTraces = [];

    /** When set, what the read-back after the UPDATE returns instead. */
    private ?string $readBackOverride = null;

    /** When set, the mocked UPDATE throws it. */
    private ?Throwable $updateFailure = null;

    /** When set, the column keeps only this many characters of a written value. */
    private ?int $truncateAt = null;

    /** Appended to the written value by the read-back (CHAR padding). */
    private string $readBackSuffix = '';

    /** When set, the read-back throws it. */
    private ?Throwable $readBackFailure = null;

    /** The key whose read-back alone fails, when set. */
    private ?string $readBackFailsForKey = null;

    /** Rows each mocked UPDATE reports as changed. */
    private int $affectedRows = 1;

    /** @var array<string, int> What the --uid-field uniqueness count returns. */
    private array $keyCounts = ['total' => 1, 'distinct_keys' => 1];

    /** @var array<string, array<mixed>> The adapter's secrets (identifier => metadata), disabled ones included. */
    private array $secrets = [];

    /** @var array<string, Throwable> Lookups of these identifiers throw. */
    private array $lookupFailures = [];

    /** @var array<string, array<mixed>> What the record link writer merged in, per identifier. */
    private array $linkedMetadata = [];

    /** @var array<string, mixed>|null When set, what a stored secret's metadata reads as afterwards. */
    private ?array $metadataAfterStore = null;

    /** When set, the record link writer refuses with it. */
    private ?Throwable $linkFailure = null;

    /** @var array<string, array<mixed>> The created metadata each link request named, per identifier. */
    private array $linkRequests = [];

    /** When set, the vault's store() throws it. */
    private ?Throwable $storeFailure = null;

    /** @var ArrayObject<int, array{mixed, string, array<mixed>}> what the command logged */
    private ArrayObject $logRecords;

    /** The value whose store() throws, the others are stored. */
    private ?string $failStoreForValue = null;

    /** Set by an UPDATE right after the read-back: an editor saving the row in between. */
    private ?string $editorValueAfterReadBack = null;

    /** @var array<string, mixed> Values of the named parameters of the query being built. */
    private array $parameters = [];

    /** @var list<array{string, string}> The eq() conditions of the query being built: [column, parameter]. */
    private array $conditions = [];

    private VaultServiceInterface $vaultService;

    private ConnectionPool $connectionPool;

    private CommandTester $commandTester;

    protected function setUp(): void
    {
        parent::setUp();

        $this->vaultService   = $this->createStub(VaultServiceInterface::class);
        $this->connectionPool = $this->createStub(ConnectionPool::class);
        $this->logRecords     = new ArrayObject();
        $this->registerStores($this->vaultService);

        $this->rebuildCommandTester();
    }

    #[Test]
    public function hasCorrectName(): void
    {
        $command = new VaultMigrateFieldCommand($this->connectionPool, $this->migrator());

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
            ->method('getConnectionForTable')
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
            'table'     => 'tx_myext_settings',
            'field'     => 'api_key',
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

        $calls = $this->recordStores($vaultService, 1);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(0, $exitCode);
        self::assertStringContainsString(self::MSG_SUCCESSFULLY_MIGRATED, $this->commandTester->getDisplay());
        $capturedIdentifier = $this->storeCall($calls, 0)['identifier'];
        self::assertSame('secret123', $this->storeCall($calls, 0)['value']);
        self::assertSame(['migrated_at'], array_keys($this->metadataOf($this->storeCall($calls, 0)['options'], 'metadata')));
        // The link is metadata of the creation: written without a second store().
        $link = $this->linkedMetadata[$capturedIdentifier] ?? [];
        self::assertSame(['source' => 'migration', 'table' => 'tx_myext_settings', 'field' => 'api_key', 'uid' => 1], [
            'source' => $link['source'] ?? null,
            'table'  => $link['table'] ?? null,
            'field'  => $link['field'] ?? null,
            'uid'    => $link['uid'] ?? null,
        ]);
        // Use the canonical validator instead of an ad-hoc regex so the test
        // stays aligned with production's definition of "valid UUID v7".
        self::assertIsString($capturedIdentifier);
        self::assertTrue(
            IdentifierValidator::looksLikeVaultIdentifier($capturedIdentifier),
            sprintf('Generated identifier "%s" must be a valid vault identifier', $capturedIdentifier),
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

        $this->storeFailure = new VaultException('Storage failed');

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
        for ($i = 1; $i <= 25; ++$i) {
            $records[] = ['uid' => $i, 'api_key' => 'secret' . $i];
        }

        $this->mockQueryReturnsRecords($records);

        $exitCode = $this->commandTester->execute([
            'table'     => 'tx_myext_settings',
            'field'     => 'api_key',
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

        // One store() per record; the link is no second store.
        $this->recordStores($vaultService, 2);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table'        => 'tx_myext_settings',
            'field'        => 'api_key',
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

    /**
     * The field is replaced with the identifier the secret was stored under,
     * with or without the deprecated --clear-source (#565).
     */
    #[Test]
    public function writesTheStoredIdentifierIntoTheFieldAndIgnoresClearSource(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $stored       = null;
        $vaultService->expects(self::once())->method('store')
            ->willReturnCallback(function (string $identifier) use (&$stored): void {
                $stored ??= $identifier;
                $this->secrets[$identifier] = ['migrated_at' => time()];
            });

        $schemaManager = $this->createStub(AbstractSchemaManager::class);
        $schemaManager->method('tablesExist')->willReturn(true);
        $schemaManager->method('listTableColumns')->willReturn([
            'uid'     => $this->createColumn('uid'),
            'api_key' => $this->createColumn('api_key'),
        ]);

        $connection = $this->createStub(Connection::class);
        $connection->method('createSchemaManager')->willReturn($schemaManager);

        $this->connectionPool
            ->method('getConnectionForTable')
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

        $written            = null;
        $updateQueryBuilder = $this->createStub(QueryBuilder::class);
        $updateQueryBuilder->method('update')->willReturnSelf();
        $updateQueryBuilder->method('set')->willReturnCallback(
            static function (string $field, mixed $value) use (&$written, &$updateQueryBuilder): QueryBuilder {
                $written = [$field, $value];

                return $updateQueryBuilder;
            },
        );
        $updateQueryBuilder->method('where')->willReturnSelf();
        $updateQueryBuilder->method('expr')->willReturn($expressionBuilder);
        $updateQueryBuilder->method('createNamedParameter')->willReturn(':dcValue2');
        $updateQueryBuilder->method('executeStatement')->willReturn(1);

        // The read-back after the UPDATE sees what it wrote.
        $readBackResult = self::createStub(Result::class);
        $readBackResult->method('fetchOne')->willReturnCallback(static function () use (&$written): mixed {
            return $written[1] ?? null;
        });
        $readBackQueryBuilder = self::createStub(QueryBuilder::class);
        $readBackQueryBuilder->method('select')->willReturnSelf();
        $readBackQueryBuilder->method('from')->willReturnSelf();
        $readBackQueryBuilder->method('where')->willReturnSelf();
        $readBackQueryBuilder->method('expr')->willReturn($expressionBuilder);
        $readBackQueryBuilder->method('createNamedParameter')->willReturn(':dcValue3');
        $readBackQueryBuilder->method('executeQuery')->willReturn($readBackResult);

        $keyCountResult = self::createStub(Result::class);
        $keyCountResult->method('fetchAssociative')->willReturn(['total' => 1, 'distinct_keys' => 1]);
        $keyCountQueryBuilder = self::createStub(QueryBuilder::class);
        $keyCountQueryBuilder->method('selectLiteral')->willReturnSelf();
        $keyCountQueryBuilder->method('quoteIdentifier')->willReturnArgument(0);
        $keyCountQueryBuilder->method('from')->willReturnSelf();
        $keyCountQueryBuilder->method('where')->willReturnSelf();
        $keyCountQueryBuilder->method('expr')->willReturn($expressionBuilder);
        $keyCountQueryBuilder->method('executeQuery')->willReturn($keyCountResult);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturnOnConsecutiveCalls($keyCountQueryBuilder, $readQueryBuilder, $updateQueryBuilder, $readBackQueryBuilder);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table'          => 'tx_myext_settings',
            'field'          => 'api_key',
            '--clear-source' => true,
        ]);

        self::assertSame(0, $exitCode);
        self::assertIsString($stored);
        self::assertSame(['api_key', $stored], $written, 'The field must receive the identifier the secret was stored under');
        self::assertStringContainsString('--clear-source has no effect', $this->commandTester->getDisplay());
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

        $this->recordStores($vaultService, 1);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table'   => 'tx_myext_settings',
            'field'   => 'api_key',
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

        $this->recordStores($vaultService, 1);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table'   => 'tx_myext_settings',
            'field'   => 'api_key',
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
        for ($i = 1; $i <= 15; ++$i) {
            $records[] = ['uid' => $i, 'api_key' => 'secret' . $i];
        }

        $this->mockQueryReturnsRecords($records);

        $this->storeFailure = new VaultException('Store failed');

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
            'table'     => 'tx_myext_settings',
            'field'     => 'api_key',
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
            'table'        => 'tx_myext_settings',
            'field'        => 'api_key',
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
            'table'       => 'tx_myext_settings',
            'field'       => 'api_key',
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

        $calls = $this->recordStores($vaultService, 1);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(0, $exitCode);
        self::assertSame('', $this->storeCall($calls, 0)['value'], 'null is cast to the empty string');
        self::assertSame(7, $this->linkedMetadata[$this->storeCall($calls, 0)['identifier']]['uid'] ?? null);
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

        $calls = $this->recordStores($vaultService, 1);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table' => 'tx_myext_settings',
            'field' => 'api_key',
        ]);

        self::assertSame(0, $exitCode);
        self::assertSame('secret-str-uid', $this->storeCall($calls, 0)['value']);
        $uid = $this->linkedMetadata[$this->storeCall($calls, 0)['identifier']]['uid'] ?? null;
        self::assertTrue(is_int($uid) && $uid === 42);
    }

    /**
     * Orphan cleanup looks a linked record up by its `uid` column. A value
     * read from another --uid-field column would name the wrong record, so
     * such a secret is stored without a record link (#565).
     */
    #[Test]
    public function storesNoRecordLinkWhenTheUidFieldIsNotUid(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['legacy_id' => 42, 'api_key' => 'secret-legacy-id'],
        ]);

        $vaultService
            ->expects(self::once())
            ->method('store')
            ->with(
                self::isString(),
                'secret-legacy-id',
                self::callback(static fn (array $options): bool => array_keys($options) === ['metadata', 'createOnly']
                    && is_array($options['metadata'])
                    && array_keys($options['metadata']) === ['migrated_at']),
            );

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute([
            'table'       => 'tx_myext_settings',
            'field'       => 'api_key',
            '--uid-field' => 'legacy_id',
        ]);

        self::assertSame(0, $exitCode);
    }

    /**
     * Non-strict SQL truncates instead of failing: the read-back catches it.
     * The original value is written back and read back; only then is the
     * secret just stored deleted again (#565).
     */
    #[Test]
    public function aFieldThatDoesNotHoldTheIdentifierAfterTheUpdateFailsTheRecord(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-truncated']]);
        $this->truncateAt = 16;

        $stored = null;
        $vaultService->expects(self::once())->method('store')
            ->willReturnCallback(function (string $identifier) use (&$stored): void {
                $stored                     = $identifier;
                $this->secrets[$identifier] = ['migrated_at' => time()];
            });
        $vaultService->expects(self::once())->method('delete')
            ->with(self::callback(static function (string $identifier) use (&$stored): bool {
                return $identifier === $stored;
            }));

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);
        self::assertStringNotContainsString('Failed, secret kept', $this->normalizedDisplay(), 'No secret was kept');

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('does not hold the identifier after the update; the original value was written back; the stored secret was deleted again', $this->normalizedDisplay());
        self::assertSame('secret-truncated', $this->lastWrittenValue, 'The row must hold its plaintext again');
    }

    /**
     * Once the UPDATE has changed the row, the secret may be the only copy of
     * the value: when the original cannot be written back, the secret is kept
     * and named (#565).
     */
    #[Test]
    public function aSecretIsKeptWhenTheOriginalValueCannotBeWrittenBack(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'a-secret-longer-than-the-column']]);
        $this->truncateAt = 16;

        $calls = $this->recordStores($vaultService, 1);
        $vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);
        self::assertSame(1, substr_count($this->normalizedDisplay(), 'Failed, secret kept'), 'Listed among the records whose secret was kept');

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('could not be written back; the value is kept in the secret ' . $this->storeCall($calls, 0)['identifier'], $this->normalizedDisplay());
        self::assertSame(['migrated_at'], array_keys($this->metadataOf($this->storeCall($calls, 0)['options'], 'metadata')), 'A kept secret has no record link, so orphan cleanup cannot delete it');
        self::assertSame([], $this->linkedMetadata);
    }

    /**
     * A read-back that is not a truncation of the identifier was written by
     * someone else after the UPDATE: the row is left alone and the secret
     * kept (#565).
     */
    #[Test]
    public function aValueSomeoneElseWroteAfterTheUpdateIsLeftAlone(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-before-edit']]);
        $this->readBackOverride = 'edited-by-an-editor';

        $calls = $this->recordStores($vaultService, 1);
        $vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);
        self::assertSame(1, substr_count($this->normalizedDisplay(), 'Failed, secret kept'), 'Listed among the records whose secret was kept');

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('so the row was left as it is', $this->normalizedDisplay());
        self::assertSame($this->storeCall($calls, 0)['identifier'], $this->lastWrittenValue, 'No restore UPDATE may run');
    }

    /**
     * An editor saving the row between the read-back and the restore keeps
     * the editor's value: the restore UPDATE names the value it replaces
     * (#565).
     */
    #[Test]
    public function aRestoreDoesNotOverwriteAnEditMadeAfterTheReadBack(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-truncated']]);
        $this->truncateAt               = 16;
        $this->editorValueAfterReadBack = 'edited';

        $this->recordStores($vaultService, 1);
        $vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        self::assertSame(1, $exitCode);
        self::assertSame('edited', $this->lastWrittenValue, "The editor's value must survive");
        self::assertStringContainsString('could not be written back', $this->normalizedDisplay());
    }

    /**
     * A value changed between the SELECT and the UPDATE is not overwritten:
     * the UPDATE names the value read, matches nothing, and the secret just
     * stored is discarded (#565).
     */
    #[Test]
    public function aValueChangedBeforeTheUpdateIsNotOverwritten(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-as-read']]);
        $this->rows['1'] = 'changed-meanwhile';

        $calls = $this->recordStores($vaultService, 1);
        $vaultService->expects(self::once())->method('delete')
            ->with(self::callback(fn (string $identifier): bool => $identifier === $this->storeCall($calls, 0)['identifier']));

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        self::assertSame(1, $exitCode);
        self::assertSame('changed-meanwhile', $this->rowValue('1'));
        self::assertStringContainsString('the row changed or is gone', $this->normalizedDisplay());
    }

    /**
     * The link goes through the vault's audited link path with the metadata
     * the creation stored. When that path refuses, the row is migrated (it
     * holds the identifier) and reported as migrated without its record link,
     * since a re-run skips it (#565).
     */
    #[Test]
    public function aRefusedRecordLinkIsReported(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-link-refused']]);
        $this->linkFailure = new VaultException('missing secret.create permission', 1795000001);

        $calls = $this->recordStores($vaultService, 1);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        self::assertSame(1, $exitCode, 'A run that leaves records unlinked must not exit as a success');
        $display = $this->normalizedDisplay();
        self::assertStringContainsString('Migrated, unlinked UID 1: the field holds the identifier', $display);
        self::assertStringContainsString('the record link could not be stored (missing secret.create permission)', $display);
        self::assertSame(1, substr_count(strtolower($display), 'migrated, unlinked'), 'The label is printed once');
        self::assertStringContainsString('1 record(s) were migrated with their record link missing or of unknown state', $display);
        self::assertStringNotContainsString('Migration completed successfully', $display);
        self::assertStringContainsString('Next Steps', $display, 'The migrated values need the same follow-up');
        self::assertStringNotContainsString('Fix and re-run the failed records', $display, 'No record failed');
        self::assertMatchesRegularExpression('/Successfully migrated\s*\|?\s*1/', $display);
        self::assertSame([], $this->linkedMetadata);
        self::assertSame(['migrated_at'], array_keys($this->linkRequests[$this->storeCall($calls, 0)['identifier']] ?? []), 'The writer is asked with the metadata the creation stored');
    }

    /**
     * A failed record whose secret was kept as the possible only copy of its
     * value cannot be recovered by a re-run: every one is listed, beyond the
     * ten ordinary errors, and logged as a warning with identifier, table,
     * field and uid. The Next Steps then ask to check each failed record
     * (#565).
     */
    #[Test]
    public function everyRecordWhoseSecretWasKeptIsListedAndLogged(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $records = [];
        for ($uid = 1; $uid <= 12; ++$uid) {
            $records[] = ['uid' => $uid, 'api_key' => 'secret-kept-' . $uid];
        }

        $this->mockQueryReturnsRecords($records);
        $this->readBackFailure = new class ('connection lost') extends RuntimeException implements DbalException {};
        $calls                 = $this->recordStores($vaultService, 12);
        $vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        self::assertSame(1, $exitCode);
        $display = $this->normalizedDisplay();
        self::assertSame(12, substr_count($display, 'could not be read back (connection lost)'), 'No cap for records whose secret was kept');
        self::assertStringNotContainsString('more errors', $display);
        $warnings = array_values(array_filter($this->logRecords->getArrayCopy(), static fn (array $record): bool => $record[0] === LogLevel::WARNING));
        self::assertCount(12, $warnings, 'One warning per record');
        self::assertSame(
            ['identifier' => $this->storeCall($calls, 11)['identifier'], 'table' => 'tx_myext_settings', 'field' => 'api_key', 'uid' => '12'],
            array_intersect_key($warnings[11][2], ['identifier' => true, 'table' => true, 'field' => true, 'uid' => true]),
        );
    }

    /**
     * A failed record whose secret was kept may hold the identifier or
     * another value: the Next Steps ask to check each failed record instead
     * of saying none holds it (#565).
     */
    #[Test]
    public function theNextStepsAskToCheckFailedRecordsWhoseSecretWasKept(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-migrates'], ['uid' => 2, 'api_key' => 'secret-read-back-fails']]);
        $this->readBackFailsForKey = '2';
        $this->recordStores($vaultService, 2);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        self::assertSame(1, $exitCode);
        $display = $this->normalizedDisplay();
        self::assertStringContainsString('check each failed record, which may hold the identifier or another value', $display);
        self::assertStringNotContainsString('the failed ones do not', $display);
    }

    /**
     * With zend.exception_ignore_args off (the default of the official php
     * Docker image), a rendered stack trace shows the arguments of every
     * frame. No frame on the way from the command to the database or the
     * link writer may show the plaintext: each parameter that carries it is
     * a SensitiveParameter (#565).
     *
     * @return iterable<string, array{string, list<string>}>
     */
    public static function plaintextPathProvider(): iterable
    {
        yield 'migrated and linked' => ['link', ['migrateRecords(', 'migrateRecord(', 'migrate(', 'migrateValue(', 'writeField(']];
        yield 'truncated and restored' => ['truncate', ['restore(', 'writeField(']];
        yield 'failed update' => ['update', ['afterFailedUpdate(']];
    }

    /**
     * @param list<string> $frames
     */
    #[Test]
    #[DataProvider('plaintextPathProvider')]
    public function noStackTraceShowsThePlaintext(string $path, array $frames): void
    {
        // The PHP defaults: arguments shown, strings cut at 15 characters.
        $previous       = ini_set('zend.exception_ignore_args', '0');
        $previousLength = ini_set('zend.exception_string_param_max_len', '15');
        self::assertNotFalse($previous, 'zend.exception_ignore_args can be set at runtime');
        self::assertNotFalse($previousLength);

        try {
            $vaultService = $this->useStrictVaultServiceMock();
            $this->mockTableAndFieldExist('api_key');
            $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'plaintext-SECRET-value-1']]);
            if ($path === 'truncate') {
                $this->truncateAt = 16;
            } elseif ($path === 'update') {
                $this->updateFailure       = new class ('connection lost', 1795000013) extends RuntimeException implements DbalException {};
                $this->failedUpdateApplied = true;
            }

            $this->recordStores($vaultService, 1);
            $this->commandTester->setInputs(['yes']);
            $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
            ini_set('zend.exception_string_param_max_len', $previousLength);
        }

        $traces = implode("\n", $this->renderedTraces);
        self::assertStringContainsString("'tx_myext_settin", $traces, 'The traces show string arguments at all');
        foreach ($frames as $frame) {
            self::assertStringContainsString($frame, $traces, 'The path runs through ' . $frame);
        }

        self::assertStringContainsString('Object(SensitiveParameterValue)', $traces);
        self::assertStringNotContainsString('plaintext-SECRE', $traces, 'No frame shows the plaintext');
    }

    /**
     * A record migrated without its link is logged with the same context
     * (#565).
     */
    #[Test]
    public function anUnlinkedRecordIsLogged(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 3, 'api_key' => 'secret-link-refused']]);
        $this->linkFailure = new VaultException('missing secret.create permission', 1795000007);
        $calls             = $this->recordStores($vaultService, 1);

        $this->commandTester->setInputs(['yes']);
        $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        $records = $this->logRecords->getArrayCopy();
        self::assertCount(1, $records);
        [$level, , $context] = $records[0];
        self::assertSame(LogLevel::WARNING, $level);
        self::assertSame(
            ['identifier' => $this->storeCall($calls, 0)['identifier'], 'table' => 'tx_myext_settings', 'field' => 'api_key', 'uid' => '3'],
            array_intersect_key($context, ['identifier' => true, 'table' => true, 'field' => true, 'uid' => true]),
        );
    }

    /**
     * A run with a failed record and a record migrated without its link
     * reports both, each with its own warning, and prints the Next Steps:
     * the migrated value needs them whatever happened to the other record
     * (#565).
     */
    #[Test]
    public function aFailedAndAnUnlinkedRecordAreBothReported(): void
    {
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([
            ['uid' => 1, 'api_key' => 'secret-store-fails'],
            ['uid' => 2, 'api_key' => 'secret-link-refused'],
        ]);
        $this->failStoreForValue = 'secret-store-fails';
        $this->linkFailure       = new VaultException('missing secret.create permission', 1795000005);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        self::assertSame(1, $exitCode);
        $display = $this->normalizedDisplay();
        self::assertStringContainsString('Migration completed with 1 errors', $display);
        self::assertStringContainsString('1 record(s) were migrated with their record link missing or of unknown state', $display);
        self::assertStringContainsString('Next Steps', $display);
        self::assertMatchesRegularExpression('/Next Steps\W+Fix and re-run the failed records before you change the TCA configuration/', $display, 'With failed records, fixing them comes first');
        self::assertStringNotContainsString('The field now holds the vault identifier', $display, 'Not every record holds it');
        self::assertStringContainsString('the failed ones do not', $display, 'An ordinary failure leaves the row without the identifier');
        self::assertStringNotContainsString('Migration completed successfully', $display);
    }

    /**
     * A link that was written and could not be taken back may be in the row
     * or not: the report says that instead of claiming the cleanup ignores
     * the secret (#565).
     */
    #[Test]
    public function aRecordLinkInAnUnknownStateIsReportedAsSuch(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-link-unknown']]);
        $this->linkFailure = RecordLinkStateUnknownException::afterFailedTakeBack(
            'some-id',
            new VaultException('registry read timed out', 1795000002),
            new VaultException('registry write failed', 1795000003),
        );

        $this->recordStores($vaultService, 1);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        self::assertSame(1, $exitCode);
        $display = $this->normalizedDisplay();
        self::assertStringContainsString('but the state of its record link is unknown', $display);
        self::assertStringContainsString('see the critical log', $display);
        self::assertStringNotContainsString('orphan cleanup will not consider this secret', $display);
    }

    /**
     * The secret is deleted again only while it is the one this run stored:
     * a secret whose metadata changed in the meantime is left alone (#565).
     */
    #[Test]
    public function aSecretThatIsNoLongerThisRunsIsNotDiscarded(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-taken-over']]);
        $this->affectedRows       = 0;
        $this->metadataAfterStore = ['migrated_at' => 1, 'source' => 'tca_field'];

        $this->recordStores($vaultService, 1);
        $vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('is no longer the one this run stored, so it was not deleted', $this->normalizedDisplay());
    }

    /**
     * A plaintext that happens to be the friendly name of an existing secret
     * is migrated, not skipped: only a UUID counts as an identifier the field
     * already holds (#565).
     */
    #[Test]
    public function aPlaintextNamingAnExistingSecretIsMigrated(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 2, 'api_key' => 'deploy_token_prod']]);
        $this->secrets['deploy_token_prod'] = [];

        $calls = $this->recordStores($vaultService, 1);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key', '--force' => true]);

        self::assertSame(0, $exitCode, $this->commandTester->getDisplay());
        self::assertSame('deploy_token_prod', $this->storeCall($calls, 0)['value']);
        self::assertStringNotContainsString('Skipped UID', $this->commandTester->getDisplay());
    }

    /**
     * A non-numeric --uid-field value is reported as it is, not as 0 (#565).
     */
    #[Test]
    public function aNonNumericKeyIsReportedAsItIs(): void
    {
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['legacy_id' => 'key-abc', 'api_key' => 'secret-text-key']]);
        $this->storeFailure = new VaultException('Storage failed', 1795000002);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key', '--uid-field' => 'legacy_id']);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('UID key-abc: the value could not be stored: Storage failed', $this->normalizedDisplay());
    }

    /**
     * A read-back that fails cannot tell whether the row holds the
     * identifier: the secret is kept (#565).
     */
    #[Test]
    public function aSecretIsKeptWhenTheReadBackFails(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-unknown']]);
        $this->readBackFailure = new class ('connection lost') extends RuntimeException implements DbalException {};

        $calls = $this->recordStores($vaultService, 1);
        $vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);
        self::assertSame(1, substr_count($this->normalizedDisplay(), 'Failed, secret kept'), 'Listed among the records whose secret was kept');

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('the secret ' . $this->storeCall($calls, 0)['identifier'] . ' was kept', $this->normalizedDisplay());
    }

    /**
     * An UPDATE that matched no row left the plaintext in place: the secret
     * is redundant and deleted (#565).
     */
    #[Test]
    public function anUpdateThatMatchedNoRowDeletesTheStoredSecret(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-gone-row']]);
        $this->affectedRows = 0;

        $calls = $this->recordStores($vaultService, 1);
        $vaultService->expects(self::once())->method('delete')
            ->with(self::callback(fn (string $identifier): bool => $identifier === $this->storeCall($calls, 0)['identifier']));

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);
        self::assertStringNotContainsString('Failed, secret kept', $this->normalizedDisplay(), 'No secret was kept');

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('no row with this key holds the value read before the update (the row changed or is gone); the stored secret was deleted again', $this->normalizedDisplay());
    }

    /**
     * An UPDATE that changed several rows overwrote plaintexts the secret
     * does not hold: the record fails and the secret is kept (#565).
     */
    #[Test]
    public function anUpdateThatChangedSeveralRowsKeepsTheSecret(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-many-rows']]);
        $this->affectedRows = 2;

        $this->recordStores($vaultService, 1);
        $vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);
        self::assertSame(1, substr_count($this->normalizedDisplay(), 'Failed, secret kept'), 'Listed among the records whose secret was kept');

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('the update changed 2 rows', $this->normalizedDisplay());
    }

    /**
     * PostgreSQL returns a CHAR column padded with spaces. The padding is not
     * a mismatch: the record migrates and the secret stays (#565).
     */
    #[Test]
    public function aPaddedReadBackCountsAsTheIdentifier(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-char']]);
        $this->readBackSuffix = '    ';

        $this->recordStores($vaultService, 1);
        $vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        self::assertSame(0, $exitCode, $this->commandTester->getDisplay());
    }

    /**
     * A --uid-field value shared by several rows would write one identifier
     * into all of them: the command refuses before it changes anything (#565).
     */
    #[Test]
    public function aUidFieldThatIsNotUniqueIsRefused(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['legacy_id' => 1, 'api_key' => 'secret-dup']]);
        $this->keyCounts = ['total' => 3, 'distinct_keys' => 2];

        $vaultService->expects(self::never())->method('store');

        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key', '--uid-field' => 'legacy_id']);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('--uid-field "legacy_id" is not unique: 1 row(s)', $this->normalizedDisplay());
    }

    #[Test]
    public function aUidFieldThatDoesNotExistIsRefused(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');

        $vaultService->expects(self::never())->method('store');

        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key', '--uid-field' => 'missing_id']);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Field "missing_id" (--uid-field) does not exist', $this->normalizedDisplay());
    }

    /**
     * When the vault cannot say whether a value is an existing identifier,
     * that record fails and the run continues with the next one (#565).
     */
    #[Test]
    public function aFailingExistsCheckFailsTheRecordAndTheRunContinues(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $existingLooking = '01937b6e-4b6c-7abc-8def-0123456789ab';
        $this->mockQueryReturnsRecords([
            ['uid' => 3, 'api_key' => $existingLooking],
            ['uid' => 4, 'api_key' => 'secret-after'],
        ]);

        $this->lookupFailures[$existingLooking] = new VaultException('vault unreachable', 9950960190);
        $calls                                  = $this->recordStores($vaultService, 1);

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key', '--force' => true]);

        self::assertSame(1, $exitCode);
        $display = $this->normalizedDisplay();
        self::assertStringContainsString('UID 3: could not check whether the value is a vault identifier: vault unreachable', $display);
        self::assertSame('secret-after', $this->storeCall($calls, 0)['value'], 'The next record is still migrated');
        self::assertMatchesRegularExpression('/Successfully migrated\s*\|?\s*1/', $display);
    }

    /**
     * A failed UPDATE leaves a secret nothing references. With --uid-field
     * other than uid it also has no record link, so orphan cleanup would
     * never find it: the command deletes it at once (#565).
     */
    #[Test]
    public function aFailedUpdateDeletesTheStoredSecret(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['legacy_id' => 7, 'api_key' => 'secret-update-fails']]);
        $this->updateFailure = new class ('database gone') extends RuntimeException implements DbalException {};

        $stored = null;
        $vaultService->expects(self::once())->method('store')
            ->willReturnCallback(function (string $identifier) use (&$stored): void {
                $stored                     = $identifier;
                $this->secrets[$identifier] = ['migrated_at' => time()];
            });
        $vaultService->expects(self::once())->method('delete')
            ->with(self::callback(static function (string $identifier) use (&$stored): bool {
                return $identifier === $stored;
            }));

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key', '--uid-field' => 'legacy_id']);
        self::assertStringNotContainsString('Failed, secret kept', $this->normalizedDisplay(), 'No secret was kept');

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('the stored secret was deleted again', $this->commandTester->getDisplay());
    }

    /**
     * An UPDATE can fail after the server applied it (connection lost). The
     * read-back shows the row no longer holds the plaintext, so the secret
     * is kept (#565).
     */
    #[Test]
    public function aFailedUpdateThatStillChangedTheRowKeepsTheSecret(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-applied']]);
        $this->updateFailure       = new class ('connection lost') extends RuntimeException implements DbalException {};
        $this->failedUpdateApplied = true;

        $calls = $this->recordStores($vaultService, 1);
        $vaultService->expects(self::never())->method('delete');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);
        self::assertSame(1, substr_count($this->normalizedDisplay(), 'Failed, secret kept'), 'Listed among the records whose secret was kept');

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('so the secret ' . $this->storeCall($calls, 0)['identifier'] . ' was kept', $this->normalizedDisplay());
    }

    /**
     * When the database gives no usable answer to the uniqueness count, the
     * command refuses instead of assuming the key is unique (#565).
     */
    #[Test]
    public function anUnanswerableUniquenessCheckIsRefused(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $this->mockQueryReturnsRecords([['uid' => 1, 'api_key' => 'secret-unknown-keys']]);
        $this->keyCounts = [];

        $vaultService->expects(self::never())->method('store');

        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key']);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('Could not check that --uid-field "uid" is unique', $this->normalizedDisplay());
    }

    /**
     * A value that is the identifier of an existing secret is skipped: a new
     * secret wrapping it would orphan the old one (#565).
     */
    #[Test]
    public function aValueThatIsAnExistingVaultIdentifierIsSkipped(): void
    {
        $vaultService = $this->useStrictVaultServiceMock();
        $this->mockTableAndFieldExist('api_key');
        $existing = '01937b6e-4b6c-7abc-8def-0123456789ab';
        $this->mockQueryReturnsRecords([['uid' => 3, 'api_key' => $existing]]);

        $this->secrets[$existing] = [];
        $vaultService->expects(self::never())->method('store');

        $this->commandTester->setInputs(['yes']);
        $exitCode = $this->commandTester->execute(['table' => 'tx_myext_settings', 'field' => 'api_key', '--force' => true]);

        self::assertSame(0, $exitCode);
        $display = $this->normalizedDisplay();
        self::assertStringContainsString('Skipped UID 3: the field already holds the identifier of an existing secret', $display);
        self::assertStringNotContainsString($existing, $display, 'The skipped line must not print the field value');
    }

    /**
     * Rebuilds the command tester using the current $vaultService / $connectionPool
     * doubles. Tests that need to upgrade $vaultService to a mock with expects()
     * call {@see useStrictVaultServiceMock()} first, which swaps the double and
     * rebuilds the tester.
     */
    private function rebuildCommandTester(): void
    {
        $logger = new class ($this->logRecords) extends AbstractLogger {
            /**
             * @param ArrayObject<int, array{mixed, string, array<mixed>}> $records
             */
            public function __construct(private readonly ArrayObject $records) {}

            public function log($level, string|Stringable $message, array $context = []): void
            {
                $this->records[] = [$level, (string) $message, $context];
            }
        };
        $command = new VaultMigrateFieldCommand($this->connectionPool, $this->migrator(), $logger);

        $application = new Application();
        $application->addCommand($command);

        $this->commandTester = new CommandTester($command);
    }

    private function useStrictVaultServiceMock(): VaultServiceInterface&MockObject
    {
        $mock               = $this->createMock(VaultServiceInterface::class);
        $this->vaultService = $mock;
        $this->registerStores($mock);
        $this->rebuildCommandTester();

        return $mock;
    }

    private function mockTableAndFieldExist(string $field): void
    {
        $schemaManager = $this->createStub(AbstractSchemaManager::class);
        $schemaManager->method('tablesExist')->willReturn(true);
        $schemaManager->method('listTableColumns')->willReturn([
            'uid'       => $this->createColumn('uid'),
            'legacy_id' => $this->createColumn('legacy_id'),
            $field      => $this->createColumn($field),
        ]);

        $connection = $this->createStub(Connection::class);
        $connection->method('createSchemaManager')->willReturn($schemaManager);

        $this->connectionPool
            ->method('getConnectionForTable')
            ->willReturn($connection);
    }

    /**
     * @param array<int, array<string, mixed>> $records
     */
    private function mockQueryReturnsRecords(array $records): void
    {
        // The read-back after the UPDATE returns what the UPDATE wrote, as a
        // database would.
        $result = $this->createStub(Result::class);
        foreach ($records as $record) {
            $key = $record['uid'] ?? $record['legacy_id'] ?? null;
            if (is_scalar($key)) {
                $value                     = $record['api_key'] ?? '';
                $this->rows[(string) $key] = is_scalar($value) ? (string) $value : '';
            }
        }

        $this->lastWrittenValue = $records[0]['api_key'] ?? null;
        $result->method('fetchAllAssociative')->willReturn($records);
        $result->method('fetchAssociative')->willReturnCallback(fn (): array => $this->keyCounts);
        $result->method('fetchOne')->willReturnCallback(function (): mixed {
            $this->renderedTraces[] = (string) new RuntimeException('trace probe', 1795000011);
            if ($this->readBackFailure instanceof Throwable) {
                throw $this->readBackFailure;
            }

            if ($this->readBackFailsForKey !== null && $this->keyOfQuery() === $this->readBackFailsForKey) {
                throw new class ('connection lost for one record', 6515316942) extends RuntimeException implements DbalException {};
            }

            if ($this->readBackOverride !== null) {
                return $this->readBackOverride;
            }

            $key      = $this->keyOfQuery();
            $written  = $this->rows[$key] ?? '';
            $readBack = $written . $this->readBackSuffix;
            if ($this->editorValueAfterReadBack !== null) {
                $this->writeRow($key, $this->editorValueAfterReadBack);
                $this->editorValueAfterReadBack = null;
            }

            return $readBack;
        });

        $expressionBuilder = $this->createStub(ExpressionBuilder::class);
        $expressionBuilder->method('neq')->willReturn('field != ""');
        $expressionBuilder->method('isNotNull')->willReturn('field IS NOT NULL');
        $expressionBuilder->method('notLike')->willReturn('field NOT LIKE pattern');
        $expressionBuilder->method('eq')->willReturnCallback(function (string $column, mixed $parameter): string {
            $this->conditions[] = [$column, is_scalar($parameter) ? (string) $parameter : ''];

            return 'eq';
        });

        $queryBuilder = $this->createStub(QueryBuilder::class);
        $queryBuilder->method('update')->willReturnCallback(function () use (&$queryBuilder): QueryBuilder {
            $this->conditions = [];

            return $queryBuilder;
        });
        $queryBuilder->method('set')->willReturnCallback(function (string $field, mixed $value) use (&$queryBuilder): QueryBuilder {
            $this->pendingValue = $value;

            return $queryBuilder;
        });
        $queryBuilder->method('executeStatement')->willReturnCallback(function (): int {
            $this->renderedTraces[] = (string) new RuntimeException('trace probe', 1795000012);
            $key                    = $this->keyOfQuery();
            $failure                = $this->updateFailure;
            if ($failure instanceof Throwable) {
                if ($this->failedUpdateApplied) {
                    $this->writeRow($key, $this->pendingValue);
                }

                throw $failure;
            }

            // `api_key = :expected` matches only while the row holds that value.
            foreach ($this->conditions as [$column, $parameter]) {
                if ($column === 'api_key' && ($this->parameters[$parameter] ?? null) !== ($this->rows[$key] ?? null)) {
                    return 0;
                }
            }

            if ($this->affectedRows > 0) {
                $this->writeRow($key, $this->pendingValue);
            }

            return $this->affectedRows;
        });
        $queryBuilder->method('select')->willReturnCallback(function () use (&$queryBuilder): QueryBuilder {
            $this->conditions = [];

            return $queryBuilder;
        });
        $queryBuilder->method('selectLiteral')->willReturnSelf();
        $queryBuilder->method('quoteIdentifier')->willReturnArgument(0);
        $queryBuilder->method('from')->willReturnSelf();
        $queryBuilder->method('where')->willReturnSelf();
        $queryBuilder->method('andWhere')->willReturnSelf();
        $queryBuilder->method('expr')->willReturn($expressionBuilder);
        $queryBuilder->method('createNamedParameter')->willReturnCallback(function (mixed $value): string {
            $placeholder                    = ':dcValue' . (count($this->parameters) + 1);
            $this->parameters[$placeholder] = $value;

            return $placeholder;
        });
        $queryBuilder->method('executeQuery')->willReturn($result);

        $this->connectionPool
            ->method('getQueryBuilderForTable')
            ->willReturn($queryBuilder);
    }

    /**
     * Record every store() call; the mock expects exactly $times of them.
     *
     * @return ArrayObject<int, array{identifier: string, value: string, options: array<mixed>}>
     */
    private function recordStores(VaultServiceInterface&MockObject $vaultService, int $times): ArrayObject
    {
        $calls = new ArrayObject();
        $vaultService->expects(self::exactly($times))->method('store')
            ->willReturnCallback(static function (string $identifier, string $value, array $options = []) use ($calls): void {
                $calls[] = ['identifier' => $identifier, 'value' => $value, 'options' => $options];
            });
        $this->registerStores($vaultService);

        return $calls;
    }

    /**
     * The key the query being built selects or updates: its eq() condition on
     * a column other than the field.
     */
    private function keyOfQuery(): string
    {
        foreach ($this->conditions as [$column, $parameter]) {
            if ($column !== 'api_key') {
                $value = $this->parameters[$parameter] ?? '';

                return is_scalar($value) ? (string) $value : '';
            }
        }

        return '';
    }

    /**
     * @param array<mixed> $metadata
     *
     * @return array<string, mixed>
     */
    private function stringKeyed(array $metadata): array
    {
        $result = [];
        foreach ($metadata as $key => $value) {
            $result[(string) $key] = $value;
        }

        return $result;
    }

    private function rowValue(string $key): string
    {
        return $this->rows[$key] ?? '';
    }

    private function writeRow(string $key, mixed $value): void
    {
        // A truncating column (non-strict SQL) keeps only the first characters.
        $value                  = is_scalar($value) ? (string) $value : '';
        $this->rows[$key]       = $this->truncateAt === null ? $value : substr($value, 0, $this->truncateAt);
        $this->lastWrittenValue = $this->rows[$key];
    }

    /**
     * The migrator under test, on the current doubles. The adapter double
     * holds the secrets the vault double stored.
     */
    private function migrator(): FieldValueMigrator
    {
        $adapter = self::createStub(VaultAdapterInterface::class);
        $adapter->method('retrieveIncludingDisabled')->willReturnCallback(function (string $identifier): ?Secret {
            if (isset($this->lookupFailures[$identifier])) {
                throw $this->lookupFailures[$identifier];
            }

            return isset($this->secrets[$identifier]) ? new Secret(identifier: $identifier, metadata: $this->stringKeyed($this->secrets[$identifier])) : null;
        });

        $linkWriter = self::createStub(SecretRecordLinkWriterInterface::class);
        $linkWriter->method('linkCreatedSecret')->willReturnCallback(function (string $identifier, array $createdMetadata, array $link): void {
            $this->renderedTraces[]          = (string) new RuntimeException('trace probe', 1795000010);
            $this->linkRequests[$identifier] = $createdMetadata;
            $failure                         = $this->linkFailure;
            if ($failure instanceof Throwable) {
                throw $failure;
            }

            $this->linkedMetadata[$identifier] = $link;
            $this->secrets[$identifier]        = array_replace($this->secrets[$identifier] ?? [], $link);
        });

        return new FieldValueMigrator($this->vaultService, $this->connectionPool, $adapter, $linkWriter);
    }

    /**
     * The vault double records each stored secret with its metadata, so the
     * adapter double sees it; with $storeFailure set, store() throws.
     */
    private function registerStores(VaultServiceInterface $vaultService): void
    {
        if (!$vaultService instanceof MockObject && !$vaultService instanceof Stub) {
            return;
        }

        $vaultService->method('store')->willReturnCallback(function (string $identifier, string $value, array $options = []): void {
            $failure = $this->storeFailure;
            if ($failure instanceof Throwable) {
                throw $failure;
            }

            if ($value === $this->failStoreForValue) {
                throw new VaultException('Storage failed for one record', 1795000004);
            }

            $metadata                   = $this->metadataAfterStore ?? $options['metadata'] ?? [];
            $this->secrets[$identifier] = is_array($metadata) ? $metadata : [];
        });
    }

    /**
     * @param ArrayObject<int, array{identifier: string, value: string, options: array<mixed>}> $calls
     *
     * @return array{identifier: string, value: string, options: array<mixed>}
     */
    private function storeCall(ArrayObject $calls, int $index): array
    {
        $call = $calls[$index] ?? null;
        self::assertIsArray($call, sprintf('store() call %d was not made', $index + 1));

        return $call;
    }

    /**
     * @param array<mixed> $options
     *
     * @return array<mixed>
     */
    private function metadataOf(array $options, string $key): array
    {
        // The migration only ever creates: createOnly refuses an identifier
        // a concurrent run took in the meantime.
        self::assertSame([$key, 'createOnly'], array_keys($options));
        self::assertTrue($options['createOnly']);
        $metadata = $options[$key];
        self::assertTrue(is_array($metadata));

        return $metadata;
    }

    /**
     * The display with SymfonyStyle's line wrapping undone.
     */
    private function normalizedDisplay(): string
    {
        return (string) preg_replace('/\s+/', ' ', $this->commandTester->getDisplay());
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
