<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Types\StringType;
use Doctrine\DBAL\Types\TextType;
use Netresearch\NrVault\Domain\Dto\SecretRecordLink;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function array_slice;
use function assert;
use function count;
use function is_int;
use function is_string;
use function sprintf;
use function strlen;

/**
 * CLI command to migrate existing plaintext fields to vault storage.
 *
 * This command helps extensions transition from storing sensitive data
 * in plaintext database columns to using vault-backed TCA fields.
 *
 * Usage:
 *   vendor/bin/typo3 vault:migrate-field tx_myext_settings api_key
 *   vendor/bin/typo3 vault:migrate-field tx_myext_settings api_key --dry-run
 *   vendor/bin/typo3 vault:migrate-field tx_myext_settings api_key --batch-size=100
 */
#[AsCommand(
    name: 'vault:migrate-field',
    description: 'Migrate existing plaintext database field values to vault storage',
)]
final class VaultMigrateFieldCommand extends Command
{
    /** Length of the UUID v7 identifiers this command writes. */
    private const IDENTIFIER_LENGTH = 36;

    public function __construct(
        private readonly VaultServiceInterface $vaultService,
        private readonly ConnectionPool $connectionPool,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument(
                'table',
                InputArgument::REQUIRED,
                'Database table name (e.g., tx_myext_settings)',
            )
            ->addArgument(
                'field',
                InputArgument::REQUIRED,
                'Field name containing plaintext values to migrate',
            )
            ->addOption(
                'dry-run',
                null,
                InputOption::VALUE_NONE,
                'Show what would be migrated without making changes',
            )
            ->addOption(
                'batch-size',
                'b',
                InputOption::VALUE_REQUIRED,
                'Number of records to process per batch',
                100,
            )
            ->addOption(
                'where',
                'w',
                InputOption::VALUE_REQUIRED,
                'Additional WHERE clause to filter records (e.g., "pid=1")',
            )
            ->addOption(
                'force',
                'f',
                InputOption::VALUE_NONE,
                'Migrate even if field already contains vault identifiers',
            )
            ->addOption(
                'clear-source',
                null,
                InputOption::VALUE_NONE,
                'Deprecated, no effect: the field is always replaced with the vault identifier',
            )
            ->addOption(
                'uid-field',
                null,
                InputOption::VALUE_REQUIRED,
                'Name of the UID field',
                'uid',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $table    = $input->getArgument('table');
        $field    = $input->getArgument('field');
        $uidField = $input->getOption('uid-field');

        assert(is_string($table));
        assert(is_string($field));
        assert(is_string($uidField));

        if (trim($uidField) === '') {
            $io->error('--uid-field must be a non-empty column name.');

            return Command::FAILURE;
        }

        $dryRun      = (bool) $input->getOption('dry-run');
        $batchSize   = $input->getOption('batch-size');
        $whereClause = $input->getOption('where');
        $force       = (bool) $input->getOption('force');
        if ((bool) $input->getOption('clear-source')) {
            $io->note('--clear-source has no effect: the migration always replaces the field value with the vault identifier.');
        }

        assert(is_int($batchSize) && $batchSize >= 1);
        assert($whereClause === null || is_string($whereClause));

        $io->title('Vault Field Migration');
        $io->text([
            sprintf('Table: <info>%s</info>', $table),
            sprintf('Field: <info>%s</info>', $field),
            sprintf('Mode: <info>%s</info>', $dryRun ? 'Dry Run' : 'Live'),
        ]);

        // Validate table exists
        if (!$this->tableExists($table)) {
            $io->error(sprintf('Table "%s" does not exist', $table));

            return Command::FAILURE;
        }

        // Validate field exists
        $column = $this->findColumn($table, $field);
        if (!$column instanceof Column) {
            $io->error(sprintf('Field "%s" does not exist in table "%s"', $field, $table));

            return Command::FAILURE;
        }

        // The field receives the identifier. A column too narrow for it would
        // truncate it (non-strict SQL) or reject it (strict SQL), and either
        // way the stored secret would be unreferenced.
        $columnProblem = $this->columnProblem($column);
        if ($columnProblem !== null) {
            $io->error(sprintf('Field "%s" cannot hold a vault identifier: %s. Widen the column first.', $field, $columnProblem));

            return Command::FAILURE;
        }

        // Get records to migrate
        $records      = $this->getRecordsToMigrate($table, $field, $uidField, $whereClause, $force);
        $totalRecords = count($records);

        if ($totalRecords === 0) {
            $io->success('No records found to migrate');

            return Command::SUCCESS;
        }

        $io->text(sprintf('Found <info>%d</info> records to migrate', $totalRecords));

        if ($dryRun) {
            $io->section('Records that would be migrated:');
            $this->showDryRunResults($io, $records, $field, $uidField);

            return Command::SUCCESS;
        }

        // Confirm migration
        if (!$io->confirm('Proceed with migration?', false)) {
            $io->warning('Migration cancelled');

            return Command::SUCCESS;
        }

        // Process in batches
        $io->section('Migrating records...');
        $progressBar = $io->createProgressBar($totalRecords);
        $progressBar->start();

        ['migrated' => $migrated, 'failed' => $failed, 'errors' => $errors, 'skipped' => $skipped] = $this->migrateRecords(
            $records,
            $batchSize,
            $table,
            $field,
            $uidField,
            $progressBar,
        );

        $progressBar->finish();
        $io->newLine(2);

        // Summary
        $io->section('Migration Summary');
        $io->definitionList(
            ['Total records' => $totalRecords],
            ['Successfully migrated' => $migrated],
            ['Skipped (already a vault identifier)' => count($skipped)],
            ['Failed' => $failed],
        );

        foreach ($skipped as $skip) {
            $io->text(sprintf('<comment>Skipped</comment> UID %d: the field already holds the vault identifier %s', $skip['uid'], $skip['identifier']));
        }

        $this->reportErrors($io, $errors);

        if ($failed > 0) {
            $io->warning(sprintf('Migration completed with %d errors', $failed));

            return Command::FAILURE;
        }

        $io->success('Migration completed successfully');

        // Show next steps
        $io->section('Next Steps');
        $io->listing([
            'Update TCA configuration to use renderType => "vaultSecret" for this field',
            'Test that the field displays correctly in the TYPO3 backend',
            'Update any code that reads this field to use VaultFieldResolver::resolveFields()',
            'The field now holds the vault identifier instead of the plaintext value',
        ]);

        return Command::SUCCESS;
    }

    /**
     * Processes the records in batches, storing each value in the vault.
     *
     * @param array<int, array<string, mixed>> $records
     * @param int<1, max>                      $batchSize
     *
     * @return array{migrated: int, failed: int, errors: list<string>, skipped: list<array{uid: int, identifier: string}>}
     */
    private function migrateRecords(
        array $records,
        int $batchSize,
        string $table,
        string $field,
        string $uidField,
        ProgressBar $progressBar,
    ): array {
        $migrated = 0;
        $failed   = 0;
        $errors   = [];
        $skipped  = [];

        foreach (array_chunk($records, $batchSize) as $batch) {
            foreach ($batch as $record) {
                $uid   = $record[$uidField];
                $value = $record[$field];

                assert(is_int($uid) || is_string($uid));
                assert(is_string($value) || is_int($value) || $value === null);

                $uidInt   = (int) $uid;
                $valueStr = (string) $value;

                // The field already holds the identifier of an existing secret
                // (an earlier run, or --force): wrapping it in a new secret
                // would leave that secret unreferenced, and orphan cleanup
                // would delete it.
                if ($this->isExistingVaultIdentifier($valueStr)) {
                    $skipped[] = ['uid' => $uidInt, 'identifier' => $valueStr];
                    $progressBar->advance();

                    continue;
                }

                $error = $this->migrateRecord($table, $field, $uidField, $uidInt, $valueStr);
                if ($error === null) {
                    ++$migrated;
                } else {
                    ++$failed;
                    $errors[] = sprintf('UID %d: %s', $uidInt, $error);
                }

                // Clear value from memory
                if (is_string($value)) {
                    sodium_memzero($value);
                }

                sodium_memzero($valueStr);

                $progressBar->advance();
            }
        }

        return ['migrated' => $migrated, 'failed' => $failed, 'errors' => $errors, 'skipped' => $skipped];
    }

    /**
     * Store one value and replace it with the identifier. Returns null on
     * success, otherwise the reason the record failed.
     */
    private function migrateRecord(string $table, string $field, string $uidField, int $uid, string $value): ?string
    {
        $identifier = IdentifierValidator::generateUuid();

        try {
            $this->vaultService->store($identifier, $value, [
                'metadata' => $this->buildMetadata($table, $field, $uidField, $uid),
            ]);
        } catch (VaultException $e) {
            return $e->getMessage();
        }

        // Replace the plaintext with the identifier: the vault field resolves
        // the secret through it. Read it back, because non-strict SQL
        // truncates silently and a WHERE on --uid-field may match no row.
        try {
            $this->writeIdentifier($table, $field, $uidField, $uid, $identifier);
            $written = $this->readField($table, $field, $uidField, $uid);
        } catch (DbalException $e) {
            return $this->discardStoredSecret($identifier, 'the field could not be updated: ' . $e->getMessage());
        }

        if ($written !== $identifier) {
            return $this->discardStoredSecret($identifier, 'the field does not hold the identifier after the update');
        }

        return null;
    }

    /**
     * The field kept its plaintext, so the secret just stored is referenced
     * by nothing. Delete it now: a secret stored without a record link
     * (--uid-field other than uid) is invisible to orphan cleanup and would
     * otherwise stay forever.
     */
    private function discardStoredSecret(string $identifier, string $reason): string
    {
        try {
            $this->vaultService->delete($identifier, 'vault:migrate-field: ' . $reason);
        } catch (VaultException $e) {
            return sprintf('%s; the stored secret %s could not be deleted: %s', $reason, $identifier, $e->getMessage());
        }

        return $reason . '; the stored secret was deleted again';
    }

    private function isExistingVaultIdentifier(string $value): bool
    {
        return IdentifierValidator::isValid($value) && $this->vaultService->exists($value);
    }

    /**
     * @param list<string> $errors
     */
    private function reportErrors(SymfonyStyle $io, array $errors): void
    {
        if ($errors === []) {
            return;
        }

        $io->section('Errors');
        foreach (array_slice($errors, 0, 10) as $error) {
            $io->text('<error>✗</error> ' . $error);
        }

        if (count($errors) > 10) {
            $io->text(sprintf('... and %d more errors', count($errors) - 10));
        }
    }

    private function tableExists(string $table): bool
    {
        $connection = $this->connectionPool->getConnectionByName(ConnectionPool::DEFAULT_CONNECTION_NAME);

        return $connection->createSchemaManager()->tablesExist([$table]);
    }

    private function fieldExists(string $table, string $field): bool
    {
        return $this->findColumn($table, $field) instanceof Column;
    }

    /**
     * DBAL keys the list by the lower-cased, platform-QUOTED name: a reserved
     * word arrives as `key` or "key". Strip the quotes to find the column.
     */
    private function findColumn(string $table, string $field): ?Column
    {
        $connection = $this->connectionPool->getConnectionByName(ConnectionPool::DEFAULT_CONNECTION_NAME);

        foreach ($connection->createSchemaManager()->listTableColumns($table) as $key => $column) {
            if (trim((string) $key, '`"[]') === strtolower($field)) {
                return $column;
            }
        }

        return null;
    }

    /**
     * Why the column cannot hold an identifier, or null when it can.
     */
    private function columnProblem(Column $column): ?string
    {
        $type = $column->getType();
        if (!$type instanceof StringType && !$type instanceof TextType) {
            return 'it is not a text column';
        }

        $length = $column->getLength();
        if ($length !== null && $length < self::IDENTIFIER_LENGTH) {
            return sprintf('it holds at most %d characters, an identifier needs %d', $length, self::IDENTIFIER_LENGTH);
        }

        return null;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function getRecordsToMigrate(
        string $table,
        string $field,
        string $uidField,
        ?string $whereClause,
        bool $force,
    ): array {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        // Hidden and time-restricted records hold plaintext secrets too; only
        // deleted records stay out (below).
        $queryBuilder->getRestrictions()->removeAll();
        $queryBuilder
            ->select($uidField, $field)
            ->from($table)
            ->where(
                $queryBuilder->expr()->neq($field, $queryBuilder->createNamedParameter('')),
                $queryBuilder->expr()->isNotNull($field),
            );

        // Skip records that already have vault identifiers (UUIDs) (unless forced)
        if (!$force) {
            // UUID v7 pattern: 8-4-4-4-12 hex chars with version 7 and correct variant
            $queryBuilder->andWhere(
                $queryBuilder->expr()->notLike(
                    $field,
                    $queryBuilder->createNamedParameter('________-____-7___-____-____________'),
                ),
            );
        }

        // Apply additional where clause
        if ($whereClause !== null && $whereClause !== '') {
            $queryBuilder->andWhere($whereClause);
        }

        // Check for deleted field
        if ($this->fieldExists($table, 'deleted')) {
            $queryBuilder->andWhere(
                $queryBuilder->expr()->eq('deleted', 0),
            );
        }

        return $queryBuilder->executeQuery()->fetchAllAssociative();
    }

    /**
     * @param array<int, array<string, mixed>> $records
     */
    private function showDryRunResults(
        SymfonyStyle $io,
        array $records,
        string $field,
        string $uidField,
    ): void {
        $rows = [];
        foreach (array_slice($records, 0, 20) as $record) {
            $uid   = $record[$uidField];
            $value = $record[$field];

            $rows[] = [
                $uid,
                $this->truncateValue($value, 30),
                '(new UUID will be generated)',
            ];
        }

        $io->table(
            ['UID', 'Current Value', 'Vault Identifier'],
            $rows,
        );

        if (count($records) > 20) {
            $io->text(sprintf('... and %d more records', count($records) - 20));
        }
    }

    private function truncateValue(mixed $value, int $maxLength): string
    {
        if (!is_string($value)) {
            return '(non-string)';
        }

        if (strlen($value) <= $maxLength) {
            return str_repeat('*', strlen($value));
        }

        return str_repeat('*', $maxLength - 3) . '...';
    }

    /**
     * The record link names the `uid` column, which orphan cleanup looks the
     * record up by. A value from another --uid-field column would point the
     * cleanup at the wrong record, so such a secret gets no link.
     *
     * @return array<string, mixed>
     */
    private function buildMetadata(string $table, string $field, string $uidField, int $uid): array
    {
        if ($uidField !== 'uid') {
            return ['migrated_at' => time()];
        }

        return SecretRecordLink::forField(SecretRecordLink::SOURCE_MIGRATION, $table, $field, $uid, ['migrated_at' => time()]);
    }

    private function readField(string $table, string $field, string $uidField, int $uid): mixed
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        return $queryBuilder
            ->select($field)
            ->from($table)
            ->where(
                $queryBuilder->expr()->eq($uidField, $queryBuilder->createNamedParameter($uid)),
            )
            ->executeQuery()
            ->fetchOne();
    }

    private function writeIdentifier(string $table, string $field, string $uidField, int $uid, string $identifier): void
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder
            ->update($table)
            ->set($field, $identifier)
            ->where(
                $queryBuilder->expr()->eq($uidField, $queryBuilder->createNamedParameter($uid)),
            )
            ->executeStatement();
    }
}
