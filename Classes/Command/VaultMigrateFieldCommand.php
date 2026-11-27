<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Doctrine\DBAL\Schema\Column;
use Netresearch\NrVault\Service\FieldValueMigratorInterface;
use Netresearch\NrVault\Utility\IdentifierValidator;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
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
        private readonly ConnectionPool $connectionPool,
        private readonly FieldValueMigratorInterface $migrator,
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
        $column = $this->migrator->findColumn($table, $field);
        if (!$column instanceof Column) {
            $io->error(sprintf('Field "%s" does not exist in table "%s"', $field, $table));

            return Command::FAILURE;
        }

        // The field receives the identifier. A column too narrow for it would
        // truncate it (non-strict SQL) or reject it (strict SQL), and either
        // way the stored secret would be unreferenced.
        $columnProblem = $this->migrator->columnProblem($column, self::IDENTIFIER_LENGTH);
        if ($columnProblem !== null) {
            $io->error(sprintf('Field "%s" cannot hold a vault identifier: %s. Widen the column first.', $field, $columnProblem));

            return Command::FAILURE;
        }

        $uidFieldProblem = $this->uidFieldProblem($table, $uidField);
        if ($uidFieldProblem !== null) {
            $io->error($uidFieldProblem);

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

                [$outcome, $detail] = $this->migrateRecord($table, $field, $uidField, (string) $uid, $valueStr);
                if ($outcome === 'migrated') {
                    ++$migrated;
                } elseif ($outcome === 'skipped') {
                    $skipped[] = ['uid' => $uidInt, 'identifier' => $detail];
                } else {
                    ++$failed;
                    $errors[] = sprintf('UID %d: %s', $uidInt, $detail);
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
     * Migrate one record: 'migrated', 'skipped' with the existing identifier,
     * or 'failed' with the reason.
     *
     * @return array{'migrated'|'skipped'|'failed', string}
     */
    private function migrateRecord(string $table, string $field, string $uidField, string $uid, string $value): array
    {
        // The field already holds the identifier of an existing secret (an
        // earlier run, or --force): wrapping it in a new secret would leave
        // that secret unreferenced, and orphan cleanup would delete it. When
        // the vault cannot answer, the record fails instead of being migrated
        // blind.
        try {
            if ($this->isExistingVaultIdentifier($value)) {
                return ['skipped', $value];
            }
        } catch (Throwable $e) {
            return ['failed', 'could not check whether the value is a vault identifier: ' . $e->getMessage()];
        }

        $error = $this->migrator->migrate($table, $field, $uidField, $uid, $value, IdentifierValidator::generateUuid());

        return $error === null ? ['migrated', ''] : ['failed', $error];
    }

    /**
     * Why --uid-field cannot key the UPDATE, or null when it can. A value
     * shared by several rows would write one identifier into all of them and
     * overwrite their plaintexts.
     */
    private function uidFieldProblem(string $table, string $uidField): ?string
    {
        if (!$this->migrator->findColumn($table, $uidField) instanceof Column) {
            return sprintf('Field "%s" (--uid-field) does not exist in table "%s"', $uidField, $table);
        }

        $duplicates = $this->migrator->countRowsWithDuplicateKey($table, $uidField);
        if ($duplicates === null) {
            return sprintf('Could not check that --uid-field "%s" is unique.', $uidField);
        }

        if ($duplicates > 0) {
            return sprintf('--uid-field "%s" is not unique: %d row(s) share their value with another row. Use a unique column.', $uidField, $duplicates);
        }

        return null;
    }

    private function isExistingVaultIdentifier(string $value): bool
    {
        // A disabled secret owns its identifier too.
        return IdentifierValidator::isValid($value) && $this->migrator->identifierInUse($value);
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
        // A table mapped to another connection lives in that database.
        return $this->connectionPool->getConnectionForTable($table)->createSchemaManager()->tablesExist([$table]);
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
        $queryBuilder
            ->select($uidField, $field)
            ->from($table)
            ->where(
                $queryBuilder->expr()->neq($field, $queryBuilder->createNamedParameter('')),
                $queryBuilder->expr()->isNotNull($field),
            );
        // Hidden and time-restricted records hold plaintext secrets too;
        // deleted records stay out.
        $this->migrator->restrictToMigratableRows($queryBuilder, $table);

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
}
