<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

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
                'Clear the source field after migration (set to empty string)',
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

        $table = $input->getArgument('table');
        $field = $input->getArgument('field');
        $uidField = $input->getOption('uid-field');

        \assert(\is_string($table));
        \assert(\is_string($field));
        \assert(\is_string($uidField));

        if (trim($uidField) === '') {
            $io->error('--uid-field must be a non-empty column name.');

            return Command::FAILURE;
        }

        $dryRun = (bool) $input->getOption('dry-run');
        $batchSize = $input->getOption('batch-size');
        $whereClause = $input->getOption('where');
        $force = (bool) $input->getOption('force');
        $clearSource = (bool) $input->getOption('clear-source');

        \assert(\is_int($batchSize) && $batchSize >= 1);
        \assert($whereClause === null || \is_string($whereClause));

        $io->title('Vault Field Migration');
        $io->text([
            \sprintf('Table: <info>%s</info>', $table),
            \sprintf('Field: <info>%s</info>', $field),
            \sprintf('Mode: <info>%s</info>', $dryRun ? 'Dry Run' : 'Live'),
        ]);

        // Validate table exists
        if (!$this->tableExists($table)) {
            $io->error(\sprintf('Table "%s" does not exist', $table));

            return Command::FAILURE;
        }

        // Validate field exists
        if (!$this->fieldExists($table, $field)) {
            $io->error(\sprintf('Field "%s" does not exist in table "%s"', $field, $table));

            return Command::FAILURE;
        }

        // Get records to migrate
        $records = $this->getRecordsToMigrate($table, $field, $uidField, $whereClause, $force);
        $totalRecords = \count($records);

        if ($totalRecords === 0) {
            $io->success('No records found to migrate');

            return Command::SUCCESS;
        }

        $io->text(\sprintf('Found <info>%d</info> records to migrate', $totalRecords));

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

        ['migrated' => $migrated, 'failed' => $failed, 'errors' => $errors] = $this->migrateRecords(
            $records,
            $batchSize,
            $table,
            $field,
            $uidField,
            $clearSource,
            $progressBar,
        );

        $progressBar->finish();
        $io->newLine(2);

        // Summary
        $io->section('Migration Summary');
        $io->definitionList(
            ['Total records' => $totalRecords],
            ['Successfully migrated' => $migrated],
            ['Failed' => $failed],
        );

        $this->reportErrors($io, $errors);

        if ($failed > 0) {
            $io->warning(\sprintf('Migration completed with %d errors', $failed));

            return Command::FAILURE;
        }

        $io->success('Migration completed successfully');

        // Show next steps
        $io->section('Next Steps');
        $io->listing([
            'Update TCA configuration to use renderType => "vaultSecret" for this field',
            'Test that the field displays correctly in the TYPO3 backend',
            'Update any code that reads this field to use VaultFieldResolver::resolveFields()',
            $clearSource
                ? 'Source field has been cleared'
                : 'Consider clearing or removing the source field after verifying migration',
        ]);

        return Command::SUCCESS;
    }

    /**
     * Processes the records in batches, storing each value in the vault.
     *
     * @param array<int, array<string, mixed>> $records
     * @param int<1, max> $batchSize
     *
     * @return array{migrated: int, failed: int, errors: list<string>}
     */
    private function migrateRecords(
        array $records,
        int $batchSize,
        string $table,
        string $field,
        string $uidField,
        bool $clearSource,
        ProgressBar $progressBar,
    ): array {
        $migrated = 0;
        $failed = 0;
        $errors = [];

        foreach (array_chunk($records, $batchSize) as $batch) {
            foreach ($batch as $record) {
                $uid = $record[$uidField];
                $value = $record[$field];

                \assert(\is_int($uid) || \is_string($uid));
                \assert(\is_string($value) || \is_int($value) || $value === null);

                $uidInt = (int) $uid;
                $valueStr = (string) $value;

                try {
                    $identifier = IdentifierValidator::generateUuid();

                    // Store in vault
                    $this->vaultService->store($identifier, $valueStr, [
                        'table' => $table,
                        'field' => $field,
                        'uid' => $uidInt,
                        'source' => 'migration',
                        'migrated_at' => time(),
                    ]);

                    // Optionally clear source field
                    if ($clearSource) {
                        $this->clearSourceField($table, $field, $uidField, $uidInt);
                    }

                    $migrated++;

                    // Clear value from memory
                    if (\is_string($value)) {
                        sodium_memzero($value);
                    }
                } catch (VaultException $e) {
                    $failed++;
                    $errors[] = \sprintf('UID %d: %s', $uid, $e->getMessage());
                }

                $progressBar->advance();
            }
        }

        return ['migrated' => $migrated, 'failed' => $failed, 'errors' => $errors];
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
        foreach (\array_slice($errors, 0, 10) as $error) {
            $io->text('<error>✗</error> ' . $error);
        }
        if (\count($errors) > 10) {
            $io->text(\sprintf('... and %d more errors', \count($errors) - 10));
        }
    }

    private function tableExists(string $table): bool
    {
        $connection = $this->connectionPool->getConnectionByName(ConnectionPool::DEFAULT_CONNECTION_NAME);

        return $connection->createSchemaManager()->tablesExist([$table]);
    }

    private function fieldExists(string $table, string $field): bool
    {
        $connection = $this->connectionPool->getConnectionByName(ConnectionPool::DEFAULT_CONNECTION_NAME);
        $columns = $connection->createSchemaManager()->listTableColumns($table);

        return isset($columns[$field]) || isset($columns[strtolower($field)]);
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
        foreach (\array_slice($records, 0, 20) as $record) {
            $uid = $record[$uidField];
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

        if (\count($records) > 20) {
            $io->text(\sprintf('... and %d more records', \count($records) - 20));
        }
    }

    private function truncateValue(mixed $value, int $maxLength): string
    {
        if (!\is_string($value)) {
            return '(non-string)';
        }

        if (\strlen($value) <= $maxLength) {
            return str_repeat('*', \strlen($value));
        }

        return str_repeat('*', $maxLength - 3) . '...';
    }

    private function clearSourceField(string $table, string $field, string $uidField, int $uid): void
    {
        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder
            ->update($table)
            ->set($field, '')
            ->where(
                $queryBuilder->expr()->eq($uidField, $queryBuilder->createNamedParameter($uid)),
            )
            ->executeStatement();
    }
}
