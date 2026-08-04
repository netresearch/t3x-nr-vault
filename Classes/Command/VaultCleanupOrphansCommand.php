<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * CLI command to clean up orphaned vault secrets from TCA fields.
 *
 * When records with vault-backed fields are deleted, the corresponding
 * vault secrets may become orphaned. This command identifies and removes
 * such orphaned secrets.
 *
 * Usage:
 *   vendor/bin/typo3 vault:cleanup-orphans --dry-run
 *   vendor/bin/typo3 vault:cleanup-orphans --retention-days=30
 *   vendor/bin/typo3 vault:cleanup-orphans
 */
#[AsCommand(
    name: 'vault:cleanup-orphans',
    description: 'Clean up orphaned vault secrets from deleted TCA records',
)]
final class VaultCleanupOrphansCommand extends Command
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
            ->addOption(
                'dry-run',
                null,
                InputOption::VALUE_NONE,
                'Show what would be deleted without making changes',
            )
            ->addOption(
                'retention-days',
                'r',
                InputOption::VALUE_REQUIRED,
                'Only delete orphans older than this many days',
                0,
            )
            ->addOption(
                'table',
                't',
                InputOption::VALUE_REQUIRED,
                'Only check secrets for this specific table',
            )
            ->addOption(
                'batch-size',
                'b',
                InputOption::VALUE_REQUIRED,
                'Number of secrets to check per batch',
                100,
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $options = $this->parseOptions($input);

        $io->title('Vault Orphan Cleanup');
        $io->text([
            \sprintf('Mode: <info>%s</info>', $options['dryRun'] ? 'Dry Run' : 'Live'),
            \sprintf('Retention: <info>%d days</info>', $options['retentionDays']),
            $options['tableFilter'] !== null ? \sprintf('Table filter: <info>%s</info>', $options['tableFilter']) : '',
        ]);

        $secrets = $this->getTcaSecrets($options['tableFilter']);
        if ($secrets === []) {
            $io->success('No TCA-sourced secrets found');

            return Command::SUCCESS;
        }

        $io->text(\sprintf('Found <info>%d</info> TCA-sourced secrets to check', \count($secrets)));

        $orphans = $this->findOrphans($io, $secrets, $options['retentionDays'], $options['batchSize']);
        $orphanCount = \count($orphans);
        if ($orphanCount === 0) {
            $io->success('No orphaned secrets found');

            return Command::SUCCESS;
        }

        $io->text(\sprintf('Found <comment>%d</comment> orphaned secrets', $orphanCount));

        if ($options['dryRun']) {
            $io->section('Orphaned secrets that would be deleted:');
            $this->showOrphanTable($io, $orphans);

            return Command::SUCCESS;
        }

        if (!$io->confirm(\sprintf('Delete %d orphaned secrets?', $orphanCount), false)) {
            $io->warning('Cleanup cancelled');

            return Command::SUCCESS;
        }

        return $this->deleteOrphans($io, $orphans);
    }

    /**
     * Parse CLI options into a typed shape so the main flow stays readable.
     *
     * @return array{dryRun: bool, retentionDays: int, tableFilter: ?string, batchSize: int}
     */
    private function parseOptions(InputInterface $input): array
    {
        $retentionDaysOption = $input->getOption('retention-days');
        $tableFilterOption = $input->getOption('table');
        $batchSizeOption = $input->getOption('batch-size');

        return [
            'dryRun' => (bool) $input->getOption('dry-run'),
            'retentionDays' => is_numeric($retentionDaysOption) ? (int) $retentionDaysOption : 0,
            'tableFilter' => \is_string($tableFilterOption) ? $tableFilterOption : null,
            'batchSize' => is_numeric($batchSizeOption) && (int) $batchSizeOption > 0 ? (int) $batchSizeOption : 100,
        ];
    }

    /**
     * Iterate TCA-sourced secrets and classify each as orphaned when the
     * backing record no longer exists AND the secret is older than the
     * configured retention cutoff.
     *
     * @param array<int, array{identifier: string, metadata: array<string, mixed>, created_at: int}> $secrets
     *
     * @return list<array{identifier: string, table: string, field: string, uid: int, created_at: int}>
     */
    private function findOrphans(SymfonyStyle $io, array $secrets, int $retentionDays, int $batchSize): array
    {
        $io->section('Checking for orphaned secrets...');
        $progressBar = $io->createProgressBar(\count($secrets));
        $progressBar->start();

        $orphans = [];
        $retentionCutoff = $retentionDays > 0 ? time() - ($retentionDays * 86400) : PHP_INT_MAX;
        $effectiveBatchSize = max(1, $batchSize);

        foreach (array_chunk($secrets, $effectiveBatchSize) as $batch) {
            foreach ($batch as $secret) {
                $orphan = $this->classifyOrphan($secret, $retentionCutoff);
                if ($orphan !== null) {
                    $orphans[] = $orphan;
                }

                $progressBar->advance();
            }
        }

        $progressBar->finish();
        $io->newLine(2);

        return $orphans;
    }

    /**
     * Classify a single secret. Returns the orphan payload if the backing
     * record is gone and retention has elapsed, otherwise null.
     *
     * @param array{identifier: string, metadata: array<string, mixed>, created_at: int} $secret
     *
     * @return array{identifier: string, table: string, field: string, uid: int, created_at: int}|null
     */
    private function classifyOrphan(array $secret, int $retentionCutoff): ?array
    {
        $identifier = $secret['identifier'];
        $metadata = $secret['metadata'];
        $createdAtRaw = $secret['created_at'] ?? 0;
        $createdAt = is_numeric($createdAtRaw) ? (int) $createdAtRaw : 0;

        $tableValue = $metadata['table'] ?? '';
        $table = \is_string($tableValue) ? $tableValue : '';
        $fieldValue = $metadata['field'] ?? $metadata['flexField'] ?? '';
        $field = \is_string($fieldValue) ? $fieldValue : '';
        $uidValue = $metadata['uid'] ?? 0;
        $uid = is_numeric($uidValue) ? (int) $uidValue : 0;

        if ($table === '' || $uid === 0) {
            return null;
        }

        if ($this->recordExists($table, $uid) || $createdAt >= $retentionCutoff) {
            return null;
        }

        return [
            'identifier' => $identifier,
            'table' => $table,
            'field' => $field,
            'uid' => $uid,
            'created_at' => $createdAt,
        ];
    }

    /**
     * Delete the confirmed orphan list, printing a summary table. Returns
     * FAILURE if any deletion threw; the rest still proceed (best-effort
     * cleanup — vault state is consistent either way).
     *
     * @param list<array{identifier: string, table: string, field: string, uid: int, created_at: int}> $orphans
     */
    private function deleteOrphans(SymfonyStyle $io, array $orphans): int
    {
        $io->section('Deleting orphaned secrets...');
        $deleted = 0;
        $failed = 0;
        $errors = [];

        foreach ($orphans as $orphan) {
            try {
                $this->vaultService->delete($orphan['identifier'], 'Orphan cleanup');
                ++$deleted;
            } catch (VaultException $e) {
                ++$failed;
                $errors[] = \sprintf('%s: %s', $orphan['identifier'], $e->getMessage());
            }
        }

        $io->section('Cleanup Summary');
        $io->definitionList(
            ['Orphans found' => \count($orphans)],
            ['Successfully deleted' => $deleted],
            ['Failed' => $failed],
        );

        if ($errors !== []) {
            $io->section('Errors');
            foreach (\array_slice($errors, 0, 10) as $error) {
                $io->text('<error>✗</error> ' . $error);
            }
        }

        if ($failed > 0) {
            $io->warning(\sprintf('Cleanup completed with %d errors', $failed));

            return Command::FAILURE;
        }

        $io->success(\sprintf('Successfully deleted %d orphaned secrets', $deleted));

        return Command::SUCCESS;
    }

    /**
     * Get all secrets that were created from TCA fields.
     *
     * @return array<int, array{identifier: string, metadata: array<string, mixed>, created_at: int}>
     */
    private function getTcaSecrets(?string $tableFilter): array
    {
        $allSecrets = $this->vaultService->list();
        $tcaSecrets = [];

        foreach ($allSecrets as $secret) {
            $metadata = $secret->metadata;
            $source = $metadata['source'] ?? '';

            // Only include TCA-sourced secrets (regular fields, FlexForm, or copied records)
            $tcaSources = ['tca_field', 'flexform_field', 'record_copy', 'migration'];
            if (!\in_array($source, $tcaSources, true)) {
                continue;
            }

            // Apply table filter if specified
            if ($tableFilter !== null) {
                $table = $metadata['table'] ?? '';
                if ($table !== $tableFilter) {
                    continue;
                }
            }

            $tcaSecrets[] = [
                'identifier' => $secret->identifier,
                'metadata' => $metadata,
                'created_at' => $secret->createdAt,
            ];
        }

        return $tcaSecrets;
    }

    /**
     * Check if a record exists in the database.
     */
    private function recordExists(string $table, int $uid): bool
    {
        // Check if table exists first
        $connection = $this->connectionPool->getConnectionByName(ConnectionPool::DEFAULT_CONNECTION_NAME);
        if (!$connection->createSchemaManager()->tablesExist([$table])) {
            return false;
        }

        $queryBuilder = $this->connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $count = $queryBuilder
            ->count('*')
            ->from($table)
            ->where(
                $queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)),
            )
            ->executeQuery()
            ->fetchOne();

        return $count > 0;
    }

    /**
     * @param array<int, array{identifier: string, table: string, field: string, uid: int, created_at: int}> $orphans
     */
    private function showOrphanTable(SymfonyStyle $io, array $orphans): void
    {
        $rows = [];
        foreach (\array_slice($orphans, 0, 20) as $orphan) {
            $rows[] = [
                $orphan['identifier'],
                $orphan['table'],
                $orphan['field'],
                $orphan['uid'],
                $orphan['created_at'] > 0 ? date('Y-m-d H:i', $orphan['created_at']) : 'Unknown',
            ];
        }

        $io->table(
            ['Identifier', 'Table', 'Field', 'UID', 'Created'],
            $rows,
        );

        if (\count($orphans) > 20) {
            $io->text(\sprintf('... and %d more orphans', \count($orphans) - 20));
        }
    }
}
