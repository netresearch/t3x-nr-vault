<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use DateTimeImmutable;
use Exception;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Utility\CsvFormulaSanitizer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * CLI command to query and export audit logs.
 */
#[AsCommand(
    name: 'vault:audit',
    description: 'Query and export vault audit logs',
)]
final class VaultAuditCommand extends Command
{
    public function __construct(
        private readonly AuditLogServiceInterface $auditLogService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'identifier',
                'i',
                InputOption::VALUE_REQUIRED,
                'Filter by secret identifier',
            )
            ->addOption(
                'action',
                'a',
                InputOption::VALUE_REQUIRED,
                'Filter by action (create, read, update, delete, rotate, access_denied)',
            )
            ->addOption(
                'actor',
                null,
                InputOption::VALUE_REQUIRED,
                'Filter by actor UID',
            )
            ->addOption(
                'since',
                null,
                InputOption::VALUE_REQUIRED,
                'Filter entries since date (Y-m-d or Y-m-d H:i:s)',
            )
            ->addOption(
                'until',
                null,
                InputOption::VALUE_REQUIRED,
                'Filter entries until date (Y-m-d or Y-m-d H:i:s)',
            )
            ->addOption(
                'success',
                null,
                InputOption::VALUE_REQUIRED,
                'Filter by success status (true/false)',
            )
            ->addOption(
                'format',
                'f',
                InputOption::VALUE_REQUIRED,
                'Output format: table, json, csv',
                'table',
            )
            ->addOption(
                'limit',
                'l',
                InputOption::VALUE_REQUIRED,
                'Maximum number of results',
                '50',
            )
            ->addOption(
                'verify',
                null,
                InputOption::VALUE_NONE,
                'Verify hash chain integrity',
            )
            ->addOption(
                'export',
                'e',
                InputOption::VALUE_REQUIRED,
                'Export to file',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        // Hash chain verification
        if ($input->getOption('verify')) {
            return $this->verifyHashChain($io);
        }

        // Build filters
        $filters = $this->buildFilters($input);
        $format = $input->getOption('format');
        $limit = $input->getOption('limit');

        \assert(\is_string($format));
        \assert(\is_string($limit) || \is_int($limit));
        $limit = (int) $limit;

        try {
            $entries = $this->auditLogService->query($filters, $limit, 0);

            if ($entries === []) {
                $io->info('No audit entries found');

                return Command::SUCCESS;
            }

            // Export to file
            $exportFile = $input->getOption('export');
            if (\is_string($exportFile) && $exportFile !== '') {
                return $this->exportToFile($io, $entries, $exportFile, $format);
            }

            // Output to console
            match ($format) {
                'json' => $output->writeln(json_encode($entries, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR)),
                'csv' => $this->outputCsv($output, $entries),
                default => $this->outputTable($io, $entries),
            };

            return Command::SUCCESS;
        } catch (VaultException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }
    }

    private function buildFilters(InputInterface $input): ?AuditLogFilter
    {
        $secretIdentifier = $input->getOption('identifier');
        $action = $input->getOption('action');
        $actor = $input->getOption('actor');
        $successOption = $input->getOption('success');
        $sinceOption = $input->getOption('since');
        $untilOption = $input->getOption('until');

        $since = null;
        if (\is_string($sinceOption) && $sinceOption !== '') {
            try {
                $since = new DateTimeImmutable($sinceOption);
            } catch (Exception) {
                // Invalid date, skip
            }
        }

        $until = null;
        if (\is_string($untilOption) && $untilOption !== '') {
            try {
                $until = new DateTimeImmutable($untilOption);
            } catch (Exception) {
                // Invalid date, skip
            }
        }

        $success = \is_string($successOption)
            ? filter_var($successOption, FILTER_VALIDATE_BOOLEAN)
            : null;

        $actorUid = null;
        if (\is_string($actor) || \is_int($actor)) {
            $actorUid = (int) $actor;
        }

        $filter = new AuditLogFilter(
            secretIdentifier: \is_string($secretIdentifier) ? $secretIdentifier : null,
            action: \is_string($action) ? $action : null,
            actorUid: $actorUid,
            success: $success,
            since: $since,
            until: $until,
        );

        return $filter->isEmpty() ? null : $filter;
    }

    private function verifyHashChain(SymfonyStyle $io): int
    {
        $io->section('Verifying hash chain integrity');

        $result = $this->auditLogService->verifyHashChain();

        if ($result->getWarningCount() > 0) {
            $io->warning(\sprintf('%d warning(s) detected:', $result->getWarningCount()));
            $io->table(
                ['Entry UID', 'Warning'],
                array_map(
                    fn ($uid, $warning): array => [$uid, $warning],
                    array_keys($result->warnings),
                    array_values($result->warnings),
                ),
            );
        }

        if ($result->isValid()) {
            $io->success('Hash chain is valid - no tampering detected');

            return Command::SUCCESS;
        }

        $io->error('Hash chain verification FAILED - possible tampering detected');

        if ($result->getErrorCount() > 0) {
            $io->table(
                ['Entry UID', 'Error'],
                array_map(
                    fn ($uid, $error): array => [$uid, $error],
                    array_keys($result->errors),
                    array_values($result->errors),
                ),
            );
        }

        return Command::FAILURE;
    }

    /**
     * @param array<int, AuditLogEntry> $entries
     */
    private function outputTable(SymfonyStyle $io, array $entries): void
    {
        $rows = [];
        foreach ($entries as $entry) {
            $rows[] = [
                date('Y-m-d H:i:s', $entry->crdate),
                $entry->secretIdentifier,
                $entry->action,
                $entry->success ? '✓' : '✗',
                $entry->actorUsername,
                $entry->ipAddress,
                substr((string) $entry->entryHash, 0, 8) . '...',
            ];
        }

        $io->table(
            ['Timestamp', 'Secret', 'Action', 'OK', 'Actor', 'IP', 'Hash'],
            $rows,
        );

        $io->writeln(\sprintf('<info>Total: %d entries</info>', \count($entries)));
    }

    /**
     * @param array<int, AuditLogEntry> $entries
     */
    private function outputCsv(OutputInterface $output, array $entries): void
    {
        // Header
        $output->writeln('timestamp,secret_identifier,action,success,actor_username,actor_type,ip_address,entry_hash');

        // Rows
        foreach ($entries as $entry) {
            $output->writeln(\sprintf(
                '%s,%s,%s,%d,%s,%s,%s,%s',
                date('Y-m-d H:i:s', $entry->crdate),
                CsvFormulaSanitizer::escapeField($entry->secretIdentifier),
                CsvFormulaSanitizer::escapeField($entry->action),
                $entry->success ? 1 : 0,
                CsvFormulaSanitizer::escapeField($entry->actorUsername),
                CsvFormulaSanitizer::escapeField($entry->actorType),
                CsvFormulaSanitizer::escapeField($entry->ipAddress),
                CsvFormulaSanitizer::escapeField($entry->entryHash),
            ));
        }
    }

    /**
     * @param array<int, AuditLogEntry> $entries
     */
    private function exportToFile(SymfonyStyle $io, array $entries, string $file, string $format): int
    {
        $data = array_map(static fn (AuditLogEntry $e): array => $e->jsonSerialize(), $entries);

        $content = match ($format) {
            'csv' => $this->formatCsv($data),
            default => json_encode($data, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR),
        };

        $result = file_put_contents($file, $content);
        if ($result === false) {
            $io->error(\sprintf('Failed to write to file: %s', $file));

            return Command::FAILURE;
        }

        $io->success(\sprintf('Exported %d entries to: %s', \count($entries), $file));

        return Command::SUCCESS;
    }

    /**
     * @param array<int, array<string, scalar|array<string, mixed>|null>> $data
     */
    private function formatCsv(array $data): string
    {
        if ($data === []) {
            return '';
        }

        $output = fopen('php://temp', 'r+');
        \assert(\is_resource($output));
        fputcsv($output, array_keys($data[0]), escape: '\\');

        foreach ($data as $row) {
            // Convert context array to JSON string for CSV
            if (isset($row['context']) && \is_array($row['context'])) {
                $row['context'] = json_encode($row['context']);
            }
            // Filter to only scalar/null values for fputcsv
            /** @var array<string, bool|float|int|string|null> $csvRow */
            $csvRow = array_map(
                static fn (mixed $v): bool|float|int|string|null => \is_scalar($v) || $v === null ? $v : json_encode($v),
                $row,
            );
            fputcsv($output, CsvFormulaSanitizer::neutralizeRow($csvRow), escape: '\\');
        }

        rewind($output);
        $csv = stream_get_contents($output);
        fclose($output);

        return $csv;
    }
}
