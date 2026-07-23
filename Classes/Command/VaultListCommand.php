<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Domain\Dto\SecretMetadata;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Utility\CsvFormulaSanitizer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * CLI command to list secrets in the vault.
 */
#[AsCommand(
    name: 'vault:list',
    description: 'List secrets in the vault',
)]
final class VaultListCommand extends Command
{
    private const DATE_FORMAT_SHORT = 'Y-m-d H:i';

    private const DATE_FORMAT_LONG = 'Y-m-d H:i:s';

    public function __construct(
        private readonly VaultServiceInterface $vaultService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'pattern',
                'p',
                InputOption::VALUE_REQUIRED,
                'Filter by identifier pattern (supports * wildcard)',
            )
            ->addOption(
                'format',
                null,
                InputOption::VALUE_REQUIRED,
                'Output format: table, json, csv',
                'table',
            )
            ->addOption(
                'limit',
                'l',
                InputOption::VALUE_REQUIRED,
                'Maximum number of results',
                '100',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $pattern = $input->getOption('pattern');
        $format = $input->getOption('format');
        $limitOption = $input->getOption('limit');
        $limit = is_numeric($limitOption) ? (int) $limitOption : 100;

        try {
            $secrets = $this->vaultService->list(\is_string($pattern) ? $pattern : null);

            // Apply limit
            if ($limit > 0 && \count($secrets) > $limit) {
                $secrets = \array_slice($secrets, 0, $limit);
            }

            if ($secrets === []) {
                $io->info('No secrets found');

                return Command::SUCCESS;
            }

            match ($format) {
                'json' => $this->outputJson($output, $secrets),
                'csv' => $this->outputCsv($output, $secrets),
                default => $this->outputTable($io, $secrets),
            };

            return Command::SUCCESS;
        } catch (VaultException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }
    }

    /**
     * @param list<SecretMetadata> $secrets
     */
    private function outputJson(OutputInterface $output, array $secrets): void
    {
        $data = array_map(
            static fn (SecretMetadata $secret): array => $secret->toArray(),
            $secrets,
        );
        $output->writeln(json_encode($data, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
    }

    /**
     * @param list<SecretMetadata> $secrets
     */
    private function outputTable(SymfonyStyle $io, array $secrets): void
    {
        $rows = [];
        foreach ($secrets as $secret) {
            $rows[] = [
                $secret->identifier,
                $secret->ownerUid,
                date(self::DATE_FORMAT_SHORT, $secret->createdAt),
                date(self::DATE_FORMAT_SHORT, $secret->updatedAt),
                $secret->readCount,
                $secret->lastReadAt !== null ? date(self::DATE_FORMAT_SHORT, $secret->lastReadAt) : '-',
            ];
        }

        $io->table(
            ['Identifier', 'Owner', 'Created', 'Updated', 'Reads', 'Last Read'],
            $rows,
        );

        $io->writeln(\sprintf('<info>Total: %d secrets</info>', \count($secrets)));
    }

    /**
     * @param list<SecretMetadata> $secrets
     */
    private function outputCsv(OutputInterface $output, array $secrets): void
    {
        // Header
        $output->writeln('identifier,owner_uid,created,updated,read_count,last_read');

        // Rows
        foreach ($secrets as $secret) {
            $output->writeln(\sprintf(
                '%s,%d,%s,%s,%d,%s',
                CsvFormulaSanitizer::escapeField($secret->identifier),
                $secret->ownerUid,
                date(self::DATE_FORMAT_LONG, $secret->createdAt),
                date(self::DATE_FORMAT_LONG, $secret->updatedAt),
                $secret->readCount,
                $secret->lastReadAt !== null ? date(self::DATE_FORMAT_LONG, $secret->lastReadAt) : '',
            ));
        }
    }
}
