<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * CLI command to delete a secret from the vault.
 */
#[AsCommand(
    name: 'vault:delete',
    description: 'Delete a secret from the vault',
)]
final class VaultDeleteCommand extends Command
{
    public function __construct(
        private readonly VaultServiceInterface $vaultService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument(
                'identifier',
                InputArgument::REQUIRED,
                'Identifier of the secret to delete',
            )
            ->addOption(
                'reason',
                'r',
                InputOption::VALUE_REQUIRED,
                'Reason for deletion (required for audit)',
                'Manual deletion via CLI',
            )
            ->addOption(
                'force',
                'f',
                InputOption::VALUE_NONE,
                'Skip confirmation prompt',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $identifierArg = $input->getArgument('identifier');
        $identifier = \is_string($identifierArg) ? $identifierArg : '';
        $reasonOption = $input->getOption('reason');
        $reason = \is_string($reasonOption) ? $reasonOption : 'Manual deletion via CLI';

        // Check if secret exists
        try {
            $metadata = $this->vaultService->getMetadata($identifier);
        } catch (SecretNotFoundException) {
            $io->error(\sprintf('Secret not found: %s', $identifier));

            return Command::FAILURE;
        }

        // Show metadata before deletion
        $io->section('Secret to be deleted');
        $io->table(
            ['Property', 'Value'],
            [
                ['Identifier', $identifier],
                ['Created', date('Y-m-d H:i:s', $metadata->createdAt)],
                ['Read count', (string) $metadata->readCount],
                ['Last read', $metadata->lastReadAt !== null ? date('Y-m-d H:i:s', $metadata->lastReadAt) : 'Never'],
            ],
        );

        // Confirm unless --force
        if (!$input->getOption('force')) {
            $confirmed = $io->confirm(
                \sprintf(
                    'Are you sure you want to delete secret "%s"? The vault cannot restore it. '
                    . 'The encrypted row is retained in the database until it is removed there.',
                    $identifier,
                ),
                false,
            );

            if (!$confirmed) {
                $io->info('Deletion cancelled');

                return Command::SUCCESS;
            }
        }

        try {
            $this->vaultService->delete($identifier, $reason);
            $io->success(\sprintf('Secret "%s" deleted successfully', $identifier));

            return Command::SUCCESS;
        } catch (SecretNotFoundException) {
            $io->error(\sprintf('Secret not found: %s', $identifier));

            return Command::FAILURE;
        } catch (VaultException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }
    }
}
