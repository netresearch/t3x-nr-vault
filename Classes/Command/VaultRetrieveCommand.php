<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Exception\SecretNotFoundException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * CLI command to retrieve a secret from the vault.
 */
#[AsCommand(
    name: 'vault:retrieve',
    description: 'Retrieve a secret from the vault',
)]
final class VaultRetrieveCommand extends Command
{
    public function __construct(
        private readonly VaultServiceInterface $vaultService,
        private readonly AccessControlServiceInterface $accessControlService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument(
                'identifier',
                InputArgument::REQUIRED,
                'Identifier of the secret to retrieve',
            )
            ->addOption(
                'output',
                'o',
                InputOption::VALUE_REQUIRED,
                'Write secret to file instead of stdout',
            )
            ->addOption(
                'no-newline',
                null,
                InputOption::VALUE_NONE,
                'Do not append newline to output',
            )
            ->addOption(
                'reason',
                'r',
                InputOption::VALUE_REQUIRED,
                'Reason for retrieving this secret (for audit log)',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $identifierArg = $input->getArgument('identifier');
        $identifier = \is_string($identifierArg) ? $identifierArg : '';

        // This command prints plaintext to a terminal (or writes it to a file),
        // so it is a reveal surface and needs `secret.reveal` on top of the
        // per-secret read access VaultService::retrieve() asserts. For a
        // trusted CLI operator the vault's `allowCliAccess` switch decides;
        // when invoked as a backend user, that user's group grants do.
        if (!$this->accessControlService->isGranted(VaultPermission::SecretReveal)) {
            $io->error(\sprintf(
                'Access denied: the "%s" permission is required to print a secret value.',
                VaultPermission::SecretReveal->value,
            ));

            return Command::FAILURE;
        }

        try {
            $value = $this->vaultService->retrieve($identifier);

            if ($value === null) {
                throw new SecretNotFoundException($identifier, 9236747158);
            }

            $outputFileOption = $input->getOption('output');
            $outputFile = \is_string($outputFileOption) ? $outputFileOption : null;
            if ($outputFile !== null) {
                // Check if parent directory exists
                $directory = \dirname($outputFile);
                if (!is_dir($directory)) {
                    $io->error(\sprintf('Failed to write to file: %s', $outputFile));
                    sodium_memzero($value);

                    return Command::FAILURE;
                }

                // Eliminate the umask race: tighten umask before the write so
                // the file is created 0600, then chmod to enforce it even when
                // the file already existed. The previous order
                // (file_put_contents -> chmod) left a brief window where a
                // freshly created file was world-readable on hosts with
                // permissive umasks, and a permanent 0644 file if the process
                // was interrupted before the chmod. Mirrors
                // FileMasterKeyProvider::storeMasterKey().
                $previousUmask = umask(0o077);

                try {
                    $result = file_put_contents($outputFile, $value);
                } finally {
                    umask($previousUmask);
                }

                if ($result === false) {
                    $io->error(\sprintf('Failed to write to file: %s', $outputFile));
                    sodium_memzero($value);

                    return Command::FAILURE;
                }

                // Enforce restrictive permissions (also tightens a pre-existing
                // file, which umask cannot) and fail loudly if it cannot be set
                if (!chmod($outputFile, 0o600)) {
                    $io->error(\sprintf('Failed to set permissions on file: %s', $outputFile));
                    sodium_memzero($value);

                    return Command::FAILURE;
                }

                $io->success(\sprintf('Secret written to: %s', $outputFile));
            } else {
                // Write to stdout
                $newline = $input->getOption('no-newline') ? '' : PHP_EOL;
                $output->write($value . $newline, false, OutputInterface::OUTPUT_RAW);
            }

            // Clear the value from memory
            sodium_memzero($value);

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
