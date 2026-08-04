<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use TYPO3\CMS\Core\Core\Environment;

/**
 * CLI command to initialize the vault (generate master key).
 */
#[AsCommand(
    name: 'vault:init',
    description: 'Initialize the vault by generating a master key',
)]
final class VaultInitCommand extends Command
{
    public function __construct(
        private readonly ExtensionConfigurationInterface $configuration,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'output',
                'o',
                InputOption::VALUE_REQUIRED,
                'Output file for the master key (defaults to configured path or var/vault/master.key)',
            )
            ->addOption(
                'force',
                'f',
                InputOption::VALUE_NONE,
                'Overwrite existing master key (DANGEROUS: will make existing secrets unrecoverable)',
            )
            ->addOption(
                'env',
                'e',
                InputOption::VALUE_NONE,
                'Output key as environment variable format instead of file',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        // Check if using typo3 provider (no init needed)
        $provider = $this->configuration->getMasterKeyProvider();
        if ($provider === 'typo3' && !$input->getOption('output') && !$input->getOption('env')) {
            $io->success('No initialization needed. Using TYPO3 encryption key as master key provider.');
            $io->note('To use a different provider, configure masterKeyProvider in extension settings.');

            return Command::SUCCESS;
        }

        // Determine output location
        $outputFileOption = $input->getOption('output');
        $outputFile = \is_string($outputFileOption) ? $outputFileOption : null;
        $outputEnv = $input->getOption('env');

        if ($outputFile === null && $outputEnv === false) {
            $outputFile = $this->resolveDefaultOutputFile();
        }

        // Check if key already exists
        if ($outputFile !== null && $outputFile !== '' && file_exists($outputFile) && !$input->getOption('force')) {
            $io->error(\sprintf(
                'Master key already exists at: %s' . PHP_EOL .
                'Use --force to overwrite (WARNING: existing secrets will become unrecoverable)',
                $outputFile,
            ));

            return Command::FAILURE;
        }

        // Generate master key using sodium
        $masterKey = sodium_crypto_secretbox_keygen();

        if ($outputEnv !== false) {
            // Output as environment variable format
            $encoded = sodium_bin2base64($masterKey, SODIUM_BASE64_VARIANT_ORIGINAL);
            $io->writeln('Add the following to your environment:');
            $io->newLine();
            $io->writeln(\sprintf('export TYPO3_VAULT_MASTER_KEY="%s"', $encoded));
            $io->newLine();
            $io->warning('Store this key securely! It cannot be recovered if lost.');
        } else {
            $writeResult = $this->writeMasterKeyToFile($io, $outputFile ?? '', $masterKey);
            if ($writeResult !== Command::SUCCESS) {
                sodium_memzero($masterKey);

                return $writeResult;
            }
        }

        // Clear key from memory
        sodium_memzero($masterKey);

        return Command::SUCCESS;
    }

    /**
     * Resolve the default master key output file from configuration or fall back to the var path.
     */
    private function resolveDefaultOutputFile(): string
    {
        // Use configured source (file path) or default
        $source = $this->configuration->getMasterKeySource();
        // Only use source if it looks like a path (contains / or \)
        $outputFile = (str_contains($source, '/') || str_contains($source, '\\')) ? $source : '';
        if ($outputFile === '') {
            return Environment::getVarPath() . '/vault/master.key';
        }

        return $outputFile;
    }

    /**
     * Persist the master key to disk with restrictive permissions; the caller zeroes the key.
     */
    private function writeMasterKeyToFile(SymfonyStyle $io, string $outputFilePath, string $masterKey): int
    {
        // Ensure directory exists
        $dir = \dirname($outputFilePath);
        if (!is_dir($dir) && !mkdir($dir, 0o700, true)) {
            $io->error(\sprintf('Failed to create directory: %s', $dir));

            return Command::FAILURE;
        }

        // Eliminate the umask race: tighten umask before the write so the file
        // is created 0600, then chmod to enforce it even when the file already
        // existed. The previous order (file_put_contents -> chmod) left a brief
        // window where a freshly created key file was world-readable on hosts
        // with permissive umasks, and a permanent 0644 file if the process was
        // interrupted before the chmod. Mirrors
        // FileMasterKeyProvider::storeMasterKey().
        $previousUmask = umask(0o077);

        try {
            $result = file_put_contents($outputFilePath, $masterKey);
        } finally {
            umask($previousUmask);
        }

        if ($result === false) {
            $io->error(\sprintf('Failed to write master key to: %s', $outputFilePath));

            return Command::FAILURE;
        }

        // Enforce restrictive permissions (owner read/write only), also on a
        // pre-existing file, and fail loudly if it cannot be secured
        if (!chmod($outputFilePath, 0o600)) {
            $io->error(\sprintf('Failed to set permissions on master key file: %s', $outputFilePath));

            return Command::FAILURE;
        }

        $io->success(\sprintf('Master key generated and saved to: %s', $outputFilePath));
        $io->table(
            ['Property', 'Value'],
            [
                ['Key file', $outputFilePath],
                ['Permissions', '0600 (owner read/write only)'],
                ['Algorithm', 'XSalsa20-Poly1305 (sodium_crypto_secretbox)'],
                ['Key length', \strlen($masterKey) . ' bytes'],
            ],
        );

        $io->warning([
            'IMPORTANT SECURITY NOTES:',
            '1. Back up this key securely - it cannot be recovered if lost',
            '2. All secrets are unrecoverable without this key',
            '3. Keep this file outside of version control',
            '4. Consider using environment variables in production',
        ]);

        return Command::SUCCESS;
    }
}
