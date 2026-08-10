<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\TechnicalActorException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * CLI command to store a secret in the vault.
 */
#[AsCommand(
    name: 'vault:store',
    description: 'Store a secret in the vault',
)]
final class VaultStoreCommand extends Command
{
    public function __construct(
        private readonly VaultServiceInterface $vaultService,
        private readonly ExtensionConfigurationInterface $configuration,
        private readonly TechnicalActorContextInterface $technicalActorContext,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument(
                'identifier',
                InputArgument::REQUIRED,
                'Unique identifier for the secret (alphanumeric, underscores, max 255 chars)',
            )
            ->addOption(
                'value',
                null,
                InputOption::VALUE_REQUIRED,
                'The secret value (will prompt if not provided)',
            )
            ->addOption(
                'stdin',
                null,
                InputOption::VALUE_NONE,
                'Read secret value from stdin',
            )
            ->addOption(
                'file',
                'f',
                InputOption::VALUE_REQUIRED,
                'Read secret value from file',
            )
            ->addOption(
                'metadata',
                'm',
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Additional metadata as key=value pairs',
            )
            ->addOption(
                'groups',
                'g',
                InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY,
                'Backend user group IDs that can access this secret',
            )
            ->addOption(
                'as-provisioner',
                null,
                InputOption::VALUE_NONE,
                'Write as the configured provisioning backend user (nr_vault option '
                . '"provisioningBeUserUid") instead of the unattributed CLI actor. The UID '
                . 'comes from configuration, never from this command line.',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $identifierArg = $input->getArgument('identifier');
        $identifier = \is_string($identifierArg) ? $identifierArg : '';

        // Get secret value from various sources
        $value = $this->getSecretValue($input, $io);
        if ($value === null) {
            $io->error('No secret value provided');

            return Command::FAILURE;
        }

        // Parse metadata
        $metadataOption = $input->getOption('metadata');
        $metadataPairs = \is_array($metadataOption) ? $metadataOption : [];
        $metadata = $this->parseMetadata($metadataPairs);

        // Add groups to metadata if specified
        $groups = $input->getOption('groups');
        if (\is_array($groups) && $groups !== []) {
            $metadata['allowed_groups'] = array_map(
                static fn (mixed $v): int => is_numeric($v) ? (int) $v : 0,
                $groups,
            );
        }

        $asProvisioner = $input->getOption('as-provisioner') !== false;
        $provisionerUid = $this->configuration->getProvisioningBeUserUid();

        if ($asProvisioner && $provisionerUid === 0) {
            sodium_memzero($value);
            $io->error(
                'No provisioning actor is configured. Set the nr_vault option '
                . '"provisioningBeUserUid" to a backend user whose group carries the '
                . 'tx_nrvault:secret.create permission option.',
            );

            return Command::FAILURE;
        }

        try {
            if ($asProvisioner) {
                $this->technicalActorContext->runAs(
                    $provisionerUid,
                    function () use ($identifier, $value, $metadata): void {
                        $this->vaultService->store($identifier, $value, $metadata);
                    },
                );
            } else {
                $this->vaultService->store($identifier, $value, $metadata);
            }

            $io->success(\sprintf('Secret "%s" stored successfully', $identifier));

            // Clear the value from memory
            sodium_memzero($value);

            return Command::SUCCESS;
        } catch (VaultException|TechnicalActorException $e) {
            sodium_memzero($value);
            $io->error($e->getMessage());

            return Command::FAILURE;
        }
    }

    private function getSecretValue(InputInterface $input, SymfonyStyle $io): ?string
    {
        // Option 1: From --value option
        $value = $input->getOption('value');
        if (\is_string($value)) {
            return $value;
        }

        // Option 2: From stdin
        if ($input->getOption('stdin') !== false) {
            $stdinValue = file_get_contents('php://stdin');
            if ($stdinValue !== false) {
                return rtrim($stdinValue, "\n\r");
            }

            return null;
        }

        // Option 3: From file
        $file = $input->getOption('file');
        if (\is_string($file)) {
            if (!file_exists($file)) {
                $io->error(\sprintf('File not found: %s', $file));

                return null;
            }

            $fileValue = file_get_contents($file);
            if ($fileValue !== false) {
                return $fileValue;
            }

            return null;
        }

        // Option 4: Interactive prompt (hidden input)
        if ($input->isInteractive()) {
            $hiddenInput = $io->askHidden('Enter secret value');

            return \is_string($hiddenInput) ? $hiddenInput : null;
        }

        return null;
    }

    /**
     * @param array<int|string, mixed> $pairs
     *
     * @return array<string, string>
     */
    private function parseMetadata(array $pairs): array
    {
        $metadata = [];
        foreach ($pairs as $pair) {
            $pairStr = \is_string($pair) ? $pair : '';
            if (str_contains($pairStr, '=')) {
                [$key, $value] = explode('=', $pairStr, 2);
                $metadata[trim($key)] = trim($value);
            }
        }

        return $metadata;
    }
}
