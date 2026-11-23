<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use InvalidArgumentException;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\SecretNotFoundException;
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

use function array_key_exists;
use function filter_var;
use function in_array;
use function is_array;
use function is_string;
use function sprintf;

/**
 * CLI command to store a secret in the vault.
 */
#[AsCommand(
    name: 'vault:store',
    description: 'Store a secret in the vault',
)]
final class VaultStoreCommand extends Command
{
    /**
     * `--metadata` keys that set a field of the secret instead of a metadata
     * entry (documented in Commands.rst). The service reads them as top-level
     * store() options.
     */
    private const FIELD_KEYS = ['description', 'context', 'expiresAt', 'owner', 'scopePid'];

    /**
     * Numeric field keys: a non-numeric expiresAt or owner silently became 0
     * (no expiry, owner 0) in the service, and a non-numeric scopePid was
     * ignored.
     */
    private const RECORD_LINK_REASON = 'reserved for the record link that orphan cleanup reads';

    private const DIGIT_FIELD_KEYS = ['expiresAt', 'owner', 'scopePid'];

    /**
     * `--metadata` keys that are refused, with the reason shown to the caller.
     * `groups` as a string clears the read groups in the service, a string
     * `frontendAccessible` is cast with (bool) so "false" widens exposure, and
     * the record-link keys are what orphan cleanup selects candidates by.
     */
    private const REFUSED_KEYS = [
        'groups'             => 'use --groups (repeatable) to set the groups that may read the secret',
        'frontendAccessible' => 'frontend availability cannot be set by vault:store; use the backend module or the VaultService API',
        'metadata'           => 'pass metadata entries as key=value pairs directly',
        'source'             => self::RECORD_LINK_REASON,
        'table'              => self::RECORD_LINK_REASON,
        'field'              => self::RECORD_LINK_REASON,
        'flexField'          => self::RECORD_LINK_REASON,
        'uid'                => self::RECORD_LINK_REASON,
    ];

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
                'Unique secret identifier: friendly name, UUIDv7, or site:<siteIdentifier>:<friendlyName> (max 255 bytes; new namespaces require the exact configured site)',
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
                'Metadata as key=value pairs, merged into the stored metadata; description, context, expiresAt, owner and scopePid set those fields',
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
        $io            = new SymfonyStyle($input, $output);
        $identifierArg = $input->getArgument('identifier');
        $identifier    = is_string($identifierArg) ? $identifierArg : '';

        // Options are validated before the secret value is read, so a refused
        // invocation never prompts for, or holds, the plaintext.
        try {
            $metadataOption       = $input->getOption('metadata');
            [$options, $freeForm] = $this->parseMetadata(is_array($metadataOption) ? $metadataOption : []);
            $groups               = $this->parseGroups($input->getOption('groups'));
        } catch (InvalidArgumentException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }

        if ($groups !== []) {
            $options['groups'] = $groups;
        }

        // Get secret value from various sources
        $value = $this->getSecretValue($input, $io);
        if ($value === null) {
            $io->error('No secret value provided');

            return Command::FAILURE;
        }

        $asProvisioner  = $input->getOption('as-provisioner') !== false;
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

        // $value by REFERENCE: capturing it by value gives the closure its own
        // copy of the plaintext, and sodium_memzero() below separates the
        // copy-on-write pair instead of wiping both — the secret would survive
        // in memory in the copy the command believes it has cleared. The
        // metadata merge reads inside the closure, so it runs as the same actor
        // and inside the `finally` that wipes the value.
        $store = function () use ($identifier, &$value, $options, $freeForm): void {
            if ($freeForm !== []) {
                $options['metadata'] = $this->mergeMetadata($identifier, $freeForm);
            }

            $this->vaultService->store($identifier, $value, $options);
        };

        try {
            if ($asProvisioner) {
                $this->technicalActorContext->runAs($provisionerUid, $store);
            } else {
                $store();
            }

            $io->success(sprintf('Secret "%s" stored successfully', $identifier));

            return Command::SUCCESS;
        } catch (VaultException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        } finally {
            // In `finally`, not on each branch: the two branches cover a
            // successful store and a VaultException, and everything else left
            // the plaintext in memory. `runAs()` resolves the actor before the
            // callback runs and can fail with something that is not a
            // VaultException; so can an audit write underneath the store. Both
            // restore their own state and neither wipes this copy, and there is
            // no outer cleanup that would (CWE-316).
            sodium_memzero($value);
        }
    }

    private function getSecretValue(InputInterface $input, SymfonyStyle $io): ?string
    {
        // Option 1: From --value option
        $value = $input->getOption('value');
        if (is_string($value)) {
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
        if (is_string($file)) {
            if (!file_exists($file)) {
                $io->error(sprintf('File not found: %s', $file));

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

            return is_string($hiddenInput) ? $hiddenInput : null;
        }

        return null;
    }

    /**
     * Split `--metadata` pairs into the field options the service reads at the
     * top level and the free-form entries that belong under `metadata`.
     *
     * @param array<int|string, mixed> $pairs
     *
     * @return array{0: array<string, string>, 1: array<string, string>}
     *
     * @throws InvalidArgumentException For a pair the command refuses
     */
    private function parseMetadata(array $pairs): array
    {
        $fields   = [];
        $freeForm = [];
        foreach ($pairs as $pair) {
            $pairStr = is_string($pair) ? $pair : '';
            if (!str_contains($pairStr, '=')) {
                throw new InvalidArgumentException(sprintf('Invalid --metadata value "%s": expected key=value.', $pairStr), 6640528976);
            }

            [$key, $value] = explode('=', $pairStr, 2);
            $key           = trim($key);
            $value         = trim($value);

            if ($key === '') {
                throw new InvalidArgumentException(sprintf('Invalid --metadata value "%s": the key is empty.', $pairStr), 7659108060);
            }

            if (array_key_exists($key, self::REFUSED_KEYS)) {
                throw new InvalidArgumentException(sprintf('--metadata %s is not accepted: %s.', $key, self::REFUSED_KEYS[$key]), 2664192772);
            }

            if (in_array($key, self::DIGIT_FIELD_KEYS, true) && filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => 4294967295]]) === false) {
                throw new InvalidArgumentException(sprintf('--metadata %s must be a non-negative integer, got "%s".', $key, $value), 8227215868);
            }

            if (in_array($key, self::FIELD_KEYS, true)) {
                $fields[$key] = $value;
            } else {
                $freeForm[$key] = $value;
            }
        }

        return [$fields, $freeForm];
    }

    /**
     * @return list<int> Distinct backend group UIDs; empty when none were given
     *
     * @throws InvalidArgumentException For a value that is not a positive integer
     */
    private function parseGroups(mixed $option): array
    {
        $groups = [];
        foreach (is_array($option) ? $option : [] as $group) {
            $groupStr = is_string($group) ? $group : '';
            if (filter_var($groupStr, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 4294967295]]) === false) {
                throw new InvalidArgumentException(sprintf(
                    'Invalid --groups value "%s": pass one positive backend group UID per option, e.g. --groups=1 --groups=2.',
                    $groupStr,
                ), 8422879066);
            }

            $groups[] = (int) $groupStr;
        }

        return array_values(array_unique($groups));
    }

    /**
     * The service replaces the metadata map; merge the given entries into the
     * stored one so an update keeps the entries it does not name. A secret
     * that does not exist yet (disabled ones included: getMetadata() sees them,
     * exists() does not) starts from an empty map.
     *
     * @param array<string, string> $entries
     *
     * @return array<string, mixed>
     */
    private function mergeMetadata(string $identifier, array $entries): array
    {
        try {
            $stored = $this->vaultService->getMetadata($identifier)->metadata;
        } catch (SecretNotFoundException) {
            return $entries;
        } catch (AccessDeniedException) {
            throw AccessDeniedException::forIdentifier(
                $identifier,
                'reading its metadata to merge --metadata is not permitted; leave out --metadata to store without reading it',
            );
        }

        return array_replace($stored, $entries);
    }
}
