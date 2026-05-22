<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderFactoryInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\MasterKeyException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * CLI command to rotate the master encryption key.
 *
 * Re-encrypts all DEKs with a new master key. Either old or new key
 * can be provided; the missing one defaults to the currently configured key.
 */
#[AsCommand(
    name: 'vault:rotate-master-key',
    description: 'Rotate the master encryption key (re-encrypt all DEKs)',
)]
final class VaultRotateMasterKeyCommand extends Command
{
    private const KEY_LENGTH = 32;

    /**
     * Pseudo-identifier used for master-key lifecycle audit entries.
     * Not a real secret identifier; the audit query layer filters on the
     * `master_key_rotate_*` actions, not on this string.
     */
    private const AUDIT_PSEUDO_IDENTIFIER = '__master_key__';

    public function __construct(
        private readonly SecretRepositoryInterface $secretRepository,
        private readonly EncryptionServiceInterface $encryptionService,
        private readonly MasterKeyProviderFactoryInterface $masterKeyProviderFactory,
        private readonly ConnectionPool $connectionPool,
        private readonly AuditLogServiceInterface $auditLogService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption(
                'old-key',
                null,
                InputOption::VALUE_REQUIRED,
                'Path to file containing the old master key (defaults to current configured key)',
            )
            ->addOption(
                'new-key',
                null,
                InputOption::VALUE_REQUIRED,
                'Path to file containing the new master key (defaults to current configured key)',
            )
            ->addOption(
                'dry-run',
                null,
                InputOption::VALUE_NONE,
                'Simulate the rotation without making changes',
            )
            ->addOption(
                'confirm',
                null,
                InputOption::VALUE_NONE,
                'Confirm the rotation (required for actual execution)',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $dryRun = (bool) $input->getOption('dry-run');
        $confirmed = (bool) $input->getOption('confirm');

        // Get keys
        try {
            $oldKeyPath = $input->getOption('old-key');
            $newKeyPath = $input->getOption('new-key');
            $oldKey = $this->resolveKey(\is_string($oldKeyPath) ? $oldKeyPath : null);
            $newKey = $this->resolveKey(\is_string($newKeyPath) ? $newKeyPath : null);
        } catch (MasterKeyException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }

        // Validate we have different keys
        if (hash_equals($oldKey, $newKey)) {
            $io->error('Old and new master keys are identical. Nothing to rotate.');
            sodium_memzero($oldKey);
            sodium_memzero($newKey);

            return Command::FAILURE;
        }

        // Get all secret identifiers
        $identifiers = $this->secretRepository->findIdentifiers();
        $totalSecrets = \count($identifiers);

        if ($totalSecrets === 0) {
            $io->warning('No secrets found in the vault.');
            sodium_memzero($oldKey);
            sodium_memzero($newKey);

            return Command::SUCCESS;
        }

        $io->title('Master Key Rotation');
        $io->text(\sprintf('Found %d secret(s) to re-encrypt.', $totalSecrets));

        if ($dryRun) {
            $io->note('DRY RUN MODE - No changes will be made.');
        } elseif (!$confirmed) {
            $io->warning([
                'This operation will re-encrypt all DEKs with the new master key.',
                'This is irreversible. Ensure you have backed up the old key.',
                'Use --confirm to proceed or --dry-run to simulate.',
            ]);
            sodium_memzero($oldKey);
            sodium_memzero($newKey);

            return Command::FAILURE;
        }

        // Verify old key works by attempting to decrypt first secret
        $io->text('Verifying old master key...');
        $firstIdentifier = $identifiers[0];
        $firstSecret = $this->secretRepository->findByIdentifier($firstIdentifier);

        if (!$firstSecret instanceof Secret) {
            $io->error('Failed to load first secret for verification.');
            sodium_memzero($oldKey);
            sodium_memzero($newKey);

            return Command::FAILURE;
        }

        try {
            $this->encryptionService->reEncryptDek(
                $firstSecret->getEncryptedDek(),
                $firstSecret->getDekNonce(),
                $firstSecret->getIdentifier(),
                $oldKey,
                $newKey,
            );
            $io->text('<info>Old master key verified successfully.</info>');
        } catch (EncryptionException $e) {
            $io->error([
                'Failed to decrypt with old master key.',
                'Error: ' . $e->getMessage(),
                'Ensure you provided the correct old key.',
            ]);
            sodium_memzero($oldKey);
            sodium_memzero($newKey);

            return Command::FAILURE;
        }

        if ($dryRun) {
            $io->success(\sprintf(
                '[DRY RUN] Would re-encrypt %d secret(s). No changes made.',
                $totalSecrets,
            ));
            sodium_memzero($oldKey);
            sodium_memzero($newKey);

            return Command::SUCCESS;
        }

        // Begin transaction
        $connection = $this->connectionPool->getConnectionForTable('tx_nrvault_secrets');
        $connection->beginTransaction();

        $successCount = 0;
        $failedSecrets = [];

        // Audit the start of the rotation lifecycle. We log BEFORE any state
        // change so that even a catastrophic crash mid-loop leaves a trail.
        $this->auditLogService->log(
            self::AUDIT_PSEUDO_IDENTIFIER,
            'master_key_rotate_start',
            true,
            null,
            \sprintf('Rotating master key for %d secret(s)', $totalSecrets),
        );

        $io->progressStart($totalSecrets);

        try {
            foreach ($identifiers as $identifier) {
                $secret = $this->secretRepository->findByIdentifier($identifier);
                if (!$secret instanceof Secret) {
                    $failedSecrets[] = ['identifier' => $identifier, 'error' => 'Not found'];
                    $io->progressAdvance();

                    continue;
                }

                try {
                    $reEncrypted = $this->encryptionService->reEncryptDek(
                        $secret->getEncryptedDek(),
                        $secret->getDekNonce(),
                        $secret->getIdentifier(),
                        $oldKey,
                        $newKey,
                    );

                    // Update the secret
                    $secret->setEncryptedDek($reEncrypted->encryptedDek);
                    $secret->setDekNonce($reEncrypted->nonce);
                    $this->secretRepository->save($secret);

                    ++$successCount;
                } catch (EncryptionException $e) {
                    $failedSecrets[] = ['identifier' => $identifier, 'error' => $e->getMessage()];
                }

                $io->progressAdvance();
            }

            $io->progressFinish();

            if ($failedSecrets !== []) {
                $connection->rollBack();
                $io->error(\sprintf(
                    'Rotation failed for %d secret(s). Transaction rolled back.',
                    \count($failedSecrets),
                ));
                $io->table(
                    ['Identifier', 'Error'],
                    array_map(
                        static fn (array $f): array => [$f['identifier'], $f['error']],
                        $failedSecrets,
                    ),
                );
                $this->auditLogService->log(
                    self::AUDIT_PSEUDO_IDENTIFIER,
                    'master_key_rotate_end',
                    false,
                    \sprintf('Rotation failed for %d secret(s); transaction rolled back', \count($failedSecrets)),
                );
                sodium_memzero($oldKey);
                sodium_memzero($newKey);

                return Command::FAILURE;
            }

            $connection->commit();
        } catch (Throwable $e) {
            $connection->rollBack();
            $io->error('Unexpected error during rotation: ' . $e->getMessage());
            // Do not propagate $e->getMessage() into the audit log to avoid
            // leaking libsodium/internal detail (CLAUDE.md security rule 1).
            $this->auditLogService->log(
                self::AUDIT_PSEUDO_IDENTIFIER,
                'master_key_rotate_end',
                false,
                'Unexpected error during rotation; transaction rolled back',
            );
            sodium_memzero($oldKey);
            sodium_memzero($newKey);

            return Command::FAILURE;
        }

        $this->auditLogService->log(
            self::AUDIT_PSEUDO_IDENTIFIER,
            'master_key_rotate_end',
            true,
            null,
            \sprintf('Successfully rotated master key for %d secret(s)', $successCount),
        );

        $io->success(\sprintf(
            'Successfully rotated master key for %d secret(s).',
            $successCount,
        ));

        $io->note([
            'Next steps:',
            '1. Update your configuration to use the new master key',
            '2. Securely archive or destroy the old master key',
            '3. Test secret retrieval to verify the rotation',
        ]);

        sodium_memzero($oldKey);
        sodium_memzero($newKey);

        return Command::SUCCESS;
    }

    /**
     * Resolve a key from file path or fall back to configured provider.
     */
    private function resolveKey(?string $keyPath): string
    {
        if ($keyPath !== null) {
            return $this->loadKeyFromFile($keyPath);
        }

        // Fall back to currently configured master key
        $provider = $this->masterKeyProviderFactory->getAvailableProvider();

        return $provider->getMasterKey();
    }

    /**
     * Load a master key from a file.
     */
    private function loadKeyFromFile(string $path): string
    {
        if (!file_exists($path)) {
            throw MasterKeyException::notFound($path);
        }

        if (!is_readable($path)) {
            throw MasterKeyException::notFound($path . ' (not readable)');
        }

        $key = file_get_contents($path);
        if ($key === false) {
            throw MasterKeyException::notFound($path);
        }

        // Handle base64-encoded keys
        if (\strlen($key) !== self::KEY_LENGTH) {
            $decoded = base64_decode($key, true);
            if ($decoded !== false && \strlen($decoded) === self::KEY_LENGTH) {
                $key = $decoded;
            }
        }

        // Trim whitespace (e.g., trailing newline)
        $key = trim($key);

        if (\strlen($key) !== self::KEY_LENGTH) {
            throw MasterKeyException::invalidLength(self::KEY_LENGTH, \strlen($key));
        }

        return $key;
    }
}
