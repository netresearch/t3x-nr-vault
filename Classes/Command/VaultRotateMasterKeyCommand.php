<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use DateTimeImmutable;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditChainLockTrait;
use Netresearch\NrVault\Audit\AuditChainRekeyServiceInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Crypto\EnvelopeCodecInterface;
use Netresearch\NrVault\Crypto\EnvelopeRotationContext;
use Netresearch\NrVault\Crypto\ForeignEnvelopeRotatorInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderFactoryInterface;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Event\MasterKeyRotatedEvent;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\MasterKeyException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
use Psr\EventDispatcher\EventDispatcherInterface;
use SensitiveParameter;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * CLI command to rotate the master encryption key.
 *
 * Re-encrypts all DEKs with a new master key. Either old or new key
 * can be provided; the missing one defaults to the currently configured key.
 *
 * The tamper-evident audit chain is keyed via HKDF from the master key, so
 * the chain is re-keyed under the new key INSIDE the same transaction as the
 * DEK re-encryption: either both commit or both roll back, and
 * `AuditLogServiceInterface::verifyHashChain()` stays valid before (old key)
 * and after (new key, once the provider configuration is switched).
 */
#[AsCommand(
    name: 'vault:rotate-master-key',
    description: 'Rotate the master encryption key (re-encrypt all DEKs)',
)]
final class VaultRotateMasterKeyCommand extends Command
{
    use AuditChainLockTrait;

    private const KEY_LENGTH = 32;

    /**
     * Pseudo-identifier used for master-key lifecycle audit entries.
     * Not a real secret identifier; the audit query layer filters on the
     * `master_key_rotate_*` actions, not on this string.
     */
    private const AUDIT_PSEUDO_IDENTIFIER = '__master_key__';

    /**
     * @param iterable<ForeignEnvelopeRotatorInterface> $foreignRotators
     */
    public function __construct(
        private readonly SecretRepositoryInterface $secretRepository,
        private readonly EncryptionServiceInterface $encryptionService,
        private readonly MasterKeyProviderFactoryInterface $masterKeyProviderFactory,
        private readonly ConnectionPool $connectionPool,
        private readonly AuditLogServiceInterface $auditLogService,
        private readonly AuditChainRekeyServiceInterface $auditChainRekeyService,
        private readonly EnvelopeCodecInterface $envelopeCodec,
        private readonly AccessControlServiceInterface $accessControlService,
        private readonly EventDispatcherInterface $eventDispatcher,
        private readonly iterable $foreignRotators = [],
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

        // Master-key rotation rewrites every envelope in the store and rekeys
        // the audit chain — the most powerful vault operation, so it carries
        // its own operation permission. For a trusted CLI operator the vault's
        // `allowCliAccess` switch decides; invoked as a backend user, the
        // admin override or that user's group grants do.
        if (!$this->accessControlService->isGranted(VaultPermission::MasterKeyRotate)) {
            $io->error(\sprintf(
                'Access denied: the "%s" permission is required to rotate the master key.',
                VaultPermission::MasterKeyRotate->value,
            ));

            return Command::FAILURE;
        }

        try {
            $oldKeyPath = $input->getOption('old-key');
            $newKeyPath = $input->getOption('new-key');
            $oldKey = $this->resolveKey(\is_string($oldKeyPath) ? $oldKeyPath : null);
            $newKey = $this->resolveKey(\is_string($newKeyPath) ? $newKeyPath : null);
        } catch (MasterKeyException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }

        try {
            return $this->runRotation(
                $io,
                $oldKey,
                $newKey,
                (bool) $input->getOption('dry-run'),
                (bool) $input->getOption('confirm'),
            );
        } finally {
            sodium_memzero($oldKey);
            sodium_memzero($newKey);
        }
    }

    /**
     * Orchestrates the rotation pipeline. Pre-flight checks → confirmation →
     * key verification → dry-run short-circuit → transactional re-encryption.
     */
    private function runRotation(
        SymfonyStyle $io,
        string $oldKey,
        string $newKey,
        bool $dryRun,
        bool $confirmed,
    ): int {
        if (hash_equals($oldKey, $newKey)) {
            $io->error('Old and new master keys are identical. Nothing to rotate.');

            return Command::FAILURE;
        }

        $identifiers = $this->secretRepository->findIdentifiers();
        $totalSecrets = \count($identifiers);

        // Consumer-owned envelopes are part of the rotation, so they are part of
        // the inventory: a vault with no secrets of its own may still be the key
        // authority for thousands of foreign envelopes (ADR-033).
        $foreignCounts = $this->inventoryForeignRotators($io);
        if ($foreignCounts === null) {
            return Command::FAILURE;
        }

        $totalForeign = array_sum($foreignCounts);

        if ($totalSecrets === 0 && $totalForeign === 0) {
            $io->warning('No secrets found in the vault, and no consumer-owned envelopes registered.');

            return Command::SUCCESS;
        }

        $io->title('Master Key Rotation');
        $io->text(\sprintf('Found %d secret(s) to re-encrypt.', $totalSecrets));
        $this->reportForeignInventory($io, $foreignCounts);

        if (!$this->confirmExecution($io, $dryRun, $confirmed)) {
            return Command::FAILURE;
        }

        // The smoke test re-encrypts one real secret to prove the old key is the
        // right one. With no vault secrets there is nothing to test against; the
        // foreign pass then does the proving, and its failure rolls everything
        // back — so this is a lost early warning, not a lost safety net.
        if ($totalSecrets > 0) {
            if (!$this->verifyOldKey($io, $identifiers[0], $oldKey, $newKey)) {
                return Command::FAILURE;
            }
        } elseif ($totalForeign > 0) {
            $io->note(
                'The vault holds no secrets of its own, so the old master key cannot be '
                . 'smoke-tested up front. A wrong key will surface as a failure of the '
                . 'consumer-envelope pass, which rolls the rotation back.',
            );
        }

        if ($dryRun) {
            $io->text(\sprintf('Would re-wrap %d consumer-owned envelope(s).', $totalForeign));
            $io->success(\sprintf(
                '[DRY RUN] Would re-encrypt %d secret(s). No changes made.',
                $totalSecrets,
            ));

            return Command::SUCCESS;
        }

        return $this->rotateAllSecrets($io, $identifiers, $oldKey, $newKey, $totalSecrets, $totalForeign);
    }

    /**
     * Show the dry-run notice or require explicit --confirm for irreversible
     * runs. Returns false to abort with FAILURE if the user must opt in first.
     */
    private function confirmExecution(SymfonyStyle $io, bool $dryRun, bool $confirmed): bool
    {
        if ($dryRun) {
            $io->note('DRY RUN MODE - No changes will be made.');

            return true;
        }

        if (!$confirmed) {
            $io->warning([
                'This operation will re-encrypt all DEKs with the new master key.',
                'This is irreversible. Ensure you have backed up the old key.',
                'Use --confirm to proceed or --dry-run to simulate.',
            ]);

            return false;
        }

        return true;
    }

    /**
     * Count the envelopes every registered consumer holds, keyed by its label.
     *
     * Returns null when a consumer cannot be inventoried: not knowing what a
     * rotation is about to touch is a reason to refuse it, not to proceed and
     * find out.
     *
     * @return array<string, int>|null
     */
    private function inventoryForeignRotators(SymfonyStyle $io): ?array
    {
        $counts = [];

        foreach ($this->foreignRotators as $rotator) {
            $label = $rotator->getIdentifier();

            try {
                $counts[$label] = $rotator->countEnvelopes();
            } catch (Throwable $exception) {
                $io->error([
                    \sprintf('Could not inventory consumer-owned envelopes for "%s".', $label),
                    'Error: ' . $exception->getMessage(),
                    'Rotation refused; nothing was changed.',
                ]);

                return null;
            }
        }

        return $counts;
    }

    /**
     * @param array<string, int> $foreignCounts
     */
    private function reportForeignInventory(SymfonyStyle $io, array $foreignCounts): void
    {
        if ($foreignCounts === []) {
            $io->text('No consumer-owned envelope rotators registered.');

            return;
        }

        $io->text('Consumer-owned envelopes participating in this rotation:');
        foreach ($foreignCounts as $label => $count) {
            $io->text(\sprintf('  - %s: %d envelope(s)', $label, $count));
        }
    }

    /**
     * Re-wrap every registered consumer's envelopes inside the caller's open
     * transaction, returning the total re-wrapped.
     *
     * The keys are handed over as an {@see EnvelopeRotationContext} so a consumer
     * can move an envelope between keys without ever holding one.
     *
     * @throws Throwable Propagates any consumer failure for the caller's rollback
     */
    private function rewrapForeignEnvelopes(
        SymfonyStyle $io,
        #[SensitiveParameter]
        string $oldKey,
        #[SensitiveParameter]
        string $newKey,
    ): int {
        $context = new EnvelopeRotationContext($this->envelopeCodec, $oldKey, $newKey);
        $total = 0;

        foreach ($this->foreignRotators as $rotator) {
            $rewrapped = $rotator->rewrapAll($context);
            $total += $rewrapped;
            $io->text(\sprintf(
                '  - %s: re-wrapped %d envelope(s).',
                $rotator->getIdentifier(),
                $rewrapped,
            ));
        }

        return $total;
    }

    /**
     * Refuse the rotation when a consumer's tables live on a different database
     * connection than the vault's, because then "one transaction" is a fiction
     * and a partial rotation could commit. Mirrors the audit-table precondition.
     */
    private function foreignTablesShareConnection(SymfonyStyle $io, Connection $connection): bool
    {
        foreach ($this->foreignRotators as $rotator) {
            foreach ($rotator->getTables() as $table) {
                if ($this->connectionPool->getConnectionForTable($table) !== $connection) {
                    $io->error(\sprintf(
                        'Table "%s" (owned by %s) is mapped to a different database connection than '
                        . 'tx_nrvault_secret; atomic master-key rotation across both is not possible.',
                        $table,
                        $rotator->getIdentifier(),
                    ));
                    $this->auditLogService->log(
                        self::AUDIT_PSEUDO_IDENTIFIER,
                        AuditAction::MasterKeyRotateEnd->value,
                        false,
                        'Rotation refused: a consumer table is on a different connection; nothing changed',
                    );

                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Smoke-test the old master key by attempting a single re-encryption.
     * Catches a wrong-key scenario before touching the rest of the vault.
     */
    private function verifyOldKey(
        SymfonyStyle $io,
        string $firstIdentifier,
        string $oldKey,
        string $newKey,
    ): bool {
        $io->text('Verifying old master key...');
        $firstSecret = $this->secretRepository->findByIdentifier($firstIdentifier);

        if (!$firstSecret instanceof Secret) {
            $io->error('Failed to load first secret for verification.');

            return false;
        }

        try {
            $this->encryptionService->reEncryptDek(
                $firstSecret->getEncryptedDek(),
                $firstSecret->getDekNonce(),
                $firstSecret->getIdentifier(),
                $oldKey,
                $newKey,
                $firstSecret->getEncryptionVersion(),
                $firstSecret->getEncryptionAlgorithm(),
            );
            $io->text('<info>Old master key verified successfully.</info>');

            return true;
        } catch (EncryptionException $e) {
            $io->error([
                'Failed to decrypt with old master key.',
                'Error: ' . $e->getMessage(),
                'Ensure you provided the correct old key.',
            ]);

            return false;
        }
    }

    /**
     * Main rotation loop wrapped in a transaction. Per-secret failures are
     * collected; ANY failure rolls back the whole batch (atomic rotation).
     *
     * The audit chain is re-keyed under the new master key inside the SAME
     * transaction (see {@see self::rekeyAuditChain()}), so chain and secrets
     * commit or roll back together.
     *
     * @param list<string> $identifiers
     */
    private function rotateAllSecrets(
        SymfonyStyle $io,
        array $identifiers,
        string $oldKey,
        string $newKey,
        int $totalSecrets,
        int $expectedForeign,
    ): int {
        $connection = $this->connectionPool->getConnectionForTable('tx_nrvault_secret');

        // Cross-table atomicity precondition: the chain re-key must share the
        // secrets transaction, which requires both tables on ONE connection.
        if ($this->connectionPool->getConnectionForTable('tx_nrvault_audit_log') !== $connection) {
            $io->error(
                'tx_nrvault_secret and tx_nrvault_audit_log are mapped to different database '
                . 'connections; atomic master-key rotation (secrets + audit chain) is not possible.',
            );
            // "Leave a trail" contract: even a refused rotation attempt must be
            // visible in the audit chain. The audit log writes on its own
            // connection, so logging works precisely in this configuration.
            $this->auditLogService->log(
                self::AUDIT_PSEUDO_IDENTIFIER,
                AuditAction::MasterKeyRotateEnd->value,
                false,
                'Rotation refused: secret and audit tables on different connections; nothing changed',
            );

            return Command::FAILURE;
        }

        if (!$this->foreignTablesShareConnection($io, $connection)) {
            return Command::FAILURE;
        }

        $isSQLite = $connection->getDatabasePlatform() instanceof SQLitePlatform;

        // Audit the start of the rotation lifecycle BEFORE the transaction so
        // the attempt leaves a trail even if everything below rolls back.
        $this->auditLogService->log(
            self::AUDIT_PSEUDO_IDENTIFIER,
            AuditAction::MasterKeyRotateStart->value,
            true,
            null,
            \sprintf('Rotating master key for %d secret(s)', $totalSecrets),
        );

        // The chain must verify under the CURRENT key before it is re-sealed
        // under the new one: re-keying a tampered chain would launder the
        // tampering into a freshly valid chain and destroy the evidence.
        // Verification does DB I/O — an unexpected failure (DBAL error, …)
        // must still leave a rotate_end trail before the command aborts.
        try {
            $verification = $this->auditLogService->verifyHashChain();
        } catch (Throwable $exception) {
            $io->error('Audit hash chain verification errored: ' . $exception->getMessage());
            $this->auditLogService->log(
                self::AUDIT_PSEUDO_IDENTIFIER,
                AuditAction::MasterKeyRotateEnd->value,
                false,
                'Audit chain verification errored before rotation; nothing changed',
            );

            return Command::FAILURE;
        }

        if (!$verification->isValid()) {
            $io->error([
                'Audit hash chain verification FAILED — re-keying refused.',
                'Investigate the chain (vault:audit --verify) before rotating the master key.',
            ]);
            $this->auditLogService->log(
                self::AUDIT_PSEUDO_IDENTIFIER,
                AuditAction::MasterKeyRotateEnd->value,
                false,
                'Audit chain verification failed before rotation; nothing changed',
            );

            return Command::FAILURE;
        }

        $connection->beginTransaction();

        $io->progressStart($totalSecrets);
        $failedSecrets = [];
        $successCount = 0;
        $rekeyedRows = 0;
        $foreignCount = 0;

        try {
            foreach ($identifiers as $identifier) {
                if ($this->rotateOne($identifier, $oldKey, $newKey, $failedSecrets)) {
                    ++$successCount;
                }

                $io->progressAdvance();
            }

            $io->progressFinish();

            if ($failedSecrets !== []) {
                $connection->rollBack();
                $this->reportFailures($io, $failedSecrets);
                $this->auditLogService->log(
                    self::AUDIT_PSEUDO_IDENTIFIER,
                    AuditAction::MasterKeyRotateEnd->value,
                    false,
                    \sprintf('Rotation failed for %d secret(s); transaction rolled back', \count($failedSecrets)),
                );

                return Command::FAILURE;
            }

            // Consumer-owned envelopes are re-wrapped BEFORE the audit-chain
            // re-key: the re-key takes the audit advisory lock and holds it for
            // the remainder of the transaction, so anything that still needs to
            // write must have written by then.
            $foreignCount = $this->rewrapForeignEnvelopes($io, $oldKey, $newKey);

            // Reconcile against the inventory. A rotator that re-wraps FEWER
            // envelopes than it reported — a batching off-by-one, a WHERE clause
            // that misses rows — would otherwise commit, report success, and send
            // the operator to step 2 below: "securely archive or destroy the old
            // master key". Destroying it then makes the missed envelopes
            // permanently unreadable, which is the silent loss this seam exists to
            // prevent. A benign shrink (rows deleted between the inventory and the
            // transaction) is indistinguishable from a buggy rotator here, so this
            // fails closed and asks for a re-run rather than guessing.
            if ($foreignCount < $expectedForeign) {
                $connection->rollBack();
                $io->error([
                    \sprintf(
                        'Consumer-owned envelopes: inventoried %d, re-wrapped only %d.',
                        $expectedForeign,
                        $foreignCount,
                    ),
                    'Rotation rolled back; nothing was changed.',
                    "Re-run the command. If the shortfall repeats, the consumer's rotator is missing rows"
                    . ' and committing would leave them unreadable once the old key is gone.',
                ]);
                $this->auditLogService->log(
                    self::AUDIT_PSEUDO_IDENTIFIER,
                    AuditAction::MasterKeyRotateEnd->value,
                    false,
                    'Consumer envelope count mismatch; transaction rolled back',
                );

                return Command::FAILURE;
            }

            $rekeyedRows = $this->rekeyAuditChain($connection, $isSQLite, $newKey, $successCount);

            $connection->commit();
        } catch (Throwable $e) {
            $connection->rollBack();
            $io->error('Unexpected error during rotation: ' . $e->getMessage());
            // Do not propagate $e->getMessage() into the audit log to avoid
            // leaking libsodium/internal detail (CLAUDE.md security rule 1).
            $this->auditLogService->log(
                self::AUDIT_PSEUDO_IDENTIFIER,
                AuditAction::MasterKeyRotateEnd->value,
                false,
                'Unexpected error during rotation; transaction rolled back',
            );

            return Command::FAILURE;
        }

        $io->text(\sprintf('Consumer-owned envelopes re-wrapped: %d.', $foreignCount));
        $io->success(\sprintf(
            'Successfully rotated master key for %d secret(s).',
            $successCount,
        ));
        $io->text(\sprintf(
            'Audit chain re-keyed under the new master key (%d row(s) rewritten).',
            $rekeyedRows,
        ));

        $io->note([
            'Next steps:',
            '1. Update your configuration to use the new master key NOW — until then,',
            '   secrets cannot be decrypted and audit-chain verification uses the old key.',
            '2. Securely archive or destroy the old master key',
            '3. Test secret retrieval and run vault:audit to verify chain integrity',
            '4. If any audit entries were written between this rotation and the',
            '   configuration switch, re-seal them with vault:audit-migrate-hmac',
        ]);

        // Dispatched last, and deliberately after the instructions above: the
        // rotation has already committed, so a listener that throws must not be
        // able to suppress "update your configuration to use the new master key
        // NOW". The exception still propagates — a broken listener should be
        // visible — but by then the operator has read what they have to do.
        $this->eventDispatcher->dispatch(new MasterKeyRotatedEvent(
            secretsReEncrypted: $successCount,
            actorUid: $this->accessControlService->getCurrentActorUid(),
            rotatedAt: new DateTimeImmutable(),
            foreignEnvelopesReEncrypted: $foreignCount,
        ));

        return Command::SUCCESS;
    }

    /**
     * Re-key the tamper-evident audit chain under the new master key, inside
     * the caller's open transaction. Returns the number of rewritten rows.
     *
     * Ordering is deliberate:
     *  1. take the audit advisory lock for the remainder of the transaction
     *     so no concurrent writer can chain onto a tip hash this method is
     *     about to rewrite;
     *  2. append the 'audit_chain_rekey' and successful
     *     'master_key_rotate_end' events — at this point they are sealed
     *     with the OLD (provider-derived) HMAC key;
     *  3. rewrite every row's entry/previous hash under the NEW key —
     *     including the two events just appended — so the committed chain
     *     verifies under the new master key from first to last row, with no
     *     old-keyed tail entry behind the re-key point.
     *
     * Writing the success events before the final step is sound because the
     * whole sequence is atomic: a failure in any step propagates to the
     * caller, which rolls back secrets, events, and chain rewrite together.
     *
     * @throws Throwable Propagates lock/re-key failures for the caller's rollback
     */
    private function rekeyAuditChain(
        Connection $connection,
        bool $isSQLite,
        #[SensitiveParameter]
        string $newKey,
        int $successCount,
    ): int {
        $this->acquireAuditLock($connection, $isSQLite);

        try {
            $this->auditLogService->log(
                self::AUDIT_PSEUDO_IDENTIFIER,
                AuditAction::AuditChainRekey->value,
                true,
                null,
                'Re-keyed audit chain HMACs under the new master key',
            );
            $this->auditLogService->log(
                self::AUDIT_PSEUDO_IDENTIFIER,
                AuditAction::MasterKeyRotateEnd->value,
                true,
                null,
                \sprintf('Successfully rotated master key for %d secret(s)', $successCount),
            );

            // The two log() calls above anchored the tip under the OLD key;
            // rekeyChain() rewrites those entry hashes and re-signs the tip
            // anchor under the new key as part of the same operation.
            $rewritten = $this->auditChainRekeyService->rekeyChain($connection, $newKey);

            $this->commitAuditLock($connection, $isSQLite);

            return $rewritten;
        } catch (Throwable $e) {
            $this->rollbackAuditLock($connection, $isSQLite);

            throw $e;
        } finally {
            $this->releaseAuditLock($connection, $isSQLite);
        }
    }

    /**
     * Re-encrypt a single secret's DEK and persist. Returns false (with the
     * failure recorded by reference) on missing-secret or EncryptionException;
     * the caller advances the progress bar and decides whether to roll back.
     *
     * @param list<array{identifier: string, error: string}> $failedSecrets
     */
    private function rotateOne(
        string $identifier,
        string $oldKey,
        string $newKey,
        array &$failedSecrets,
    ): bool {
        $secret = $this->secretRepository->findByIdentifier($identifier);
        if (!$secret instanceof Secret) {
            $failedSecrets[] = ['identifier' => $identifier, 'error' => 'Not found'];

            return false;
        }

        try {
            $reEncrypted = $this->encryptionService->reEncryptDek(
                $secret->getEncryptedDek(),
                $secret->getDekNonce(),
                $secret->getIdentifier(),
                $oldKey,
                $newKey,
                $secret->getEncryptionVersion(),
                $secret->getEncryptionAlgorithm(),
            );

            $this->secretRepository->save(
                $secret->withReEncryptedDek($reEncrypted->encryptedDek, $reEncrypted->nonce),
            );

            return true;
        } catch (EncryptionException $e) {
            $failedSecrets[] = ['identifier' => $identifier, 'error' => $e->getMessage()];

            return false;
        }
    }

    /**
     * Render the failure table after a rolled-back rotation.
     *
     * @param list<array{identifier: string, error: string}> $failedSecrets
     */
    private function reportFailures(SymfonyStyle $io, array $failedSecrets): void
    {
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

        // Resolve the key, mirroring FileMasterKeyProvider::loadRawKey() ordering.
        // Order matters: never trim() a value that is already binary key material,
        // or a valid 32-byte raw key whose first/last byte happens to be a trim
        // char (\t \n \r space \0 \x0B) is silently corrupted to 30/31 bytes.
        $trimmed = trim($key);

        // 1) Trimmed value as raw binary key.
        if (\strlen($trimmed) === self::KEY_LENGTH) {
            return $trimmed;
        }

        // 2) base64 decode of the trimmed text.
        $decoded = base64_decode($trimmed, true);
        if ($decoded !== false && \strlen($decoded) === self::KEY_LENGTH) {
            return $decoded;
        }

        // 3) Raw file contents as binary (no trimming of binary data).
        if (\strlen($key) === self::KEY_LENGTH) {
            return $key;
        }

        throw MasterKeyException::invalidLength(self::KEY_LENGTH, \strlen($trimmed));
    }
}
