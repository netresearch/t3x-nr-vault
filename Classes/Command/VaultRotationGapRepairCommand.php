<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditChainLockTrait;
use Netresearch\NrVault\Audit\AuditChainRekeyServiceInterface;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\AuditSinkPublicationBuffer;
use Netresearch\NrVault\Audit\RotationGapScan;
use Netresearch\NrVault\Audit\RotationGapScannerInterface;
use Netresearch\NrVault\Crypto\EncryptionServiceInterface;
use Netresearch\NrVault\Crypto\MasterKeyFile;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\MasterKeyException;
use Netresearch\NrVault\Exception\VaultException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\VaultPermission;
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

use function count;
use function date;
use function is_string;
use function sprintf;

/**
 * Repair what was written between a master-key rotation and the
 * configuration switch, using the retained previous master key.
 *
 * Until the configuration points at the new key, the provider keeps returning
 * the old one: a secret stored in that gap is wrapped under the old key, and
 * an audit row is sealed under the old key's HMAC. This command re-wraps such
 * secrets and re-seals such rows under the configured key, in one transaction
 * that also holds the audit-chain lock.
 */
#[AsCommand(
    name: 'vault:rotation-gap-repair',
    description: 'Re-wrap secrets and re-seal audit rows left under the previous master key after a rotation',
)]
final class VaultRotationGapRepairCommand extends Command
{
    use AuditChainLockTrait;

    private const AUDIT_PSEUDO_IDENTIFIER = '__master_key__';

    private const AUDIT_LOG_TABLE = 'tx_nrvault_audit_log';

    private const SECRET_TABLE = 'tx_nrvault_secret';

    public function __construct(
        private readonly AccessControlServiceInterface $accessControlService,
        private readonly SecretRepositoryInterface $secretRepository,
        private readonly EncryptionServiceInterface $encryptionService,
        private readonly MasterKeyProviderInterface $masterKeyProvider,
        private readonly ConnectionPool $connectionPool,
        private readonly AuditLogServiceInterface $auditLogService,
        private readonly AuditChainRekeyServiceInterface $auditChainRekeyService,
        private readonly RotationGapScannerInterface $rotationGapScanner,
        private readonly ?AuditSinkPublicationBuffer $publicationBuffer = null,
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
                'Path to the file containing the previous master key (required)',
            )
            ->addOption(
                'dry-run',
                null,
                InputOption::VALUE_NONE,
                'Report what would be repaired without changing anything',
            )
            ->addOption(
                'confirm',
                null,
                InputOption::VALUE_NONE,
                'Confirm the repair (required for actual execution)',
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        // Re-wrapping DEKs and re-sealing the audit chain is part of a master-key
        // rotation, so it needs the same operation permission.
        if (!$this->accessControlService->isGranted(VaultPermission::MasterKeyRotate)) {
            $io->error(sprintf(
                'Access denied: the "%s" permission is required to repair a master-key rotation.',
                VaultPermission::MasterKeyRotate->value,
            ));

            return Command::FAILURE;
        }

        $keys = $this->resolveKeys($io, $input->getOption('old-key'));
        if ($keys === null) {
            return Command::FAILURE;
        }

        [$previousKey, $currentKey] = $keys;
        // The array shares the key strings; sodium_memzero() below only wipes
        // a buffer nothing else references.
        unset($keys);

        try {
            return $this->runRepair(
                $io,
                $previousKey,
                $currentKey,
                (bool) $input->getOption('dry-run'),
                (bool) $input->getOption('confirm'),
            );
        } finally {
            sodium_memzero($previousKey);
            sodium_memzero($currentKey);
        }
    }

    /**
     * Read the previous key from `--old-key` and the current one from the
     * provider. Null, after reporting why, when either is missing or both
     * are the same key.
     *
     * @return array{string, string}|null previous key, current key
     */
    private function resolveKeys(SymfonyStyle $io, mixed $oldKeyPath): ?array
    {
        if (!is_string($oldKeyPath) || $oldKeyPath === '') {
            $io->error('--old-key is required: the file with the master key used before the rotation.');

            return null;
        }

        $keys = null;

        try {
            $previousKey = MasterKeyFile::read($oldKeyPath);
            $currentKey  = $this->masterKeyProvider->getMasterKey();

            if (hash_equals($previousKey, $currentKey)) {
                sodium_memzero($previousKey);
                sodium_memzero($currentKey);
                $io->error([
                    '--old-key is the master key the configuration uses now.',
                    'Run this command after the configuration switch, with the key used before the rotation.',
                ]);
            } else {
                $keys = [$previousKey, $currentKey];
            }
        } catch (MasterKeyException $e) {
            $io->error($e->getMessage());
        }

        return $keys;
    }

    private function runRepair(
        SymfonyStyle $io,
        #[SensitiveParameter]
        string $previousKey,
        #[SensitiveParameter]
        string $currentKey,
        bool $dryRun,
        bool $confirmed,
    ): int {
        $io->title('Master-key rotation gap repair');

        [$previousKeySecrets, $unreadableSecrets] = $this->classifySecrets($previousKey, $currentKey);
        $scan                                     = $this->rotationGapScanner->scan($previousKey);

        $this->report($io, $previousKeySecrets, $unreadableSecrets, $scan);

        $exit = $this->exitBeforeRepair($io, $scan, $previousKeySecrets, $unreadableSecrets, $dryRun, $confirmed);
        if ($exit !== null) {
            return $exit;
        }

        $counts = $this->repair($io, $previousKey, $currentKey);

        return $counts === null ? Command::FAILURE : $this->finish($io, $unreadableSecrets, sprintf(
            'Re-wrapped %d secret(s) and re-sealed %d audit row(s) under the configured master key.',
            ...$counts,
        ));
    }

    /**
     * The exit code when the run ends before the repair: a refused chain,
     * nothing to repair, a dry run, or a missing --confirm. Null to go on.
     *
     * @param list<string> $previousKeySecrets
     * @param list<string> $unreadableSecrets
     */
    private function exitBeforeRepair(
        SymfonyStyle $io,
        RotationGapScan $scan,
        array $previousKeySecrets,
        array $unreadableSecrets,
        bool $dryRun,
        bool $confirmed,
    ): ?int {
        $exit = null;

        if (!$scan->isRepairable()) {
            $io->error(array_merge(
                ['The audit chain has findings a re-seal would hide. Nothing was changed.'],
                $scan->problems,
                ['Keep both master keys and investigate with vault:audit-verify.'],
            ));
            // A dry run changes nothing, not even the audit log.
            if (!$dryRun) {
                $this->auditLogService->log(
                    self::AUDIT_PSEUDO_IDENTIFIER,
                    AuditAction::AuditChainRekey->value,
                    false,
                    'Rotation gap repair refused: the audit chain has findings besides rows under the previous key',
                );
            }

            $exit = Command::FAILURE;
        } elseif ($previousKeySecrets === [] && !$scan->hasPreviousKeyRows()) {
            $exit = $this->finish($io, $unreadableSecrets, 'Nothing is left under the previous master key.');
        } elseif ($dryRun) {
            $exit = $this->finish($io, $unreadableSecrets, sprintf(
                '[DRY RUN] Would re-wrap %d secret(s) and re-seal %d audit row(s). No changes made.',
                count($previousKeySecrets),
                count($scan->previousKeyRows),
            ));
        } elseif (!$confirmed) {
            $io->warning([
                'This re-wraps the secrets and re-seals the audit rows listed above under the configured master key.',
                'Use --confirm to proceed or --dry-run to only report.',
            ]);
            $exit = Command::FAILURE;
        }

        return $exit;
    }

    /**
     * Sort every secret, disabled ones included, by the key its DEK opens
     * under. Secrets under the configured key are left out, and so are
     * records without a local envelope (a custom adapter keeps the value
     * elsewhere), which no master key wraps.
     *
     * @return array{list<string>, list<string>} identifiers under the previous key, identifiers under neither key
     */
    private function classifySecrets(
        #[SensitiveParameter]
        string $previousKey,
        #[SensitiveParameter]
        string $currentKey,
    ): array {
        $previousKeySecrets = [];
        $unreadableSecrets  = [];

        foreach ($this->secretRepository->findIdentifiers(new SecretFilters(includeDisabled: true)) as $identifier) {
            $secret = $this->secretRepository->findByIdentifierIncludingDisabled($identifier);
            if (!$secret instanceof Secret
                || $secret->getEncryptedDek() === ''
                || $this->opensUnder($secret, $currentKey, $currentKey)
            ) {
                continue;
            }

            if ($this->opensUnder($secret, $previousKey, $currentKey)) {
                $previousKeySecrets[] = $identifier;
            } else {
                $unreadableSecrets[] = $identifier;
            }
        }

        return [$previousKeySecrets, $unreadableSecrets];
    }

    private function opensUnder(
        Secret $secret,
        #[SensitiveParameter]
        string $key,
        #[SensitiveParameter]
        string $currentKey,
    ): bool {
        try {
            $this->rewrap($secret, $key, $currentKey);

            return true;
        } catch (EncryptionException) {
            return false;
        }
    }

    /**
     * @throws EncryptionException When `$fromKey` does not open the DEK
     */
    private function rewrap(
        Secret $secret,
        #[SensitiveParameter]
        string $fromKey,
        #[SensitiveParameter]
        string $toKey,
    ): Secret {
        $reEncrypted = $this->encryptionService->reEncryptDek(
            $secret->getEncryptedDek(),
            $secret->getDekNonce(),
            $secret->getIdentifier(),
            $fromKey,
            $toKey,
            $secret->getEncryptionVersion(),
            $secret->getEncryptionAlgorithm(),
        );

        return $secret->withReEncryptedDek($reEncrypted->encryptedDek, $reEncrypted->nonce);
    }

    /**
     * @param list<string> $previousKeySecrets
     * @param list<string> $unreadableSecrets
     */
    private function report(SymfonyStyle $io, array $previousKeySecrets, array $unreadableSecrets, RotationGapScan $scan): void
    {
        $io->section(sprintf('Secrets under the previous master key: %d', count($previousKeySecrets)));
        if ($previousKeySecrets !== []) {
            $io->listing($previousKeySecrets);
        }

        if ($unreadableSecrets !== []) {
            $io->section(sprintf('Secrets that neither key opens: %d', count($unreadableSecrets)));
            $io->listing($unreadableSecrets);
        }

        $io->section(sprintf('Audit rows sealed under the previous master key: %d', count($scan->previousKeyRows)));
        if ($scan->previousKeyRows !== []) {
            $io->table(
                ['UID', 'Created', 'Action', 'Secret'],
                array_map(
                    static fn (array $row): array => [
                        (string) $row['uid'],
                        date('Y-m-d H:i:s', $row['crdate']),
                        $row['action'],
                        $row['secretIdentifier'],
                    ],
                    $scan->previousKeyRows,
                ),
            );
        }
    }

    /**
     * Re-wrap the secrets and re-seal the chain in one transaction under the
     * audit-chain lock. Secrets and chain are checked again inside the lock,
     * and the repaired chain must pass the regular verification before the
     * commit. Returns the numbers of re-wrapped secrets and re-sealed rows, or
     * null when nothing was committed.
     *
     * @return array{int, int}|null
     */
    private function repair(
        SymfonyStyle $io,
        #[SensitiveParameter]
        string $previousKey,
        #[SensitiveParameter]
        string $currentKey,
    ): ?array {
        $connection = $this->openRepairTransaction($io);
        if (!$connection instanceof Connection) {
            return null;
        }

        $isSQLite = $connection->getDatabasePlatform() instanceof SQLitePlatform;
        $lockHeld = true;

        try {
            $counts = $this->applyAndCommit($io, $connection, $isSQLite, $lockHeld, $previousKey, $currentKey);
        } finally {
            if ($lockHeld) {
                try {
                    $this->releaseAuditLock($connection, $isSQLite);
                } catch (Throwable) {
                    // Closing the connection ends the session and its lock.
                    $connection->close();
                }
            }
        }

        if ($counts !== null) {
            $this->publicationBuffer?->flush();
        }

        return $counts;
    }

    /**
     * Take the audit-chain lock and open the repair transaction. Null, after
     * reporting why, when that is not possible.
     */
    private function openRepairTransaction(SymfonyStyle $io): ?Connection
    {
        $connection = $this->connectionPool->getConnectionForTable(self::SECRET_TABLE);
        if ($this->connectionPool->getConnectionForTable(self::AUDIT_LOG_TABLE) !== $connection) {
            $io->error(
                'tx_nrvault_secret and tx_nrvault_audit_log are mapped to different database '
                . 'connections; the repair cannot change secrets and audit chain atomically.',
            );

            return null;
        }

        // Entries written inside the transaction reach the external sinks only
        // after the commit, with the hashes the re-seal gave them.
        $this->publicationBuffer?->collect();

        try {
            // A Doctrine-managed transaction on SQLite as well: the audit
            // writes inside it nest as savepoints, where a raw BEGIN EXCLUSIVE
            // cannot nest.
            $this->acquireAuditLock($connection, $connection->getDatabasePlatform() instanceof SQLitePlatform, true);
        } catch (Throwable $e) {
            $this->publicationBuffer?->discard();
            $io->error(['The audit-chain lock was not granted; nothing was changed.', $e->getMessage()]);

            return null;
        }

        return $connection;
    }

    /**
     * @return array{int, int}|null
     */
    private function applyAndCommit(
        SymfonyStyle $io,
        Connection $connection,
        bool $isSQLite,
        bool &$lockHeld,
        #[SensitiveParameter]
        string $previousKey,
        #[SensitiveParameter]
        string $currentKey,
    ): ?array {
        try {
            $counts = $this->applyRepair($connection, $previousKey, $currentKey);
        } catch (Throwable $e) {
            return $this->failRepair(
                $connection,
                $io,
                $lockHeld,
                ['Repair rolled back; nothing was changed.', $e->getMessage()],
                'Rotation gap repair rolled back; nothing changed',
            );
        }

        try {
            $this->commitAuditLock($connection, $isSQLite);
        } catch (Throwable $e) {
            // The server may have committed before the connection failed.
            $counts = $this->failRepair(
                $connection,
                $io,
                $lockHeld,
                [
                    'The repair commit failed: ' . $e->getMessage(),
                    'The database may or may not hold the repair. Keep both master keys and run '
                    . 'this command again with --dry-run to see what is left under the previous key.',
                ],
                'Rotation gap repair commit failed; outcome unknown',
            );
        }

        return $counts;
    }

    /**
     * End a failed repair: roll back what is left of its transaction, report
     * the error and record a failed `audit_chain_rekey` row. After a failed
     * commit DBAL reports no active transaction; closing the connection then
     * discards whatever the database still holds open, and ends the session
     * lock with it.
     *
     * @param list<string> $error
     */
    private function failRepair(
        Connection $connection,
        SymfonyStyle $io,
        bool &$lockHeld,
        array $error,
        string $auditReason,
    ): null {
        // First, so the failure row below is published at once.
        $this->publicationBuffer?->discard();

        try {
            if ($connection->isTransactionActive()) {
                $connection->rollBack();
            } else {
                $connection->close();
                $lockHeld = false;
            }
        } catch (Throwable) {
            $connection->close();
            $lockHeld = false;
        }

        $io->error($error);

        try {
            $this->auditLogService->log(
                self::AUDIT_PSEUDO_IDENTIFIER,
                AuditAction::AuditChainRekey->value,
                false,
                $auditReason,
            );
        } catch (Throwable $e) {
            // After a failed commit the dead session can still hold the audit
            // lock until the server notices; the failure is reported above.
            $io->warning('The failed repair could not be recorded in the audit log: ' . $e->getMessage());
        }

        return null;
    }

    /**
     * @return array{int, int} re-wrapped secrets, re-sealed audit rows
     *
     * @throws Throwable Any failure, for the caller's rollback
     */
    private function applyRepair(
        Connection $connection,
        #[SensitiveParameter]
        string $previousKey,
        #[SensitiveParameter]
        string $currentKey,
    ): array {
        // Both may have changed since the report: a process that still holds
        // the previous key can have written in between. Check again under the
        // lock and repair what is there now.
        $scan = $this->rotationGapScanner->scan($previousKey);
        if (!$scan->isRepairable()) {
            throw new VaultException('The audit chain changed since the report: ' . implode(' ', $scan->problems), 6915487669);
        }

        [$identifiers] = $this->classifySecrets($previousKey, $currentKey);

        foreach ($identifiers as $identifier) {
            $secret = $this->secretRepository->findByIdentifierIncludingDisabled($identifier);
            if (!$secret instanceof Secret) {
                throw new VaultException(sprintf('Secret "%s" disappeared while it was repaired.', $identifier), 4544303749);
            }

            $this->secretRepository->save($this->rewrap($secret, $previousKey, $currentKey));
            $this->auditLogService->log(
                $identifier,
                AuditAction::MasterKeyRewrap->value,
                true,
                null,
                'DEK re-wrapped from the previous master key after a rotation',
            );
        }

        // Written on every committed repair, also one that only re-wrapped
        // secrets: as the newest successful audit_chain_rekey row it closes the
        // window, so the next scan accepts no further row under the previous key.
        $this->auditLogService->log(
            self::AUDIT_PSEUDO_IDENTIFIER,
            AuditAction::AuditChainRekey->value,
            true,
            null,
            sprintf(
                'Re-sealed %d audit row(s) and re-wrapped %d secret(s) left under the previous master key after a rotation',
                count($scan->previousKeyRows),
                count($identifiers),
            ),
        );

        if ($scan->hasPreviousKeyRows()) {
            $this->auditChainRekeyService->rekeyChain($connection, $currentKey);
        }

        if (!$this->auditLogService->verifyHashChain()->isValid()) {
            throw new VaultException('The repaired audit chain does not verify.', 6051565967);
        }

        return [count($identifiers), count($scan->previousKeyRows)];
    }

    /**
     * @param list<string> $unreadableSecrets
     */
    private function finish(SymfonyStyle $io, array $unreadableSecrets, string $message): int
    {
        if ($unreadableSecrets === []) {
            $io->success($message);

            return Command::SUCCESS;
        }

        $io->warning($message);
        $io->error(sprintf(
            '%d secret(s) open under neither the configured nor the previous master key. '
            . 'They were not changed; restore them from a backup made under a key you still hold.',
            count($unreadableSecrets),
        ));

        return Command::FAILURE;
    }
}
