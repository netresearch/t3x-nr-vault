<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Netresearch\NrVault\Exception\AuditMigrationException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * CLI command to migrate audit log entries from legacy SHA-256 to HMAC-SHA256.
 */
#[AsCommand(
    name: 'vault:audit-migrate-hmac',
    description: 'Migrate audit log hash chain from SHA-256 to HMAC-SHA256',
)]
final class VaultAuditMigrateCommand extends Command
{
    private const TABLE_NAME = 'tx_nrvault_audit_log';

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly MasterKeyProviderInterface $masterKeyProvider,
        private readonly ExtensionConfigurationInterface $extensionConfiguration,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption(
            'dry-run',
            null,
            InputOption::VALUE_NONE,
            'Show what would be changed without modifying data',
        );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $dryRun = (bool) $input->getOption('dry-run');

        $targetEpoch = $this->extensionConfiguration->getAuditHmacEpoch();
        if ($targetEpoch === 0) {
            $io->error('Cannot migrate to epoch 0 (legacy mode). Set auditHmacEpoch >= 1 in extension configuration.');

            return Command::FAILURE;
        }

        $io->title('Audit Log HMAC Migration');

        if ($dryRun) {
            $io->note('DRY RUN - no changes will be made');
        }

        $connection = $this->connectionPool->getConnectionForTable(self::TABLE_NAME);

        // Count epoch-0 entries (for progress reporting)
        $queryBuilder = $connection->createQueryBuilder();
        $countResult = $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq(
                    'hmac_key_epoch',
                    $queryBuilder->createNamedParameter(0, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        $epoch0Count = is_numeric($countResult) ? (int) $countResult : 0;

        if ($epoch0Count === 0) {
            $io->success('No entries with epoch 0 found. Nothing to migrate.');

            return Command::SUCCESS;
        }

        // Count total entries (we must re-hash ALL to maintain chain integrity)
        $totalQueryBuilder = $connection->createQueryBuilder();
        $totalResult = $totalQueryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->executeQuery()
            ->fetchOne();

        $totalEntries = is_numeric($totalResult) ? (int) $totalResult : 0;

        $io->writeln(\sprintf(
            'Found %d entries with epoch 0 (re-hashing all %d entries to maintain chain integrity)',
            $epoch0Count,
            $totalEntries,
        ));

        // Derive HMAC key using the shared method
        $hmacKey = AuditLogService::deriveHmacKey($this->masterKeyProvider);

        try {
            return $this->migrateEntries($io, $output, $connection, $hmacKey, $targetEpoch, $totalEntries, $dryRun);
        } finally {
            sodium_memzero($hmacKey);
        }
    }

    private function migrateEntries(
        SymfonyStyle $io,
        OutputInterface $output,
        Connection $connection,
        string $hmacKey,
        int $targetEpoch,
        int $totalEntries,
        bool $dryRun,
    ): int {
        // Acquire an advisory lock to prevent concurrent writes during migration.
        // GET_LOCK returns 1 on success, 0 on timeout, NULL on error — check the
        // return so a contended lock aborts rather than silently running unprotected.
        $isSQLite = $connection->getDatabasePlatform() instanceof SQLitePlatform;
        $lockAcquired = false;

        if ($isSQLite) {
            $connection->executeStatement('BEGIN EXCLUSIVE');
            $lockAcquired = true;
        } else {
            $lockResult = $connection->executeQuery('SELECT GET_LOCK("nr_vault_audit", 5)')->fetchOne();
            if ((int) $lockResult !== 1) {
                throw AuditMigrationException::lockAcquisitionFailed(
                    $lockResult === null ? 'NULL (DB error)' : (string) $lockResult,
                );
            }
            $lockAcquired = true;
            $connection->beginTransaction();
        }

        try {
            // Stream ALL entries in UID order using fetchAssociative() to avoid loading entire table
            $queryBuilder = $connection->createQueryBuilder();
            $result = $queryBuilder
                ->select('*')
                ->from(self::TABLE_NAME)
                ->orderBy('uid', 'ASC')
                ->executeQuery();

            $progressBar = new ProgressBar($output, $totalEntries);
            $progressBar->start();

            $previousHash = '';
            $migratedCount = 0;

            while (($row = $result->fetchAssociative()) !== false) {
                $rowUid = $row['uid'] ?? 0;
                $uid = is_numeric($rowUid) ? (int) $rowUid : 0;
                $rowSecretId = $row['secret_identifier'] ?? '';
                $secretId = \is_string($rowSecretId) ? $rowSecretId : '';
                $rowAction = $row['action'] ?? '';
                $actionStr = \is_string($rowAction) ? $rowAction : '';
                $rowActorUid = $row['actor_uid'] ?? 0;
                $actorUid = is_numeric($rowActorUid) ? (int) $rowActorUid : 0;
                $rowCrdate = $row['crdate'] ?? 0;
                $crdate = is_numeric($rowCrdate) ? (int) $rowCrdate : 0;
                $rowEpoch = $row['hmac_key_epoch'] ?? 0;
                $epoch = is_numeric($rowEpoch) ? (int) $rowEpoch : 0;

                // Re-hash ALL entries (including already-epoch-1 entries) to maintain chain integrity.
                // After re-hashing, all entries use HMAC with the current master key.
                $newHash = AuditLogService::calculateHash(
                    $uid,
                    $secretId,
                    $actionStr,
                    $actorUid,
                    $crdate,
                    $previousHash,
                    $hmacKey,
                );

                if (!$dryRun) {
                    $connection->update(
                        self::TABLE_NAME,
                        [
                            'entry_hash' => $newHash,
                            'previous_hash' => $previousHash,
                            'hmac_key_epoch' => $targetEpoch,
                        ],
                        ['uid' => $uid],
                    );
                }

                $previousHash = $newHash;

                if ($epoch === 0) {
                    ++$migratedCount;
                }

                $progressBar->advance();
            }

            if ($isSQLite) {
                $connection->executeStatement('COMMIT');
            } else {
                $connection->commit();
            }
        } catch (Throwable $e) {
            if ($isSQLite) {
                $connection->executeStatement('ROLLBACK');
            } else {
                $connection->rollBack();
            }

            throw $e;
        } finally {
            if (!$isSQLite) {
                $connection->executeStatement('SELECT RELEASE_LOCK("nr_vault_audit")');
            }
        }

        $progressBar->finish();
        $io->newLine(2);

        if ($dryRun) {
            $io->success(\sprintf('DRY RUN: Would migrate %d entries from epoch 0 to epoch %d', $migratedCount, $targetEpoch));
        } else {
            $io->success(\sprintf('Migrated %d entries from epoch 0 to epoch %d', $migratedCount, $targetEpoch));
        }

        return Command::SUCCESS;
    }
}
