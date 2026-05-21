<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Command;

use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Audit\AuditChainLockTrait;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
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
    use AuditChainLockTrait;

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

        // Count outdated entries — anything below the target epoch. Covers
        // 0 → 1, 0 → 2, and 1 → 2 migrations (the v1 hash payload omits
        // forensic fields, so a 1 → 2 rehash is required for tamper
        // detection of success/error_message/reason/ip/UA/context).
        $queryBuilder = $connection->createQueryBuilder();
        $countResult = $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->lt(
                    'hmac_key_epoch',
                    $queryBuilder->createNamedParameter($targetEpoch, Connection::PARAM_INT),
                ),
            )
            ->executeQuery()
            ->fetchOne();

        $outdatedCount = is_numeric($countResult) ? (int) $countResult : 0;

        if ($outdatedCount === 0) {
            $io->success(\sprintf(
                'All entries already at epoch %d or higher. Nothing to migrate.',
                $targetEpoch,
            ));

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
            'Found %d entries below epoch %d (re-hashing all %d entries to maintain chain integrity)',
            $outdatedCount,
            $targetEpoch,
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
        $isSQLite = $connection->getDatabasePlatform() instanceof SQLitePlatform;
        $this->acquireAuditLock($connection, $isSQLite);

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
                $entry = AuditLogService::extractHashRow($row);
                $uid = $entry['uid'];
                $epoch = $entry['epoch'];

                // Re-hash ALL entries to maintain chain integrity. Dispatch by
                // target epoch: v1 covers identity fields only, v2 adds the
                // forensic fields (success/error_message/reason/ip/UA/context).
                $newHash = $targetEpoch >= 2
                    ? AuditLogService::calculateHashV2(
                        AuditLogService::extractV2HashRow($row),
                        $previousHash,
                        $hmacKey,
                    )
                    : AuditLogService::calculateHash(
                        $uid,
                        $entry['secretId'],
                        $entry['action'],
                        $entry['actorUid'],
                        $entry['crdate'],
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

                if ($epoch !== $targetEpoch) {
                    ++$migratedCount;
                }

                $progressBar->advance();
            }

            $this->commitAuditLock($connection, $isSQLite);
        } catch (Throwable $e) {
            $this->rollbackAuditLock($connection, $isSQLite);

            throw $e;
        } finally {
            $this->releaseAuditLock($connection, $isSQLite);
        }

        $progressBar->finish();
        $io->newLine(2);

        if ($dryRun) {
            $io->success(\sprintf('DRY RUN: Would migrate %d entries to epoch %d', $migratedCount, $targetEpoch));
        } else {
            $io->success(\sprintf('Migrated %d entries to epoch %d', $migratedCount, $targetEpoch));
        }

        return Command::SUCCESS;
    }
}
