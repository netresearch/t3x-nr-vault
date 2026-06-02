<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Task;

use Netresearch\NrVault\Domain\Dto\OrphanReference;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Log\LogManager;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Scheduler\Task\AbstractTask;

/**
 * Scheduler task to clean up orphaned vault secrets.
 *
 * This task runs periodically to remove vault secrets whose source
 * TCA records have been deleted. It helps maintain vault hygiene
 * and prevents accumulation of unused encrypted data.
 *
 * Configuration (via TCA fields in tx_scheduler_task):
 * - nr_vault_retention_days: Only delete orphans older than this many days (default: 7)
 * - nr_vault_table_filter: Only check secrets for a specific table (optional)
 */
final class OrphanCleanupTask extends AbstractTask
{
    /** Page size for the UID-windowed secret scan (bounds peak memory). */
    private const PAGE_SIZE = 200;

    /** Only delete orphans older than this many days. */
    protected int $retentionDays = 7;

    /** Only check secrets for this specific table (optional). */
    protected string $tableFilter = '';

    public function __construct(
        private readonly ?ConnectionPool $connectionPool = null,
        private readonly ?VaultServiceInterface $vaultService = null,
        private readonly ?LogManager $logManager = null,
        private readonly ?SecretRepositoryInterface $secretRepository = null,
    ) {
        parent::__construct();
    }

    /**
     * Get task parameters for TCA storage.
     *
     * Maps internal properties to TCA field names.
     *
     * @return array<string, mixed>
     */
    public function getTaskParameters(): array
    {
        return [
            'nr_vault_retention_days' => $this->retentionDays,
            'nr_vault_table_filter' => $this->tableFilter,
        ];
    }

    /**
     * Set task parameters from TCA fields.
     *
     * @param array<string, mixed> $parameters
     */
    public function setTaskParameters(array $parameters): void
    {
        $retentionDays = $parameters['nr_vault_retention_days'] ?? 7;
        $this->retentionDays = is_numeric($retentionDays) ? (int) $retentionDays : 7;

        $tableFilter = $parameters['nr_vault_table_filter'] ?? '';
        $this->tableFilter = \is_string($tableFilter) ? trim($tableFilter) : '';
    }

    public function execute(): bool
    {
        $vaultService = $this->getVaultService();
        $connectionPool = $this->getConnectionPool();
        $repository = $this->getSecretRepository();
        $logger = $this->getLogger();

        $logger->info('Starting vault orphan cleanup', [
            'retentionDays' => $this->retentionDays,
            'tableFilter' => $this->tableFilter ?: '(all)',
        ]);

        $retentionCutoff = $this->retentionDays > 0
            ? time() - ($this->retentionDays * 86400)
            : PHP_INT_MAX;

        // Walk the vault in UID-windowed pages so peak memory is bounded by
        // the page size, not the total vault size (PERFORMANCE-8). Identify
        // and delete orphans page-by-page; deletes still route through
        // VaultService (ACL + audit preserved).
        $afterUid = 0;
        $checked = 0;
        $orphansFound = 0;
        $success = true;

        do {
            $page = $repository->findPaginatedAfterUid($afterUid, self::PAGE_SIZE);
            if ($page === []) {
                break;
            }

            foreach ($page as $secret) {
                $uid = $secret->getUid();
                if ($uid !== null) {
                    $afterUid = max($afterUid, $uid);
                }

                $reference = $this->resolveOrphanReference($secret->getMetadata());
                if (!$reference instanceof OrphanReference) {
                    continue;
                }

                $checked++;

                // Only delete if the source record is gone AND the secret is
                // older than the retention period.
                if ($this->recordExists($connectionPool, $reference->table, $reference->uid) || $secret->getCrdate() >= $retentionCutoff) {
                    continue;
                }

                $orphansFound++;

                if (!$this->deleteOrphan($vaultService, $logger, $secret->getIdentifier())) {
                    $success = false;
                }
            }
        } while (\count($page) === self::PAGE_SIZE);

        $logger->info('Orphan check complete', [
            'secretsChecked' => $checked,
            'orphansFound' => $orphansFound,
        ]);

        return $success;
    }

    /**
     * Return additional information for the scheduler module display.
     */
    public function getAdditionalInformation(): string
    {
        $info = [];
        $info[] = \sprintf('Retention: %d days', $this->retentionDays);

        if ($this->tableFilter !== '') {
            $info[] = \sprintf('Table filter: %s', $this->tableFilter);
        }

        return implode(', ', $info);
    }

    /**
     * Resolve a deletable orphan reference from a secret's metadata, or null
     * when the secret is not a TCA-sourced candidate, has no parseable
     * reference, or is excluded by the configured table filter.
     *
     * @param array<string, mixed> $metadata Secret metadata
     */
    private function resolveOrphanReference(array $metadata): ?OrphanReference
    {
        $source = $metadata['source'] ?? '';

        // Only check TCA-sourced secrets
        if ($source !== 'tca_field' && $source !== 'migration') {
            return null;
        }

        // Extract reference from metadata (table, field, uid are stored by DataHandlerHook)
        $reference = $this->parseMetadataReference($metadata);
        if (!$reference instanceof OrphanReference) {
            return null;
        }

        // Apply table filter if specified
        if ($this->tableFilter !== '' && $reference->table !== $this->tableFilter) {
            return null;
        }

        return $reference;
    }

    /**
     * Delete a single orphan secret through the VaultService (ACL + audit
     * preserved). Returns false when deletion failed.
     */
    private function deleteOrphan(VaultServiceInterface $vaultService, LoggerInterface $logger, string $identifier): bool
    {
        try {
            $vaultService->delete($identifier, 'Scheduler orphan cleanup');
            $logger->info('Deleted orphan secret', ['identifier' => $identifier]);

            return true;
        } catch (Throwable $e) {
            $logger->error('Failed to delete orphan secret', [
                'identifier' => $identifier,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Extract orphan reference from secret metadata.
     *
     * TCA-sourced secrets store their origin in metadata (table, field, uid)
     * rather than encoding it in the identifier (which is a UUID).
     *
     * @param array<string, mixed> $metadata Secret metadata
     */
    private function parseMetadataReference(array $metadata): ?OrphanReference
    {
        $table = $metadata['table'] ?? '';
        $field = $metadata['field'] ?? $metadata['flexField'] ?? '';
        $uid = $metadata['uid'] ?? null;

        if (!\is_string($table) || $table === '') {
            return null;
        }

        if (!is_numeric($uid) || (int) $uid <= 0) {
            return null;
        }

        return new OrphanReference(
            table: $table,
            field: \is_string($field) ? $field : '',
            uid: (int) $uid,
        );
    }

    private function recordExists(ConnectionPool $connectionPool, string $table, int $uid): bool
    {
        $connection = $connectionPool->getConnectionByName(ConnectionPool::DEFAULT_CONNECTION_NAME);
        if (!$connection->createSchemaManager()->tablesExist([$table])) {
            return false;
        }

        $queryBuilder = $connectionPool->getQueryBuilderForTable($table);
        $queryBuilder->getRestrictions()->removeAll();

        $count = $queryBuilder
            ->count('*')
            ->from($table)
            ->where(
                $queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)),
            )
            ->executeQuery()
            ->fetchOne();

        return $count > 0;
    }

    private function getVaultService(): VaultServiceInterface
    {
        return $this->vaultService ?? GeneralUtility::makeInstance(VaultServiceInterface::class);
    }

    private function getSecretRepository(): SecretRepositoryInterface
    {
        return $this->secretRepository ?? GeneralUtility::makeInstance(SecretRepositoryInterface::class);
    }

    private function getConnectionPool(): ConnectionPool
    {
        return $this->connectionPool ?? GeneralUtility::makeInstance(ConnectionPool::class);
    }

    private function getLogger(): LoggerInterface
    {
        if (!$this->logManager instanceof LogManager) {
            return new NullLogger();
        }

        return $this->logManager
            ->getLogger(self::class);
    }
}
