<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Netresearch\NrVault\Exception\AuditWriteException;
use Psr\Log\LoggerInterface;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

/**
 * Owns the stock local mutation's transaction, chain lock and commit boundary.
 *
 * Custom adapters/repositories and DataHandler writes outside VaultService do
 * not participate. Caller-owned transactions are refused: DBAL has no hook
 * through which their final commit could safely release our lock and effects.
 */
final class VaultMutationTransaction
{
    use AuditChainLockTrait;

    private bool $active = false;

    /** @var list<callable():void> */
    private array $committedActions = [];

    /** @var list<callable():void> */
    private array $rolledBackActions = [];

    public function __construct(
        private readonly ConnectionPool $connectionPool,
        private readonly ?LoggerInterface $logger = null,
    ) {}

    public function isActive(): bool
    {
        return $this->active;
    }

    /**
     * @param callable():void $action
     */
    public function afterCommit(callable $action): void
    {
        if ($this->active) {
            $this->committedActions[] = $action;

            return;
        }

        $action();
    }

    /**
     * @param callable():void $action
     */
    public function afterRollback(callable $action): void
    {
        if ($this->active) {
            $this->rolledBackActions[] = $action;
        }
    }

    /**
     * @param callable():void $mutation
     */
    public function run(callable $mutation): void
    {
        if ($this->active) {
            throw new AuditWriteException(
                'Nested vault mutations are not supported.',
                1793180001,
            );
        }

        $connection = $this->sharedConnection();
        if ($connection->isTransactionActive()) {
            throw new AuditWriteException(
                'A local vault mutation must own its database transaction; an outer transaction is already active.',
                1793180002,
            );
        }

        $platform = $connection->getDatabasePlatform();
        $isSQLite = $platform instanceof SQLitePlatform;
        if (!$isSQLite && !$platform instanceof AbstractMySQLPlatform) {
            throw new AuditWriteException(
                'Atomic local vault mutations require SQLite, MySQL or MariaDB.',
                1793180003,
            );
        }

        // Doctrine-managed SQLite transactions allow log() to use savepoints.
        // On MySQL the named lock remains held through the OUTERMOST commit.
        $this->acquireAuditLock($connection, $isSQLite, true);
        $this->active = true;
        $failure      = null;

        try {
            $mutation();
            $this->commitAuditLock($connection, $isSQLite);
        } catch (Throwable $e) {
            $failure = $e;

            try {
                if ($connection->isTransactionActive()) {
                    $this->rollbackAuditLock($connection, $isSQLite);
                }
            } catch (Throwable $rollbackFailure) {
                $connection->close();
                $this->reportCleanupFailure($rollbackFailure);
            }
        }

        $committedActions        = $this->committedActions;
        $rolledBackActions       = $this->rolledBackActions;
        $this->committedActions  = [];
        $this->rolledBackActions = [];
        $this->active            = false;

        try {
            $this->releaseAuditLock($connection, $isSQLite);
        } catch (Throwable $releaseFailure) {
            // Closing prevents a leaked session lock from blocking later work.
            $connection->close();
            $this->reportCleanupFailure($releaseFailure);
        }

        if ($failure instanceof Throwable) {
            foreach ($rolledBackActions as $action) {
                try {
                    $action();
                } catch (Throwable $replayFailure) {
                    // A failed denial-log replay must not replace the original
                    // operation failure or accidentally replay a success entry.
                    $this->reportCleanupFailure($replayFailure);
                }
            }

            throw $failure;
        }

        // Effects cannot roll back a committed transaction. Listener failures
        // may propagate, but no longer enter the rollback path above.
        foreach ($committedActions as $action) {
            $action();
        }
    }

    public function sharedConnection(): Connection
    {
        $connection = $this->connectionPool->getConnectionForTable(
            AuditLogService::TABLE_NAME,
        );
        foreach ([
            'tx_nrvault_secret',
            'tx_nrvault_secret_begroups_mm',
            'tx_nrvault_secret_writegroups_mm',
            'sys_registry',
        ] as $table) {
            if ($this->connectionPool->getConnectionForTable($table) !== $connection) {
                throw new AuditWriteException(
                    'Atomic local vault mutations require secret, ACL, audit and anchor tables on the same database connection.',
                    1793180004,
                );
            }
        }

        return $connection;
    }

    private function reportCleanupFailure(Throwable $failure): void
    {
        try {
            $this->logger?->error(
                'Local vault transaction cleanup or denied-audit replay failed.',
                ['exception' => $failure::class],
            );
        } catch (Throwable) {
            // Cleanup must preserve the original operation outcome.
        }
    }
}
