<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Fixtures;

use Netresearch\NrVault\Audit\AuditChainLockTrait;
use TYPO3\CMS\Core\Database\Connection;

/**
 * Minimal host for {@see AuditChainLockTrait} so its lock primitives can be
 * exercised directly.
 *
 * The trait's methods are private by design — the three production consumers
 * (audit writer, migrate command, upgrade wizard) each reach them from inside
 * their own class. Testing them through any one consumer would drag that
 * consumer's whole write path into every lock assertion; this host isolates the
 * lock protocol itself.
 *
 * @internal test fixture
 */
final readonly class AuditChainLockHost
{
    use AuditChainLockTrait;

    /**
     * @param int $lockTimeoutSeconds Replaces the trait's 5-second PostgreSQL
     *                                lock wait, so a timeout test needs one poll
     */
    public function __construct(
        private int $lockTimeoutSeconds = self::AUDIT_LOCK_TIMEOUT_SECONDS,
    ) {}

    public function acquire(Connection $connection, bool $isSQLite): void
    {
        $this->acquireAuditLock($connection, $isSQLite);
    }

    public function commit(Connection $connection, bool $isSQLite): void
    {
        $this->commitAuditLock($connection, $isSQLite);
    }

    public function rollback(Connection $connection, bool $isSQLite): void
    {
        $this->rollbackAuditLock($connection, $isSQLite);
    }

    public function release(Connection $connection, bool $isSQLite): void
    {
        $this->releaseAuditLock($connection, $isSQLite);
    }

    private function auditLockTimeoutSeconds(): int
    {
        return $this->lockTimeoutSeconds;
    }
}
