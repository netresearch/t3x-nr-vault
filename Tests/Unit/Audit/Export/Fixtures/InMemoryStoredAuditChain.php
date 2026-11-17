<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Export\Fixtures;

use Netresearch\NrVault\Audit\Export\StoredAuditChainInterface;
use Throwable;

/**
 * The installation's audit chain held in memory, for verifier tests. With a
 * failure set, every read throws it, like an unreachable database.
 */
final readonly class InMemoryStoredAuditChain implements StoredAuditChainInterface
{
    /** @var list<array<string, int|string>> */
    private array $rows;

    private ?Throwable $failure;

    /**
     * @param list<array<string, int|string>> $rows
     */
    public function __construct(array $rows, ?Throwable $failure = null)
    {
        $this->rows    = $rows;
        $this->failure = $failure;
    }

    public function exportRowAt(int $uid): ?array
    {
        $this->failIfConfigured();
        foreach ($this->rows as $row) {
            if ($row['uid'] === $uid) {
                return $row;
            }
        }

        return null;
    }

    public function entryHashAt(int $uid): ?string
    {
        $row = $this->exportRowAt($uid);

        return $row === null ? null : (string) $row['entry_hash'];
    }

    public function countAfter(int $uid): int
    {
        $this->failIfConfigured();

        return count(array_filter($this->rows, static fn (array $row): bool => $row['uid'] > $uid));
    }

    private function failIfConfigured(): void
    {
        if ($this->failure instanceof Throwable) {
            throw $this->failure;
        }
    }
}
