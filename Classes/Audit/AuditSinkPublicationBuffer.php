<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

/**
 * Holds back external audit-sink publication while a caller-owned
 * transaction is open, so a sink never receives an entry that rolls back.
 *
 * {@see VaultMutationTransaction} does the same for local mutations. Master-key
 * rotation runs its own transaction and uses this buffer instead: it starts
 * collecting before the transaction, flushes after the commit and discards on
 * a rollback. {@see AuditLogService::log()} defers to the buffer while it
 * collects.
 *
 * @internal
 */
final class AuditSinkPublicationBuffer
{
    private bool $collecting = false;

    /** @var list<callable():void> */
    private array $pending = [];

    public function collect(): void
    {
        $this->collecting = true;
        $this->pending    = [];
    }

    public function isCollecting(): bool
    {
        return $this->collecting;
    }

    /**
     * @param callable():void $publish
     */
    public function defer(callable $publish): void
    {
        if (!$this->collecting) {
            $publish();

            return;
        }

        $this->pending[] = $publish;
    }

    /**
     * Stop collecting and publish what was collected, in the order it was
     * written.
     */
    public function flush(): void
    {
        $pending          = $this->pending;
        $this->collecting = false;
        $this->pending    = [];

        foreach ($pending as $publish) {
            $publish();
        }
    }

    /**
     * Stop collecting and drop what was collected; its entries rolled back.
     */
    public function discard(): void
    {
        $this->collecting = false;
        $this->pending    = [];
    }
}
