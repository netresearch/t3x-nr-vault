<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\QueryRecorder;

use Doctrine\DBAL\Driver\Middleware\AbstractConnectionMiddleware;
use Doctrine\DBAL\Driver\Result;
use Doctrine\DBAL\Driver\Statement;

/**
 * Tracks the driver-level transaction: Doctrine nests through savepoints on
 * top of one driver transaction, so begin/commit/rollBack here mark the
 * outermost one.
 */
final class QueryRecordingConnection extends AbstractConnectionMiddleware
{
    private bool $inTransaction = false;

    public function beginTransaction(): void
    {
        parent::beginTransaction();
        $this->inTransaction = true;
    }

    public function commit(): void
    {
        parent::commit();
        $this->inTransaction = false;
    }

    public function rollBack(): void
    {
        parent::rollBack();
        $this->inTransaction = false;
    }

    public function prepare(string $sql): Statement
    {
        QueryRecordingMiddleware::record($sql, $this->inTransaction);

        return parent::prepare($sql);
    }

    public function query(string $sql): Result
    {
        QueryRecordingMiddleware::record($sql, $this->inTransaction);

        return parent::query($sql);
    }

    public function exec(string $sql): int|string
    {
        QueryRecordingMiddleware::record($sql, $this->inTransaction);

        return parent::exec($sql);
    }
}
