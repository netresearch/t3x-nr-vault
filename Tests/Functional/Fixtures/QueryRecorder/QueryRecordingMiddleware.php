<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\QueryRecorder;

use Doctrine\DBAL\Driver;
use Doctrine\DBAL\Driver\Middleware;

/**
 * Test-only Doctrine driver middleware: records every statement the
 * connection sends, with whether a transaction was open at that moment.
 *
 * It sits below the vault adapter and repository, so a test can observe
 * where a read happens on the stock wiring, where any decorator around the
 * adapter would make `VaultService::mutate()` skip its transaction. Recording
 * is off until a test calls {@see self::start()}.
 */
final class QueryRecordingMiddleware implements Middleware
{
    /** @var list<array{sql: string, inTransaction: bool}>|null */
    public static ?array $queries = null;

    public static function start(): void
    {
        self::$queries = [];
    }

    /**
     * Stop recording and return what was recorded.
     *
     * @return list<array{sql: string, inTransaction: bool}>
     */
    public static function stop(): array
    {
        $queries       = self::$queries ?? [];
        self::$queries = null;

        return $queries;
    }

    public static function record(string $sql, bool $inTransaction): void
    {
        if (self::$queries !== null) {
            self::$queries[] = ['sql' => $sql, 'inTransaction' => $inTransaction];
        }
    }

    public function wrap(Driver $driver): Driver
    {
        return new QueryRecordingDriver($driver);
    }
}
