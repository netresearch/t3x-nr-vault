<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Http\Fixtures;

use Closure;
use Netresearch\NrVault\Http\TransportTickerInterface;
use RuntimeException;

/**
 * Controlled only by isolated idle-bound tests; never loaded in the parent process.
 */
final class TransferClock
{
    private static int $milliseconds = 0;

    private static int $reads = 0;

    public static function reset(): void
    {
        self::$milliseconds = 0;
        self::$reads = 0;
    }

    public static function advance(): void
    {
        self::$milliseconds += 50;
    }

    public static function now(): float
    {
        self::$reads++;

        return 1000.0 + self::$milliseconds / 1000;
    }

    public static function elapsed(): float
    {
        return self::$milliseconds / 1000;
    }

    public static function reads(): int
    {
        return self::$reads;
    }
}

final class TransferClockTicker implements TransportTickerInterface
{
    private int $ticks = 0;

    /**
     * @param Closure(int): void $step
     */
    public function __construct(private readonly Closure $step) {}

    public function tick(): void
    {
        if (++$this->ticks > 20) {
            throw new RuntimeException(
                'Controlled transfer exceeded the test tick ceiling',
                1791599700,
            );
        }

        TransferClock::advance();
        ($this->step)($this->ticks);
    }

    public function ticks(): int
    {
        return $this->ticks;
    }
}

namespace Netresearch\NrVault\Http;

use Netresearch\NrVault\Tests\Unit\Http\Fixtures\TransferClock;

use function microtime as nativeMicrotime;

/**
 * @return ($asFloat is true ? float : string)
 */
function microtime(bool $asFloat = false): float|string
{
    return $asFloat ? TransferClock::now() : nativeMicrotime(false);
}
