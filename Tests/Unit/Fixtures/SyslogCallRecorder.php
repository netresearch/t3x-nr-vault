<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Sink;

/**
 * @internal Isolated PHPUnit call capture, never loaded by production.
 */
final class SyslogCallRecorder
{
    /** @var list<array{string, list<int|string>}> */
    public static array $calls = [];
}

function openlog(string $prefix, int $flags, int $facility): bool
{
    SyslogCallRecorder::$calls[] = ['openlog', [$prefix, $flags, $facility]];

    return true;
}

function syslog(int $priority, string $message): bool
{
    SyslogCallRecorder::$calls[] = ['syslog', [$priority, $message]];

    return true;
}

function closelog(): bool
{
    SyslogCallRecorder::$calls[] = ['closelog', []];

    return true;
}
