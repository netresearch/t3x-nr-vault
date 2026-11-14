<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\HashiCorp;

/**
 * Reports once per process that the KV store behind the HashiCorp adapter
 * implements only the deprecated {@see KvStoreInterface}. The flag lives here
 * because the adapter is a readonly class and cannot hold static state.
 *
 * @internal
 */
final class LegacyKvStoreNotice
{
    private static bool $reported = false;

    public static function report(): void
    {
        if (self::$reported) {
            return;
        }

        self::$reported = true;

        trigger_error(
            'The KV store for the HashiCorp adapter implements only KvStoreInterface, which is deprecated: it cannot create a key atomically, '
            . 'so a key created by someone else between the check and the write is overwritten. Implement AtomicKvStoreInterface; '
            . 'nr-vault 2.0 will require it.',
            E_USER_DEPRECATED,
        );
    }

    /**
     * For tests: report again on the next use.
     */
    public static function reset(): void
    {
        self::$reported = false;
    }
}
