<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Export;

/**
 * The installation's own audit chain, as `--verify-export` consults it: the
 * reference an export file is checked against, never the file itself.
 */
interface StoredAuditChainInterface
{
    /**
     * The stored row at $uid in export form, or null when there is none.
     *
     * @return array<string, int|string>|null
     */
    public function exportRowAt(int $uid): ?array;

    /**
     * The stored entry hash at $uid, or null when there is no such row.
     */
    public function entryHashAt(int $uid): ?string;

    /**
     * How many rows the installation stores after $uid.
     */
    public function countAfter(int $uid): int;
}
