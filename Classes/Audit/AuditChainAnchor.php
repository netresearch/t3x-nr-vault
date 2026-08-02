<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

/**
 * The assertion pinned outside `tx_nrvault_audit_log`:
 *
 *   audit row `uid` still exists AND its `entry_hash` is still `entryHash`.
 *
 * Deliberately NOT a row count and NOT a `max(uid)`. An aggregate has to be
 * compared against something the verifier observes, and a concurrent append
 * changes it between the observation and the anchor read — that is what made
 * an earlier count-based attempt report "truncation detected" on an intact
 * chain. An existence-and-equality claim about one already-committed row
 * cannot be falsified by an append at all.
 *
 * The hash is load-bearing, not decoration: after
 * `DELETE ... WHERE uid > N` the auto-increment counter is reused on two of
 * the three supported platforms (SQLite `rowid` without `AUTOINCREMENT` is
 * `max(rowid)+1`; MariaDB InnoDB re-derives `AUTO_INCREMENT` as `max(uid)+1`
 * on server start), so ordinary appends refill the anchored uid and mere
 * existence would report VALID again. The refilled row carries a different
 * `entry_hash`.
 */
final readonly class AuditChainAnchor
{
    public function __construct(
        public int $uid,
        public string $entryHash,
        public int $tstamp,
    ) {}
}
