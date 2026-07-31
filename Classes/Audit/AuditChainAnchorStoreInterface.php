<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use SensitiveParameter;
use TYPO3\CMS\Core\Database\Connection;

/**
 * Persists a MAC-signed assertion about the audit chain's tip OUTSIDE
 * `tx_nrvault_audit_log`, so a tail truncation or a full wipe of that table
 * cannot leave a self-consistent chain that verifies as valid.
 *
 * Every mutator is *given* the caller's `Connection` and refuses to write
 * unless `sys_registry` resolves to that same connection. The invariant
 *
 *     an anchor exists  =>  sys_registry shares the audit connection
 *
 * is what makes the anchor commit or roll back together with the audit row it
 * describes: the store never resolves its own connection for a write, so it
 * can never end up ahead of a rolled-back audit write.
 */
interface AuditChainAnchorStoreInterface
{
    /**
     * Whether the anchor is armed at all — true from audit HMAC epoch 1 up.
     *
     * At epoch 0 the chain is keyless, so there is no tamper evidence to
     * protect and arming the anchor would add a brand-new master-key
     * dependency to the audit write path.
     */
    public function isEnabled(): bool;

    /**
     * Whether `sys_registry` resolves to the same connection as the audit log.
     */
    public function sharesConnection(Connection $auditConnection): bool;

    /**
     * Record a newly appended tip. Forward-only in uid: a stored uid greater
     * than or equal to `$tip->uid` is left alone (out-of-order writers such as
     * the lock-free demo seeder). Rewriting an existing row's hash is
     * {@see self::reseal()}'s job, never this one's.
     *
     * `$masterKey` null means "derive from the master-key provider".
     *
     * No-op when the anchor is disabled, when `sys_registry` is on a foreign
     * connection, when the stored value is present but unparseable, when the
     * stored anchor's own assertion no longer holds, or when no anchor row
     * exists while `auditAnchorRequired` is on. Together those keep the control
     * monotone: a corrupted,
     * already-violated or REMOVED anchor must not be silently repaired or
     * overtaken by the next append — otherwise an attacker truncates the log
     * and lets ordinary traffic re-arm the anchor on the shortened chain.
     * Arming again is an explicit, audited operator action
     * ({@see self::arm()}, `vault:audit --reset-anchor`).
     */
    public function advance(
        Connection $connection,
        AuditChainAnchor $tip,
        #[SensitiveParameter]
        ?string $masterKey = null,
    ): void;

    /**
     * Re-record the anchor after every row's `entry_hash` was rewritten
     * (master-key rotation, HMAC migration). Re-reads the tip from the audit
     * table on the caller's connection, inside the caller's lock/transaction.
     *
     * Writes nothing when the recomputed tip already equals the stored one,
     * records nothing on an empty chain — deleting the anchor there would be a
     * downgrade an attacker could induce by wiping the table — and, like
     * {@see self::advance()}, refuses to create an anchor that is not there
     * while `auditAnchorRequired` is on.
     *
     * `$masterKey` null means "derive from the master-key provider"; master-key
     * rotation passes the NEW key explicitly, because it must sign under that
     * key before the provider is reconfigured.
     */
    public function reseal(
        Connection $connection,
        #[SensitiveParameter]
        ?string $masterKey = null,
    ): void;

    /**
     * Explicitly (re-)arm the anchor on the chain's current tip, replacing
     * whatever is stored.
     *
     * This is the ONLY path that may create an absent anchor while
     * `auditAnchorRequired` is on, and it is reachable only from an
     * operator command that records the fact in the audit chain itself. Returns
     * false — writing nothing — when the anchor is disabled, when `sys_registry`
     * is on a foreign connection, or when the chain is empty.
     *
     * `$masterKey` null means "derive from the master-key provider".
     */
    public function arm(
        Connection $connection,
        #[SensitiveParameter]
        ?string $masterKey = null,
    ): bool;

    /**
     * Clear the anchor. Escape hatch for a legitimate full wipe, where the
     * forward-only rule would otherwise leave the install reporting a
     * violation forever. Callers MUST write an audit entry recording the reset
     * in the same transaction.
     */
    public function reset(Connection $connection): void;

    /**
     * Read the anchor. Strictly read-only on every path — the verifier must
     * never adopt or repair what it is checking.
     */
    public function load(Connection $auditConnection): AuditChainAnchorLoad;
}
