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
 * Re-keys the tamper-evident audit hash chain after a master-key rotation.
 *
 * The chain's HMAC key is derived from the master key, so rotating the
 * master key orphans every HMAC-epoch entry: verification with the new key
 * fails from the first HMAC'd row onward. Re-keying recomputes the chain
 * under the key derived from the NEW master key while preserving each row's
 * stored payload-format epoch.
 */
interface AuditChainRekeyServiceInterface
{
    /**
     * Recompute every chain hash under the HMAC key derived from the new
     * master key.
     *
     * Runs INSIDE the caller's open transaction on `$connection` and takes
     * no locks itself. The caller MUST:
     *  - hold the audit advisory lock for the remainder of the transaction
     *    (no concurrent writer may chain onto a tip hash being rewritten),
     *  - have the audit-log table on this connection, and
     *  - commit/roll back secrets re-encryption and chain re-key together.
     *
     * Per-row `hmac_key_epoch` values are preserved — re-keying changes the
     * key, not the payload format:
     *  - epoch 0 rows are keyless SHA-256 and only change where their
     *    `previous_hash` link changes,
     *  - epoch 1 / 2+ rows are recomputed under the new HMAC key.
     *
     * @param Connection $connection Connection carrying the caller's transaction
     * @param string $newMasterKey The NEW raw master key (32 bytes)
     *
     * @return int Number of rows whose hashes were rewritten
     */
    public function rekeyChain(Connection $connection, #[SensitiveParameter] string $newMasterKey): int;
}
