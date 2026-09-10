<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Traits;

use Netresearch\NrVault\Audit\AuditLogService;

/**
 * Seeds audit rows the way an installation from before the HMAC chain wrote
 * them: epoch 0, keyless SHA-256, one row per call.
 *
 * Each row starts its own chain (`previous_hash` stays empty), which is what
 * the migration tests need — they assert that the migration re-links and
 * re-seals whatever it finds, not that the seed was a well-formed chain.
 *
 * Requires the using class to provide `getConnectionPool()`, which every
 * TYPO3 functional test case does.
 */
trait LegacyAuditEntryTrait
{
    private function seedLegacyAuditEntry(string $secretIdentifier, string $action): void
    {
        $connection = $this->getConnectionPool()->getConnectionForTable('tx_nrvault_audit_log');

        $crdate = time();
        $previousHash = '';

        $connection->insert('tx_nrvault_audit_log', [
            'pid' => 0,
            'secret_identifier' => $secretIdentifier,
            'action' => $action,
            'success' => 1,
            'error_message' => '',
            'reason' => 'Legacy test entry',
            'actor_uid' => 1,
            'actor_type' => 'be_user',
            'actor_username' => 'admin',
            'actor_role' => 'admin',
            'ip_address' => 'CLI',
            'user_agent' => 'CLI',
            'request_id' => bin2hex(random_bytes(8)),
            'previous_hash' => $previousHash,
            'hash_before' => '',
            'hash_after' => '',
            'crdate' => $crdate,
            'hmac_key_epoch' => 0,
            'context' => '{}',
            'entry_hash' => '', // placeholder - will be updated below
        ]);

        $uid = (int) $connection->lastInsertId();

        // Calculate correct legacy SHA-256 hash for this entry
        $legacyHash = AuditLogService::calculateHash(
            $uid,
            $secretIdentifier,
            $action,
            1,
            $crdate,
            $previousHash, // null = legacy SHA-256
        );

        $connection->update(
            'tx_nrvault_audit_log',
            ['entry_hash' => $legacyHash],
            ['uid' => $uid],
        );
    }
}
