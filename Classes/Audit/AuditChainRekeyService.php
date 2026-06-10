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
 * Rewrites the audit hash chain under the HMAC key derived from a new
 * master key. See {@see AuditChainRekeyServiceInterface} for the contract
 * (caller-managed transaction + advisory lock, epoch preservation).
 *
 * Modelled on `AuditHmacMigrationWizard::rehashAllRows()`, with two
 * deliberate differences:
 *  - the per-row `hmac_key_epoch` is PRESERVED, not migrated — re-keying
 *    changes the key, never the payload format;
 *  - rows are only UPDATEd when their hashes actually change, so an
 *    all-epoch-0 (keyless) chain passes through untouched.
 */
final readonly class AuditChainRekeyService implements AuditChainRekeyServiceInterface
{
    private const TABLE_NAME = 'tx_nrvault_audit_log';

    public function rekeyChain(Connection $connection, #[SensitiveParameter] string $newMasterKey): int
    {
        $hmacKey = AuditLogService::deriveHmacKeyFromMasterKey($newMasterKey);

        try {
            return $this->rewriteChain($connection, $hmacKey);
        } finally {
            sodium_memzero($hmacKey);
        }
    }

    /**
     * Walk the chain from uid 1 upward, recomputing each row's entry hash
     * with its OWN stored epoch and the new HMAC key, re-linking
     * `previous_hash` as it goes.
     */
    private function rewriteChain(Connection $connection, #[SensitiveParameter] string $hmacKey): int
    {
        $result = $connection->createQueryBuilder()
            ->select('*')
            ->from(self::TABLE_NAME)
            ->orderBy('uid', 'ASC')
            ->executeQuery();

        $previousHash = '';
        $rewrittenCount = 0;

        while (($row = $result->fetchAssociative()) !== false) {
            $entry = AuditLogService::extractHashRow($row);

            // Epoch-aware dispatch, mirroring verifyHashChain():
            //   0  → legacy keyless SHA-256 (identity fields only)
            //   1  → HMAC-SHA256 (identity fields only)
            //   2+ → HMAC-SHA256 (extended forensic payload)
            $expectedHash = match (true) {
                $entry['epoch'] === 0 => AuditLogService::calculateHash(
                    $entry['uid'],
                    $entry['secretId'],
                    $entry['action'],
                    $entry['actorUid'],
                    $entry['crdate'],
                    $previousHash,
                ),
                $entry['epoch'] === 1 => AuditLogService::calculateHash(
                    $entry['uid'],
                    $entry['secretId'],
                    $entry['action'],
                    $entry['actorUid'],
                    $entry['crdate'],
                    $previousHash,
                    $hmacKey,
                ),
                default => AuditLogService::calculateHashV2(
                    AuditLogService::extractV2HashRow($row),
                    $previousHash,
                    $hmacKey,
                ),
            };

            $rowEntryHash = \is_string($row['entry_hash'] ?? null) ? $row['entry_hash'] : '';
            $rowPreviousHash = \is_string($row['previous_hash'] ?? null) ? $row['previous_hash'] : '';

            // Constant-time comparisons per project mandate (AGENTS.md
            // Security Requirement #2), although this check only decides
            // whether an UPDATE is needed.
            if (!hash_equals($expectedHash, $rowEntryHash) || !hash_equals($previousHash, $rowPreviousHash)) {
                $connection->update(
                    self::TABLE_NAME,
                    [
                        'entry_hash' => $expectedHash,
                        'previous_hash' => $previousHash,
                    ],
                    ['uid' => $entry['uid']],
                );
                ++$rewrittenCount;
            }

            $previousHash = $expectedHash;
        }

        return $rewrittenCount;
    }
}
