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

    /**
     * Rows fetched per keyset-paginated batch. The chain walk is sequential by
     * design (each hash links to its predecessor), but the audit log can be
     * arbitrarily large — fetching it wholesale would OOM the rotation command.
     */
    private const BATCH_SIZE = 1000;

    public function __construct(
        private AuditChainAnchorStoreInterface $anchorStore,
    ) {}

    public function rekeyChain(Connection $connection, #[SensitiveParameter] string $newMasterKey): int
    {
        $hmacKey = AuditLogService::deriveHmacKeyFromMasterKey($newMasterKey);

        try {
            $rewritten = $this->rewriteChain($connection, $hmacKey);
        } finally {
            sodium_memzero($hmacKey);
        }

        // The rewrite invalidated the entry hash the tip anchor asserts, so the
        // anchor is re-signed here — under the NEW key, because the master-key
        // provider still holds the old one at this point. This lives inside
        // rekeyChain() rather than in its caller on purpose: as a caller
        // obligation it was a docblock that every future caller had to honour,
        // and skipping it makes an entirely healthy chain report a tip-anchor
        // violation on every subsequent verification.
        $this->anchorStore->reseal($connection, $newMasterKey);

        return $rewritten;
    }

    /**
     * Walk the chain from uid 1 upward, recomputing each row's entry hash
     * with its OWN stored epoch and the new HMAC key, re-linking
     * `previous_hash` as it goes.
     */
    private function rewriteChain(Connection $connection, #[SensitiveParameter] string $hmacKey): int
    {
        $previousHash = '';
        $rewrittenCount = 0;
        $lastUid = 0;

        // Keyset pagination (uid > last seen, LIMIT n): bounded memory on
        // arbitrarily large logs, and each batch is fully materialised before
        // its UPDATEs run, so reads never interleave with writes on an open
        // cursor. $previousHash carries the chain linkage across batches.
        do {
            $queryBuilder = $connection->createQueryBuilder();
            $rows = $queryBuilder
                ->select('*')
                ->from(self::TABLE_NAME)
                ->where($queryBuilder->expr()->gt(
                    'uid',
                    $queryBuilder->createNamedParameter($lastUid, Connection::PARAM_INT),
                ))
                ->orderBy('uid', 'ASC')
                ->setMaxResults(self::BATCH_SIZE)
                ->executeQuery()
                ->fetchAllAssociative();

            foreach ($rows as $row) {
                $rewrittenCount += $this->rekeyRow($connection, $row, $hmacKey, $previousHash);
                $uid = $row['uid'] ?? 0;
                $lastUid = max($lastUid, is_numeric($uid) ? (int) $uid : 0);
            }
        } while (\count($rows) === self::BATCH_SIZE);

        return $rewrittenCount;
    }

    /**
     * Recompute one row's entry hash with its OWN stored epoch under the new
     * HMAC key, re-linking previous_hash. Returns 1 when the row was updated.
     * $previousHash is advanced to this row's expected hash for the next link.
     *
     * @param array<string, mixed> $row
     */
    private function rekeyRow(
        Connection $connection,
        array $row,
        #[SensitiveParameter]
        string $hmacKey,
        string &$previousHash,
    ): int {
        $entry = AuditLogService::extractHashRow($row);

        // Epoch-aware dispatch, mirroring verifyHashChain():
        //   0  → legacy keyless SHA-256 (identity fields only)
        //   1  → HMAC-SHA256 (identity fields only)
        //   2  → HMAC-SHA256 (extended forensic payload)
        //   3+ → HMAC-SHA256 (forensic payload + epoch selector + attribution)
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
            $entry['epoch'] === 2 => AuditLogService::calculateHashV2(
                AuditLogService::extractV2HashRow($row),
                $previousHash,
                $hmacKey,
            ),
            default => AuditLogService::calculateHashV3(
                AuditLogService::extractV3HashRow($row),
                $previousHash,
                $hmacKey,
            ),
        };

        $rowEntryHash = \is_string($row['entry_hash'] ?? null) ? $row['entry_hash'] : '';
        $rowPreviousHash = \is_string($row['previous_hash'] ?? null) ? $row['previous_hash'] : '';

        // Constant-time comparisons per project mandate (AGENTS.md
        // Security Requirement #2), although this check only decides
        // whether an UPDATE is needed.
        $updated = 0;
        if (!hash_equals($expectedHash, $rowEntryHash) || !hash_equals($previousHash, $rowPreviousHash)) {
            $connection->update(
                self::TABLE_NAME,
                [
                    'entry_hash' => $expectedHash,
                    'previous_hash' => $previousHash,
                ],
                ['uid' => $entry['uid']],
            );
            $updated = 1;
        }

        $previousHash = $expectedHash;

        return $updated;
    }
}
