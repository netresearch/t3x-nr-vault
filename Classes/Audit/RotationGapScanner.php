<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use SensitiveParameter;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function array_column;
use function array_flip;
use function is_string;
use function sprintf;

/**
 * Two-key check of the audit chain after a master-key rotation.
 *
 * The rotation re-keys the whole chain under the new master key, but a
 * process that still holds the old key until the configuration switch seals
 * its rows under the old one. Those rows break verification under the new
 * key. This scanner accepts a row under the previous key only when it comes
 * after the last successful rotation and links correctly to the row before
 * it; everything else the regular verification reports still refuses.
 */
final readonly class RotationGapScanner implements RotationGapScannerInterface
{
    private const TABLE_NAME = 'tx_nrvault_audit_log';

    public function __construct(
        private ConnectionPool $connectionPool,
        private AuditLogServiceInterface $auditLogService,
        private MasterKeyProviderInterface $masterKeyProvider,
    ) {}

    public function scan(#[SensitiveParameter] string $previousMasterKey): RotationGapScan
    {
        $verification = $this->auditLogService->verifyHashChain();
        if ($verification->isValid()) {
            return new RotationGapScan();
        }

        $connection = $this->connectionPool->getConnectionForTable(self::TABLE_NAME);
        $boundary   = $this->findRotationBoundary($connection);
        if ($boundary === null) {
            return new RotationGapScan(problems: [
                'The audit chain does not verify, and it holds no successful master-key rotation '
                . 'after which rows could have been sealed under the previous key.',
            ]);
        }

        $currentKey  = AuditLogService::deriveHmacKey($this->masterKeyProvider);
        $previousKey = AuditLogService::deriveHmacKeyFromMasterKey($previousMasterKey);

        try {
            [$rows, $problems] = $this->walkAfter($connection, $boundary, $currentKey, $previousKey);
        } finally {
            sodium_memzero($currentKey);
            sodium_memzero($previousKey);
        }

        // Every error of the regular verification must be one of the rows just
        // accepted under the previous key. Anything else — a row before the
        // rotation, the anchor (negative keys), the epoch floor (key 0) — is a
        // finding a re-seal would launder.
        $accepted = array_flip(array_column($rows, 'uid'));
        foreach ($verification->errors as $uid => $message) {
            if (!isset($accepted[$uid])) {
                $problems[] = $uid > 0 ? sprintf('Row uid %d: %s', $uid, $message) : $message;
            }
        }

        return new RotationGapScan($rows, $problems);
    }

    /**
     * The newest successful `master_key_rotate_end` row, or null.
     *
     * @return array<string, mixed>|null
     */
    private function findRotationBoundary(Connection $connection): ?array
    {
        $queryBuilder = $connection->createQueryBuilder();
        $row          = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq(
                    'action',
                    $queryBuilder->createNamedParameter(AuditAction::MasterKeyRotateEnd->value),
                ),
                $queryBuilder->expr()->eq(
                    'success',
                    $queryBuilder->createNamedParameter(1, Connection::PARAM_INT),
                ),
            )
            ->orderBy('uid', 'DESC')
            ->setMaxResults(1)
            ->executeQuery()
            ->fetchAssociative();

        return $row === false ? null : $row;
    }

    /**
     * Walk the rows after the boundary. Returns the rows that verify only
     * under the previous key, and the problems found on the way.
     *
     * @param array<string, mixed> $boundary
     *
     * @return array{list<array{uid: int, action: string, secretIdentifier: string, crdate: int}>, list<string>}
     */
    private function walkAfter(
        Connection $connection,
        array $boundary,
        #[SensitiveParameter]
        string $currentKey,
        #[SensitiveParameter]
        string $previousKey,
    ): array {
        $start        = AuditLogService::extractHashRow($boundary);
        $previousHash = is_string($boundary['entry_hash'] ?? null) ? $boundary['entry_hash'] : '';
        $previousUid  = $start['uid'];
        $epochBefore  = $start['epoch'];
        $rows         = [];
        $problems     = [];

        $queryBuilder = $connection->createQueryBuilder();
        $result       = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->gt(
                'uid',
                $queryBuilder->createNamedParameter($previousUid, Connection::PARAM_INT),
            ))
            ->orderBy('uid', 'ASC')
            ->executeQuery();

        foreach ($result->iterateAssociative() as $row) {
            $entry      = AuditLogService::extractHashRow($row);
            $storedLink = is_string($row['previous_hash'] ?? null) ? $row['previous_hash'] : '';
            $storedHash = is_string($row['entry_hash'] ?? null) ? $row['entry_hash'] : '';

            if ($entry['uid'] !== $previousUid + 1) {
                $problems[] = sprintf('Rows uid %d to %d are missing.', $previousUid + 1, $entry['uid'] - 1);
            }

            if ($entry['epoch'] < $epochBefore) {
                $problems[] = sprintf(
                    'Row uid %d lowers the HMAC key epoch from %d to %d.',
                    $entry['uid'],
                    $epochBefore,
                    $entry['epoch'],
                );
            }

            if (!hash_equals($previousHash, $storedLink)) {
                $problems[] = sprintf('Row uid %d does not link to the row before it.', $entry['uid']);
            } elseif (!$this->isSealedUnder($row, $previousHash, $storedHash, $currentKey)) {
                // Epoch-0 rows are keyless and match any key, so only an HMAC
                // row can be one sealed under the previous key.
                if ($entry['epoch'] > 0 && $this->isSealedUnder($row, $previousHash, $storedHash, $previousKey)) {
                    $rows[] = [
                        'uid'              => $entry['uid'],
                        'action'           => $entry['action'],
                        'secretIdentifier' => $entry['secretId'],
                        'crdate'           => $entry['crdate'],
                    ];
                } else {
                    $problems[] = sprintf(
                        'Row uid %d verifies under neither the current nor the previous master key.',
                        $entry['uid'],
                    );
                }
            }

            $previousHash = $storedHash;
            $previousUid  = $entry['uid'];
            $epochBefore  = $entry['epoch'];
        }

        return [$rows, $problems];
    }

    /**
     * @param array<string, mixed> $row
     */
    private function isSealedUnder(
        array $row,
        string $previousHash,
        string $storedHash,
        #[SensitiveParameter]
        string $hmacKey,
    ): bool {
        return hash_equals(AuditLogService::calculateEntryHash($row, $previousHash, $hmacKey), $storedHash);
    }
}
