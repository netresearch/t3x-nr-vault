<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Acknowledgement;

use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Audit\HashChainVerificationResult;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;

use function array_key_exists;
use function count;
use function is_array;
use function is_numeric;
use function is_string;
use function sprintf;

/**
 * @see AuditFindingOverlayInterface
 */
final readonly class AuditFindingOverlay implements AuditFindingOverlayInterface
{
    /**
     * Lowest `hmac_key_epoch` whose MAC covers `reason`, `context` and the actor
     * columns. Below it a database-write attacker could forge or edit the
     * acknowledgement without the HMAC key.
     */
    public const MIN_ACKNOWLEDGEMENT_EPOCH = 3;

    /**
     * Marker substring of the epoch-downgrade error emitted by
     * {@see AuditLogService::verifyHashChain()}.
     */
    public const ERROR_MARKER_EPOCH_DOWNGRADE = 'epoch downgrade detected';

    /**
     * Marker substring of the uid-gap error emitted by
     * {@see AuditLogService::verifyHashChain()}. Gaps are read from the
     * structured `gaps` of the result, never from this message.
     */
    public const ERROR_MARKER_UID_GAP = 'uid gap detected';

    private const ROW_BATCH = 500;

    public function __construct(
        private ConnectionPool $connectionPool,
    ) {}

    /**
     * Stable identity of a finding: sha256 over its parts, unit-separated.
     */
    public static function key(string ...$parts): string
    {
        return hash('sha256', implode("\x1f", $parts));
    }

    public function chainItems(HashChainVerificationResult $raw): array
    {
        $digestUids = [];
        foreach ($raw->gaps as $gap) {
            $digestUids[] = $gap['uid'];
        }

        foreach (array_keys($raw->errors) as $uid) {
            if ($uid > 0) {
                $digestUids[] = $uid;
            }
        }

        return self::itemsFrom($raw, $this->rowDigests($digestUids));
    }

    /**
     * The pure part of {@see self::chainItems()}: items from a raw result and the
     * stored-content digests of the rows it names.
     *
     * @param array<int, string> $digests Row digest by uid
     *
     * @return list<AuditFindingItem>
     */
    public static function itemsFrom(HashChainVerificationResult $raw, array $digests): array
    {
        $items = [];

        foreach ($raw->gaps as $gap) {
            $items[] = new AuditFindingItem(
                self::key(AuditIntegrityReason::UidGap->value, (string) $gap['start'], (string) $gap['end'], (string) $gap['uid'], $digests[$gap['uid']] ?? ''),
                AuditIntegrityReason::UidGap,
                $gap['start'],
                $gap['end'],
                sprintf('Missing uids %d..%d before uid %d.', $gap['start'], $gap['end'], $gap['uid']),
            );
        }

        foreach ($raw->errors as $uid => $message) {
            $lower = strtolower($message);
            if (str_contains($lower, self::ERROR_MARKER_UID_GAP)) {
                continue;
            }

            $reason = str_contains($lower, self::ERROR_MARKER_EPOCH_DOWNGRADE)
                ? AuditIntegrityReason::EpochDowngrade
                : AuditIntegrityReason::HashMismatch;
            $row     = max(0, $uid);
            $items[] = new AuditFindingItem(
                self::key($reason->value, (string) $uid, $message, $digests[$uid] ?? ''),
                $reason,
                $row,
                $row,
                $message,
            );
        }

        return $items;
    }

    public function apply(array $items, HashChainVerificationResult $raw, int $fromUid = 0): array
    {
        if ($items === []) {
            return [];
        }

        $covered = $this->coveredKeys($raw, $fromUid);
        if ($covered === []) {
            return $items;
        }

        $result = [];
        foreach ($items as $item) {
            $ackUid = $covered[$item->key] ?? null;
            // A chain item is covered only by a row written AFTER it; chain-level
            // items (anchor findings, range 0) have no row to follow.
            if ($ackUid !== null && ($item->rangeEnd === 0 || $ackUid > $item->rangeEnd)) {
                $item = $item->withAcknowledgement($ackUid);
            }

            $result[] = $item;
        }

        return $result;
    }

    /**
     * Finding key => uid of the first valid acknowledgement row listing it.
     *
     * @return array<string, int>
     */
    private function coveredKeys(HashChainVerificationResult $raw, int $fromUid): array
    {
        $queryBuilder = $this->connectionPool
            ->getConnectionForTable(AuditLogService::TABLE_NAME)
            ->createQueryBuilder();
        $rows = $queryBuilder
            ->select('uid', 'previous_hash', 'context')
            ->from(AuditLogService::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq('action', $queryBuilder->createNamedParameter(AuditAction::AuditFindingsAcknowledged->value)),
                $queryBuilder->expr()->eq('success', $queryBuilder->createNamedParameter(1, Connection::PARAM_INT)),
                $queryBuilder->expr()->gte('hmac_key_epoch', $queryBuilder->createNamedParameter(self::MIN_ACKNOWLEDGEMENT_EPOCH, Connection::PARAM_INT)),
                $queryBuilder->expr()->gte('uid', $queryBuilder->createNamedParameter($fromUid, Connection::PARAM_INT)),
            )
            ->orderBy('uid', 'ASC')
            ->executeQuery()
            ->fetchAllAssociative();

        $covered = [];
        foreach ($rows as $row) {
            $uid = is_numeric($row['uid'] ?? null) ? (int) $row['uid'] : 0;
            // A row that fails its own hash proves nothing: ignore it.
            if ($uid === 0 || array_key_exists($uid, $raw->errors)) {
                continue;
            }

            $context = json_decode(is_string($row['context'] ?? null) ? $row['context'] : '', true);
            if (!is_array($context)) {
                continue;
            }

            $tipHash  = $context['tipHash'] ?? null;
            $findings = $context['findings'] ?? null;
            $previous = is_string($row['previous_hash'] ?? null) ? $row['previous_hash'] : '';
            // The acknowledgement must sit directly after the tip it recorded:
            // that is what stops it from covering rows written later.
            if (!is_string($tipHash) || $tipHash === '' || !hash_equals($tipHash, $previous) || !is_string($findings) || $findings === '') {
                continue;
            }

            foreach (explode(',', $findings) as $key) {
                if (preg_match('/^[0-9a-f]{64}$/', $key) === 1 && !array_key_exists($key, $covered)) {
                    $covered[$key] = $uid;
                }
            }
        }

        return $covered;
    }

    /**
     * sha256 of each row's complete stored content, keyed by uid.
     *
     * Whole-row rather than the hashed columns: an acknowledgement then covers
     * the row exactly as the administrator saw it, and any later edit of any
     * column reopens the finding.
     *
     * @param list<int> $uids
     *
     * @return array<int, string>
     */
    private function rowDigests(array $uids): array
    {
        $uids = array_values(array_unique($uids));
        if ($uids === []) {
            return [];
        }

        $connection = $this->connectionPool->getConnectionForTable(AuditLogService::TABLE_NAME);
        $digests    = [];

        for ($offset = 0; $offset < count($uids); $offset += self::ROW_BATCH) {
            $queryBuilder = $connection->createQueryBuilder();
            $rows         = $queryBuilder
                ->select('*')
                ->from(AuditLogService::TABLE_NAME)
                ->where(
                    $queryBuilder->expr()->in(
                        'uid',
                        $queryBuilder->createNamedParameter(array_slice($uids, $offset, self::ROW_BATCH), Connection::PARAM_INT_ARRAY),
                    ),
                )
                ->executeQuery()
                ->fetchAllAssociative();

            foreach ($rows as $row) {
                ksort($row);
                $rowUid = $row['uid'] ?? null;
                if (!is_numeric($rowUid)) {
                    continue;
                }

                $digests[(int) $rowUid] = hash('sha256', json_encode($row, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE));
            }
        }

        return $digests;
    }
}
