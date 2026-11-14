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

    /** Acknowledgement rows read per verification; a chain holds a handful. */
    private const MAX_ACKNOWLEDGEMENT_ROWS = 1000;

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
                null,
                // The chain-wide epoch-floor error (pseudo uid 0) has no row; it may
                // be covered while the chain up to the recorded tip is unchanged.
                // The in-database anchor errors (negative pseudo uids) are resolved
                // by re-arming the anchor and are never covered.
                $uid === 0,
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
            $ack = $covered[$item->key] ?? null;
            if ($ack !== null && $this->covers($item, $ack)) {
                $item = $item->withAcknowledgement($ack['uid']);
            }

            $result[] = $item;
        }

        return $result;
    }

    /**
     * @param array{uid: int, tipUid: int, tipHash: string} $ack
     */
    private function covers(AuditFindingItem $item, array $ack): bool
    {
        // A row or gap finding is covered only by a row written AFTER it; the key
        // already carries the stored content of the affected row.
        if ($item->rangeStart > 0) {
            return $ack['uid'] > $item->rangeEnd;
        }

        // A chain-level finding without a row is covered only when it is bound to
        // the chain prefix the administrator saw: the row at the recorded tip must
        // still carry the recorded hash. The in-database anchor errors are never covered.
        return $item->prefixBound && $this->tipStillHolds($ack['tipUid'], $ack['tipHash']);
    }

    private function tipStillHolds(int $tipUid, string $tipHash): bool
    {
        if ($tipUid <= 0 || $tipHash === '') {
            return false;
        }

        $queryBuilder = $this->connectionPool
            ->getConnectionForTable(AuditLogService::TABLE_NAME)
            ->createQueryBuilder();
        $stored = $queryBuilder
            ->select('entry_hash')
            ->from(AuditLogService::TABLE_NAME)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($tipUid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return is_string($stored) && hash_equals($tipHash, $stored);
    }

    /**
     * Finding key => the first valid acknowledgement row listing it, with the
     * tip it recorded.
     *
     * @return array<string, array{uid: int, tipUid: int, tipHash: string}>
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
            ->setMaxResults(self::MAX_ACKNOWLEDGEMENT_ROWS)
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
                    $covered[$key] = [
                        'uid'     => $uid,
                        'tipUid'  => is_numeric($context['tipUid'] ?? null) ? (int) $context['tipUid'] : 0,
                        'tipHash' => $tipHash,
                    ];
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

                $digests[(int) $rowUid] = hash('sha256', serialize($row));
            }
        }

        return $digests;
    }
}
