<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Export;

use Generator;
use Netresearch\NrVault\Audit\Anchor\AnchorReaderInterface;
use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditLogFilter;
use Netresearch\NrVault\Audit\AuditLogService;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Crypto\MasterKeyProviderInterface;
use Throwable;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

use function count;
use function is_array;
use function is_int;
use function is_string;
use function sprintf;

/**
 * Exports the audit chain so that it can be re-verified without the database.
 *
 * Each exported row carries exactly the values the entry hash is computed
 * over — {@see AuditLogService::extractV3HashRow()}, which is a superset of
 * every epoch's payload — plus `previous_hash` and `entry_hash`, so
 * {@see AuditLogService::calculateEntryHash()} recomputes the stored hash from
 * the exported row alone. The one input that is never exported is the audit
 * HMAC key (rows at epoch 1 and above): it is derived from the master key, and
 * the verifier has to supply it.
 *
 * Rows are read in ascending uid order with keyset paging, `CHUNK_SIZE` at a
 * time, so memory stays bounded and rows written during the export can neither
 * shift a page boundary nor enter the selection (it ends at the tip uid taken
 * before the first read).
 */
final readonly class AuditChainExporter implements AuditChainExporterInterface
{
    public const FORMAT = 'nr-vault-audit-chain-export';

    public const FORMAT_VERSION = 1;

    private const TABLE_NAME = 'tx_nrvault_audit_log';

    private const CHUNK_SIZE = 1000;

    public function __construct(
        private ConnectionPool $connectionPool,
        private MasterKeyProviderInterface $masterKeyProvider,
        private ExtensionConfigurationInterface $configuration,
        private AnchorReaderInterface $anchorReader,
    ) {}

    public function select(?AuditLogFilter $filter = null, ?int $limit = null): AuditChainExport
    {
        if ($filter instanceof AuditLogFilter && $filter->isEmpty()) {
            $filter = null;
        }

        $tipUid = $this->aggregateUid('MAX', null, null);
        $total  = $this->countUpTo($filter, $tipUid);
        $count  = $limit === null ? $total : min($total, max(0, $limit));

        if ($count === 0) {
            return new AuditChainExport($tipUid, $total, 0, 0, 0, $filter, $limit, []);
        }

        $lastUid  = $this->aggregateUid('MAX', $filter, $tipUid);
        $firstUid = $count === $total
            ? $this->aggregateUid('MIN', $filter, $tipUid)
            : $this->nthNewestUid($filter, $tipUid, $count);

        return new AuditChainExport(
            $tipUid,
            $total,
            $count,
            $firstUid,
            $lastUid,
            $filter,
            $limit,
            $this->streamRows($filter, $firstUid, $lastUid),
        );
    }

    /**
     * The exported form of one stored row: the verbatim hash inputs, the
     * stored link to the previous row and the stored entry hash.
     *
     * @param array<string, mixed> $row
     *
     * @return array<string, int|string>
     */
    public static function exportRow(array $row): array
    {
        return AuditLogService::extractV3HashRow($row) + [
            'previous_hash' => is_string($row['previous_hash'] ?? null) ? $row['previous_hash'] : '',
            'entry_hash'    => is_string($row['entry_hash'] ?? null) ? $row['entry_hash'] : '',
        ];
    }

    /**
     * @return list<string>
     */
    public static function columns(): array
    {
        return array_keys(self::exportRow([]));
    }

    public function verify(array $document): AuditExportVerification
    {
        $meta = is_array($document['export'] ?? null) ? $document['export'] : [];
        $rows = is_array($document['rows'] ?? null) ? $document['rows'] : null;

        // What the file claims. The result's "whole chain" is derived below
        // from the rows and the installation; the claim only selects how
        // strictly neighbours are checked.
        $chainComplete = ($meta['chainComplete'] ?? null) === true;
        $truncated     = ($meta['truncated'] ?? null) === true;
        $tipUid        = is_int($meta['tipUid'] ?? null) ? $meta['tipUid'] : -1;
        $notes         = [];
        $firstUid      = is_int($meta['firstUid'] ?? null) ? $meta['firstUid'] : 0;
        $lastUid       = is_int($meta['lastUid'] ?? null) ? $meta['lastUid'] : 0;

        $errors = [];
        if (($meta['format'] ?? null) !== self::FORMAT || ($meta['version'] ?? null) !== self::FORMAT_VERSION) {
            $errors[] = sprintf('Not a %s document of version %d.', self::FORMAT, self::FORMAT_VERSION);
        }

        if ($rows === null) {
            $errors[] = 'The document has no "rows" list.';

            return new AuditExportVerification(0, -1, $errors, [], false, $truncated, $firstUid, $lastUid, $notes);
        }

        $declaredCount = is_int($meta['count'] ?? null) ? $meta['count'] : -1;
        if ($rows === []) {
            $errors[] = 'The export holds no rows, so nothing was verified.';
        }

        if ($declaredCount !== count($rows)) {
            $errors[] = sprintf('The metadata declares %d row(s), the document holds %d.', $declaredCount, count($rows));
        }

        $hmacKey     = null;
        $keyError    = null;
        $epochCounts = [];
        $checked     = 0;
        $previous    = null;
        // Every row that passed the shape check, in file order. The whole-chain
        // and anchor checks read these and nothing else, so no check can see a
        // value the hash check did not.
        $verifiedRows = [];
        // A row below the configured epoch is weaker than the chain it sits in:
        // the keyless epoch 0 can be recomputed by anyone who edits the file,
        // and epochs 1 and 2 leave columns out of their hash, and an old export
        // still carries the rows from before the migration re-sealed them. On
        // an installation that signs its chain with HMAC, such a row is accepted
        // only when the installation stores the same row, column for column, at
        // the same uid: the stored chain is the only evidence such a row has.
        $floorEpoch = $this->configuration->getAuditHmacEpoch();

        try {
            foreach ($rows as $index => $row) {
                $shapeError = is_array($row) ? $this->shapeError($row) : 'is not an object';
                if ($shapeError !== null) {
                    $errors[] = sprintf('Row %d %s.', $index, $shapeError);
                    $previous = null;

                    continue;
                }

                /** @var array<string, int|string> $row */
                $verifiedRows[]      = $row;
                $uid                 = (int) $row['uid'];
                $epoch               = (int) $row['hmac_key_epoch'];
                $epochCounts[$epoch] = ($epochCounts[$epoch] ?? 0) + 1;

                if ($epoch > 0 && $hmacKey === null && $keyError === null) {
                    try {
                        $hmacKey = AuditLogService::deriveHmacKey($this->masterKeyProvider);
                    } catch (Throwable $e) {
                        $keyError = 'The master key is not available, so rows at HMAC epoch 1 and above cannot be checked: '
                            . $e->getMessage();
                        $errors[] = $keyError;
                    }
                }

                if ($epoch < $floorEpoch) {
                    try {
                        $stored = $this->storedExportRow($uid);
                    } catch (Throwable $e) {
                        $stored  = null;
                        $notes[] = 'The stored chain could not be consulted: ' . $e->getMessage();
                    }

                    if ($stored !== $row) {
                        $errors[] = sprintf(
                            'uid %d is exported at epoch %d and differs from the row this installation stores '
                            . '(or it stores none at that uid); with HMAC at epoch %d, a row below that epoch is only confirmed by the stored chain.',
                            $uid,
                            $epoch,
                            $floorEpoch,
                        );
                        $previous = $row;

                        continue;
                    }
                }

                if ($epoch === 0 || $hmacKey !== null) {
                    $expected = AuditLogService::calculateEntryHash($row, (string) $row['previous_hash'], $hmacKey ?? '');
                    if (!hash_equals($expected, (string) $row['entry_hash'])) {
                        $errors[] = sprintf('uid %d: entry hash does not match its exported fields.', $uid);
                    }

                    ++$checked;
                } else {
                    $errors[] = sprintf('uid %d was not checked: its HMAC epoch needs the master key.', $uid);
                }

                if ($previous !== null) {
                    $this->checkNeighbours($previous, $row, $chainComplete, $floorEpoch, $errors, $notes);
                }

                $previous = $row;
            }
        } finally {
            if (is_string($hmacKey)) {
                sodium_memzero($hmacKey);
            }
        }

        if ($rows !== []) {
            $first       = $rows[array_key_first($rows)];
            $last        = $rows[array_key_last($rows)];
            $actualFirst = is_array($first) && is_int($first['uid'] ?? null) ? $first['uid'] : null;
            $actualLast  = is_array($last) && is_int($last['uid'] ?? null) ? $last['uid'] : null;
            if ($actualFirst !== $firstUid) {
                $errors[] = sprintf('The metadata declares first uid %d, the first row is uid %s.', $firstUid, $actualFirst ?? '?');
            }

            if ($actualLast !== $lastUid) {
                $errors[] = sprintf('The metadata declares last uid %d, the last row is uid %s.', $lastUid, $actualLast ?? '?');
            }
        }

        // Never "whole chain" for a file that failed anywhere else.
        $wholeChain = $errors === [] && $chainComplete && $verifiedRows !== [] && count($verifiedRows) === count($rows)
            && $this->isWholeChain($verifiedRows, $tipUid, $errors, $notes);

        // What the hash does not cover, so nobody reads a matching row as
        // proof of every column (see the evidence docs on epochs).
        if (isset($epochCounts[0]) || isset($epochCounts[1])) {
            $notes[] = 'Rows at epoch 0 and 1 bind only uid, secret_identifier, action, actor_uid, crdate and previous_hash; '
                . 'their other columns are not covered by the hash.';
        }

        if (isset($epochCounts[2])) {
            $notes[] = 'Rows at epoch 2 do not bind hmac_key_epoch, actor_type, actor_username, actor_role and request_id.';
        }

        ksort($epochCounts);

        return new AuditExportVerification($checked, $declaredCount, $errors, $epochCounts, $wholeChain, $truncated, $firstUid, $lastUid, $notes);
    }

    /**
     * Whether the export is the whole chain, judged from the rows and the
     * installation rather than from the file's own claim: the first row is the
     * genesis row, the last row is the declared tip, the installation stores
     * no newer row, and the newest external anchor neither lies beyond the
     * export nor disagrees with the exported row at its sequence. Anything that
     * cannot be checked counts against it, and so does a difference from the
     * stored row or the anchor (a rotation or migration re-seals rows). An
     * anchored uid inside the exported range that the export lacks is an
     * error: anchors are taken on rows that exist.
     *
     * @param non-empty-list<array<string, int|string>> $rows   the verified rows only
     * @param list<string>                              $errors
     * @param list<string>                              $notes
     */
    private function isWholeChain(array $rows, int $tipUid, array &$errors, array &$notes): bool
    {
        $first   = $rows[0];
        $last    = $rows[count($rows) - 1];
        $lastUid = (int) $last['uid'];

        if ($first['previous_hash'] !== '') {
            $notes[] = 'The first row does not start the chain (its previous_hash is not empty).';

            return false;
        }

        if ($tipUid !== $lastUid) {
            $notes[] = sprintf('The export ends at uid %d, not at its declared tip uid %d.', $lastUid, $tipUid);

            return false;
        }

        try {
            $anchor = $this->anchorReader->isAvailable() ? $this->anchorReader->readLatestAnchor() : null;
        } catch (Throwable $e) {
            $notes[] = 'The external anchor could not be read: ' . $e->getMessage();

            return false;
        }

        if ($anchor instanceof ChainTipAnchor && !$anchor->isEmpty()) {
            if ($anchor->sequence > $lastUid) {
                $notes[] = sprintf('The newest external anchor is at uid %d, beyond the end of the export.', $anchor->sequence);

                return false;
            }

            $anchored = null;
            foreach ($rows as $row) {
                if ((int) $row['uid'] === $anchor->sequence) {
                    $anchored = $row;

                    break;
                }
            }

            if ($anchored === null && $anchor->sequence >= (int) $first['uid']) {
                $errors[] = sprintf('The external anchor was taken at uid %d, which this export lacks.', $anchor->sequence);

                return false;
            }

            if ($anchored !== null && !hash_equals($anchor->chainTip, (string) $anchored['entry_hash'])) {
                $notes[] = sprintf('uid %d differs from the external anchor taken at that uid '
                    . "(re-sealed since the anchor, or not this installation's chain).", $anchor->sequence);

                return false;
            }
        }

        try {
            $stored = $this->storedEntryHash($lastUid);
            if ($stored === null) {
                $notes[] = sprintf('This installation does not store uid %d, so the end of the export cannot be confirmed.', $lastUid);

                return false;
            }

            if (!hash_equals($stored, (string) $last['entry_hash'])) {
                // Not an error by itself: a master-key rotation or the HMAC
                // migration re-seals every stored row. Tampering with the row
                // fails its own hash check.
                $notes[] = sprintf('uid %d carries a different entry hash than the row this installation stores '
                    . "(re-sealed since the export, or not this installation's chain).", $lastUid);

                return false;
            }

            $newer = $this->countNewerThan($lastUid);
            if ($newer > 0) {
                $notes[] = sprintf('This installation stores %d entr%s after uid %d.', $newer, $newer === 1 ? 'y' : 'ies', $lastUid);

                return false;
            }
        } catch (Throwable $e) {
            $notes[] = 'The installation could not be consulted: ' . $e->getMessage();

            return false;
        }

        return true;
    }

    /**
     * Why a decoded row is not an exported row, or null when it is one: exactly
     * the exported columns, integers where the writer writes integers, strings
     * where it writes strings, `success` 0 or 1. Coercing a value instead would
     * let a file carry content no hash covers (an array where an empty string
     * was hashed, any truthy `success`).
     *
     * @param array<mixed> $row
     */
    private function shapeError(array $row): ?string
    {
        $template = self::exportRow([]);
        $missing  = array_diff(array_keys($template), array_keys($row));
        if ($missing !== []) {
            return 'lacks the column(s) ' . implode(', ', $missing);
        }

        $unknown = array_diff(array_keys($row), array_keys($template));
        if ($unknown !== []) {
            return 'carries the unknown column(s) ' . implode(', ', array_map(strval(...), $unknown));
        }

        foreach ($template as $column => $example) {
            if (is_int($example) ? !is_int($row[$column]) : !is_string($row[$column])) {
                return sprintf('has a %s in "%s", where the export writes %s', get_debug_type($row[$column]), $column, get_debug_type($example));
            }
        }

        if ($row['success'] !== 0 && $row['success'] !== 1) {
            return 'has a "success" other than 0 or 1';
        }

        return null;
    }

    /**
     * @param array<string, int|string> $previous
     * @param array<string, int|string> $row
     * @param list<string>              $errors
     * @param list<string>              $notes
     */
    private function checkNeighbours(array $previous, array $row, bool $chainComplete, int $floorEpoch, array &$errors, array &$notes): void
    {
        $previousUid = (int) $previous['uid'];
        $uid         = (int) $row['uid'];

        if ($uid <= $previousUid) {
            $errors[] = sprintf('uid %d follows uid %d: rows are not in ascending uid order.', $uid, $previousUid);

            return;
        }

        // In a complete export every row follows its predecessor in the chain,
        // gap or not. In a filtered or truncated one only rows with adjacent
        // uids are known to be neighbours.
        if ($chainComplete || $uid === $previousUid + 1) {
            if (!hash_equals((string) $previous['entry_hash'], (string) $row['previous_hash'])) {
                $errors[] = sprintf('uid %d does not link to uid %d: previous_hash differs from its entry_hash.', $uid, $previousUid);
            }
        }

        // A uid gap is tolerated only where both neighbours are proven: between
        // keyed rows the HMAC link (previous_hash is part of every keyed row's
        // MAC) proves the two rows were written one after the other, so the gap
        // is a skipped uid (a rolled-back insert), not a removed row. A keyless
        // row's hash can be recomputed by anyone, so a gap next to one proves
        // nothing - unless the installation signs with HMAC, where every
        // keyless row has already been confirmed against the stored row above.
        // Only in a file claiming the whole chain; a filtered or truncated one
        // has gaps by selection.
        if ($chainComplete && $uid !== $previousUid + 1) {
            if ($floorEpoch === 0 && ((int) $previous['hmac_key_epoch'] === 0 || (int) $row['hmac_key_epoch'] === 0)) {
                $errors[] = sprintf('uid %d to %d are not in the export, next to a keyless row whose link can be recomputed.', $previousUid + 1, $uid - 1);
            } else {
                $notes[] = sprintf('uid %d to %d are not in the chain; the keyed link across them is intact.', $previousUid + 1, $uid - 1);
            }
        }

        // A real chain never goes back to a lower epoch, in any selection of it.
        if ((int) $row['hmac_key_epoch'] < (int) $previous['hmac_key_epoch']) {
            $errors[] = sprintf(
                'uid %d: HMAC key epoch downgrade %d -> %d.',
                $uid,
                (int) $previous['hmac_key_epoch'],
                (int) $row['hmac_key_epoch'],
            );
        }
    }

    /**
     * @return Generator<int, array<string, int|string>>
     */
    private function streamRows(?AuditLogFilter $filter, int $firstUid, int $lastUid): Generator
    {
        $after = $firstUid - 1;

        do {
            $queryBuilder = $this->queryBuilder();
            $queryBuilder
                ->select('*')
                ->from(self::TABLE_NAME)
                ->where(
                    $queryBuilder->expr()->gt('uid', $queryBuilder->createNamedParameter($after, Connection::PARAM_INT)),
                    $queryBuilder->expr()->lte('uid', $queryBuilder->createNamedParameter($lastUid, Connection::PARAM_INT)),
                )
                ->orderBy('uid', 'ASC')
                ->setMaxResults(self::CHUNK_SIZE);
            if ($filter instanceof AuditLogFilter) {
                AuditLogService::applyFilterToQuery($queryBuilder, $filter);
            }

            $chunk = $queryBuilder->executeQuery()->fetchAllAssociative();
            foreach ($chunk as $row) {
                $exported = self::exportRow($row);
                $after    = (int) $exported['uid'];

                yield $exported;
            }
        } while (count($chunk) === self::CHUNK_SIZE);
    }

    private function storedEntryHash(int $uid): ?string
    {
        $queryBuilder = $this->queryBuilder();
        $value        = $queryBuilder
            ->select('entry_hash')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return is_string($value) ? $value : null;
    }

    /**
     * The stored row at $uid in export form, or null when there is none.
     *
     * @return array<string, int|string>|null
     */
    private function storedExportRow(int $uid): ?array
    {
        $queryBuilder = $this->queryBuilder();
        $row          = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchAssociative();

        return is_array($row) ? self::exportRow($row) : null;
    }

    private function countNewerThan(int $uid): int
    {
        $queryBuilder = $this->queryBuilder();
        $value        = $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->gt('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)))
            ->executeQuery()
            ->fetchOne();

        return is_numeric($value) ? (int) $value : 0;
    }

    private function countUpTo(?AuditLogFilter $filter, int $tipUid): int
    {
        $queryBuilder = $this->queryBuilder();
        $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->lte('uid', $queryBuilder->createNamedParameter($tipUid, Connection::PARAM_INT)));
        if ($filter instanceof AuditLogFilter) {
            AuditLogService::applyFilterToQuery($queryBuilder, $filter);
        }

        $value = $queryBuilder->executeQuery()->fetchOne();

        return is_numeric($value) ? (int) $value : 0;
    }

    /**
     * @param 'MAX'|'MIN' $function
     * @param int|null    $tipUid   null: no upper bound (the tip query itself;
     *                              PostgreSQL rejects PHP_INT_MAX for an int column)
     */
    private function aggregateUid(string $function, ?AuditLogFilter $filter, ?int $tipUid): int
    {
        $queryBuilder = $this->queryBuilder();
        $queryBuilder
            ->selectLiteral(sprintf('%s(uid)', $function))
            ->from(self::TABLE_NAME);
        if ($tipUid !== null) {
            $queryBuilder->where($queryBuilder->expr()->lte('uid', $queryBuilder->createNamedParameter($tipUid, Connection::PARAM_INT)));
        }

        if ($filter instanceof AuditLogFilter) {
            AuditLogService::applyFilterToQuery($queryBuilder, $filter);
        }

        $value = $queryBuilder->executeQuery()->fetchOne();

        return is_numeric($value) ? (int) $value : 0;
    }

    private function nthNewestUid(?AuditLogFilter $filter, int $tipUid, int $n): int
    {
        $queryBuilder = $this->queryBuilder();
        $queryBuilder
            ->select('uid')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->lte('uid', $queryBuilder->createNamedParameter($tipUid, Connection::PARAM_INT)))
            ->orderBy('uid', 'DESC')
            ->setFirstResult($n - 1)
            ->setMaxResults(1);
        if ($filter instanceof AuditLogFilter) {
            AuditLogService::applyFilterToQuery($queryBuilder, $filter);
        }

        $value = $queryBuilder->executeQuery()->fetchOne();

        return is_numeric($value) ? (int) $value : 0;
    }

    private function queryBuilder(): QueryBuilder
    {
        $queryBuilder = $this->connectionPool->getConnectionForTable(self::TABLE_NAME)->createQueryBuilder();
        $queryBuilder->getRestrictions()->removeAll();

        return $queryBuilder;
    }
}
