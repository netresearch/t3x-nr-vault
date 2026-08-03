<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Repository;

use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Query\Restriction\HiddenRestriction;

/**
 * Repository for secret entities.
 */
final readonly class SecretRepository implements SecretRepositoryInterface
{
    private const TABLE_NAME = 'tx_nrvault_secret';

    private const MM_TABLE_NAME = 'tx_nrvault_secret_begroups_mm';

    private const MM_WRITE_TABLE_NAME = 'tx_nrvault_secret_writegroups_mm';

    public function __construct(
        private ConnectionPool $connectionPool,
    ) {}

    public function findByIdentifier(string $identifier): ?Secret
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $row = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq('deleted', 0),
            )
            ->executeQuery()
            ->fetchAssociative();

        if ($row === false) {
            return null;
        }

        $uid = $row['uid'] ?? 0;
        $intUid = is_numeric($uid) ? (int) $uid : 0;

        return Secret::fromDatabaseRow(
            $row,
            $this->loadGroupsForSecret($intUid),
            $this->loadGroupsForSecret($intUid, self::MM_WRITE_TABLE_NAME),
        );
    }

    public function findByUid(int $uid): ?Secret
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $row = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)),
                $queryBuilder->expr()->eq('deleted', 0),
            )
            ->executeQuery()
            ->fetchAssociative();

        if ($row === false) {
            return null;
        }

        return Secret::fromDatabaseRow(
            $row,
            $this->loadGroupsForSecret($uid),
            $this->loadGroupsForSecret($uid, self::MM_WRITE_TABLE_NAME),
        );
    }

    /**
     * Resolve a secret by UID INCLUDING one that is disabled.
     *
     * The counterpart of {@see findByUid()} for the write-path guards that
     * must judge a record they are about to change or remove. Everything
     * else, the plaintext read path above all, keeps using `findByUid()`.
     *
     * That split is the whole point, so exactly one restriction is lifted and
     * named: `HiddenRestriction`, the one TCA's `enablecolumns.disabled`
     * mapping binds to the `hidden` column. `removeAll()` is deliberately NOT
     * used — it would also discard `DeletedRestriction`, and a lookup that
     * hands back soft-deleted rows would turn an `undelete` guard into the
     * thing that resurrects them. `findByUid()` is left untouched for the
     * same reason: widening it would switch the control off rather than work
     * around it.
     */
    public function findByUidIncludingDisabled(int $uid): ?Secret
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $queryBuilder->getRestrictions()->removeByType(HiddenRestriction::class);
        $row = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($uid, Connection::PARAM_INT)),
                $queryBuilder->expr()->eq('deleted', 0),
            )
            ->executeQuery()
            ->fetchAssociative();

        if ($row === false) {
            return null;
        }

        return Secret::fromDatabaseRow(
            $row,
            $this->loadGroupsForSecret($uid),
            $this->loadGroupsForSecret($uid, self::MM_WRITE_TABLE_NAME),
        );
    }

    public function exists(string $identifier): bool
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $count = $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq('identifier', $queryBuilder->createNamedParameter($identifier)),
                $queryBuilder->expr()->eq('deleted', 0),
            )
            ->executeQuery()
            ->fetchOne();

        return (is_numeric($count) ? (int) $count : 0) > 0;
    }

    /**
     * Persist the Secret. Returns a (possibly new) Secret instance — on
     * INSERT, the returned instance carries the freshly-assigned UID from
     * `lastInsertId()`; on UPDATE the original instance is returned
     * unchanged. Callers MUST use the returned value if they need the
     * UID after save (it cannot be set on the readonly input).
     *
     * With `$persistGroupRelations = false` the record's two group tiers
     * are left untouched, MM relation rows and count columns alike. Both
     * halves matter: writing the count of an entity whose tier list is
     * incomplete, while skipping the MM write that would make the count
     * true, produces a row claiming fewer groups than it grants — the
     * inconsistency this option exists to avoid, not a milder form of it.
     */
    public function save(Secret $secret, bool $persistGroupRelations = true): Secret
    {
        $connection = $this->getConnection();
        $data = $secret->toDatabaseRow();

        if (!$persistGroupRelations) {
            unset($data['allowed_groups'], $data['write_groups']);
        }

        if ($secret->getUid() === null) {
            // Insert new secret
            $data['crdate'] = time();
            $connection->insert(self::TABLE_NAME, $data);
            $lastId = $connection->lastInsertId();
            $secret = $secret->withUid(is_numeric($lastId) ? (int) $lastId : 0);
        } else {
            // Update existing secret
            $connection->update(
                self::TABLE_NAME,
                $data,
                ['uid' => $secret->getUid()],
            );
        }

        // Update MM tables for the read-tier and write-tier groups.
        if ($persistGroupRelations) {
            $this->saveGroupsForSecret($secret, self::MM_TABLE_NAME, $secret->getAllowedGroups());
            $this->saveGroupsForSecret($secret, self::MM_WRITE_TABLE_NAME, $secret->getWriteGroups());
        }

        return $secret;
    }

    public function delete(Secret $secret): void
    {
        if ($secret->getUid() === null) {
            return;
        }

        // Soft delete
        $this->getConnection()->update(
            self::TABLE_NAME,
            ['deleted' => 1, 'tstamp' => time()],
            ['uid' => $secret->getUid()],
        );
    }

    /**
     * Find all secrets matching filters.
     *
     * @return string[]
     */
    public function findIdentifiers(?SecretFilters $filters = null): array
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $queryBuilder
            ->select('identifier')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->eq('deleted', 0));

        if ($filters instanceof SecretFilters) {
            if ($filters->owner !== null) {
                $queryBuilder->andWhere(
                    $queryBuilder->expr()->eq('owner_uid', $queryBuilder->createNamedParameter($filters->owner, Connection::PARAM_INT)),
                );
            }

            if ($filters->prefix !== null) {
                // Escape LIKE metacharacters (% and _) in the caller-supplied
                // prefix so they match literally, then append the trailing
                // wildcard ourselves (SEC-INJECTION-LEAK-1).
                $escapedPrefix = $queryBuilder->escapeLikeWildcards($filters->prefix);
                $queryBuilder->andWhere(
                    $queryBuilder->expr()->like('identifier', $queryBuilder->createNamedParameter($escapedPrefix . '%')),
                );
            }

            if ($filters->context !== null) {
                $queryBuilder->andWhere(
                    $queryBuilder->expr()->eq('context', $queryBuilder->createNamedParameter($filters->context)),
                );
            }

            if ($filters->scopePid !== null) {
                $queryBuilder->andWhere(
                    $queryBuilder->expr()->eq('scope_pid', $queryBuilder->createNamedParameter($filters->scopePid, Connection::PARAM_INT)),
                );
            }
        }

        $queryBuilder->orderBy('identifier', 'ASC');

        $result = $queryBuilder->executeQuery();
        $identifiers = [];

        while ($row = $result->fetchAssociative()) {
            $identifier = $row['identifier'] ?? null;
            // Skip rows whose identifier is not a non-empty string (driver/schema
            // anomaly). Emitting '' here would inject a bogus empty identifier
            // into callers (list views, rotation loops), so drop it instead.
            if (!\is_string($identifier)) {
                continue;
            }
            if ($identifier === '') {
                continue;
            }

            $identifiers[] = $identifier;
        }

        return $identifiers;
    }

    /**
     * Find all secrets accessible by specific groups.
     *
     * @param int[] $groupUids
     *
     * @return Secret[]
     */
    public function findByGroups(array $groupUids): array
    {
        if ($groupUids === []) {
            return [];
        }

        // First query hits the MM table — must use the MM connection.
        $mmQuery = $this->getMmConnection()->createQueryBuilder();
        $intGroupUids = [];
        foreach ($groupUids as $gid) {
            $intGroupUids[] = (int) $gid;
        }
        $secretUids = $mmQuery
            ->select('DISTINCT uid_local')
            ->from(self::MM_TABLE_NAME)
            ->where($mmQuery->expr()->in('uid_foreign', $intGroupUids))
            ->executeQuery()
            ->fetchFirstColumn();

        if ($secretUids === []) {
            return [];
        }

        $intSecretUids = [];
        foreach ($secretUids as $sid) {
            $intSecretUids[] = is_numeric($sid) ? (int) $sid : 0;
        }

        // Second query hits the secret table — uses the main connection.
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $rows = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->in('uid', $intSecretUids),
                $queryBuilder->expr()->eq('deleted', 0),
            )
            ->executeQuery()
            ->fetchAllAssociative();

        // Batch-load both group tiers in a constant number of queries
        // instead of one-per-row (PERFORMANCE-2).
        return $this->hydrateRowsWithGroups($rows);
    }

    /**
     * Find expired secrets.
     *
     * @return Secret[]
     */
    public function findExpired(): array
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $rows = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->gt('expires_at', 0),
                $queryBuilder->expr()->lt('expires_at', time()),
                $queryBuilder->expr()->eq('deleted', 0),
            )
            ->executeQuery()
            ->fetchAllAssociative();

        return $this->hydrateRowsWithGroups($rows);
    }

    /**
     * Find secrets expiring within given days.
     *
     * @return Secret[]
     */
    public function findExpiringSoon(int $days): array
    {
        $now = time();
        $future = $now + ($days * 86400);

        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $rows = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->gt('expires_at', $now),
                $queryBuilder->expr()->lte('expires_at', $future),
                $queryBuilder->expr()->eq('deleted', 0),
            )
            ->orderBy('expires_at', 'ASC')
            ->executeQuery()
            ->fetchAllAssociative();

        return $this->hydrateRowsWithGroups($rows);
    }

    /**
     * Count all active secrets.
     */
    public function countAll(): int
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();

        $count = $queryBuilder
            ->count('uid')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->eq('deleted', 0))
            ->executeQuery()
            ->fetchOne();

        return is_numeric($count) ? (int) $count : 0;
    }

    /**
     * Find all secrets matching filters with groups batch-loaded.
     *
     * @return Secret[]
     */
    public function findAllWithFilters(?SecretFilters $filters = null): array
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where($queryBuilder->expr()->eq('deleted', 0));

        if ($filters instanceof SecretFilters) {
            if ($filters->owner !== null) {
                $queryBuilder->andWhere(
                    $queryBuilder->expr()->eq('owner_uid', $queryBuilder->createNamedParameter($filters->owner, Connection::PARAM_INT)),
                );
            }

            if ($filters->prefix !== null) {
                // Escape LIKE metacharacters (% and _) in the caller-supplied
                // prefix so they match literally, then append the trailing
                // wildcard ourselves (SEC-INJECTION-LEAK-1).
                $escapedPrefix = $queryBuilder->escapeLikeWildcards($filters->prefix);
                $queryBuilder->andWhere(
                    $queryBuilder->expr()->like('identifier', $queryBuilder->createNamedParameter($escapedPrefix . '%')),
                );
            }

            if ($filters->context !== null) {
                $queryBuilder->andWhere(
                    $queryBuilder->expr()->eq('context', $queryBuilder->createNamedParameter($filters->context)),
                );
            }

            if ($filters->scopePid !== null) {
                $queryBuilder->andWhere(
                    $queryBuilder->expr()->eq('scope_pid', $queryBuilder->createNamedParameter($filters->scopePid, Connection::PARAM_INT)),
                );
            }
        }

        $queryBuilder->orderBy('identifier', 'ASC');

        $rows = $queryBuilder->executeQuery()->fetchAllAssociative();

        return $this->hydrateRowsWithGroups($rows);
    }

    /**
     * Find a window of active secrets ordered by UID, for memory-bounded
     * batch processing (e.g. the orphan-cleanup scheduler task). Returns
     * up to `$limit` secrets whose UID is strictly greater than
     * `$afterUid`; pass the last returned UID back as `$afterUid` to fetch
     * the next page. An empty result signals the end of the table
     * (PERFORMANCE-8).
     *
     * @return Secret[]
     */
    public function findPaginatedAfterUid(int $afterUid, int $limit): array
    {
        if ($limit < 1) {
            return [];
        }

        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $rows = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->eq('deleted', 0),
                $queryBuilder->expr()->gt('uid', $queryBuilder->createNamedParameter($afterUid, Connection::PARAM_INT)),
            )
            ->orderBy('uid', 'ASC')
            ->setMaxResults($limit)
            ->executeQuery()
            ->fetchAllAssociative();

        return $this->hydrateRowsWithGroups($rows);
    }

    /**
     * Increment read count and update last_read_at atomically without full entity save.
     */
    public function incrementReadCount(int $uid): void
    {
        $this->getConnection()->executeStatement(
            'UPDATE ' . self::TABLE_NAME . ' SET read_count = read_count + 1, last_read_at = ? WHERE uid = ?',
            [time(), $uid],
            [Connection::PARAM_INT, Connection::PARAM_INT],
        );
    }

    /**
     * Hydrate secret rows into Secret objects, batch-loading both group
     * tiers (read + write) in a constant number of MM queries regardless
     * of the number of rows. Preserves the input row order and duplicates,
     * matching the SELECT's ORDER BY contract.
     *
     * @param array<int, array<string, mixed>> $rows
     *
     * @return Secret[]
     */
    private function hydrateRowsWithGroups(array $rows): array
    {
        if ($rows === []) {
            return [];
        }

        // Collect distinct UIDs once, then batch-load each group tier in a
        // single query so a readonly Secret can be built with its lists
        // already populated (it has no post-construction mutator).
        $uids = [];
        foreach ($rows as $row) {
            $uid = $row['uid'] ?? 0;
            $intUid = is_numeric($uid) ? (int) $uid : 0;
            if ($intUid > 0) {
                $uids[$intUid] = true;
            }
        }

        $uidList = array_keys($uids);
        $readGroupsBySecret = $uidList !== [] ? $this->loadGroupsForSecrets($uidList, self::MM_TABLE_NAME) : [];
        $writeGroupsBySecret = $uidList !== [] ? $this->loadGroupsForSecrets($uidList, self::MM_WRITE_TABLE_NAME) : [];

        $secrets = [];
        foreach ($rows as $row) {
            $uid = $row['uid'] ?? 0;
            $intUid = is_numeric($uid) ? (int) $uid : 0;
            $secrets[] = Secret::fromDatabaseRow(
                $row,
                $readGroupsBySecret[$intUid] ?? [],
                $writeGroupsBySecret[$intUid] ?? [],
            );
        }

        return $secrets;
    }

    /**
     * Batch-load groups for multiple secrets from a given MM table.
     *
     * @param int[] $secretUids
     * @param string $mmTable One of the MM relation tables (read/write tier)
     *
     * @return array<int, int[]> Map of secret UID to group UIDs
     */
    private function loadGroupsForSecrets(array $secretUids, string $mmTable = self::MM_TABLE_NAME): array
    {
        if ($secretUids === []) {
            return [];
        }

        $queryBuilder = $this->getMmConnection($mmTable)->createQueryBuilder();
        $rows = $queryBuilder
            ->select('uid_local', 'uid_foreign')
            ->from($mmTable)
            ->where($queryBuilder->expr()->in('uid_local', $secretUids))
            ->orderBy('uid_local', 'ASC')
            ->addOrderBy('sorting', 'ASC')
            ->executeQuery()
            ->fetchAllAssociative();

        $groupsBySecret = [];
        foreach ($rows as $row) {
            $uidLocal = $row['uid_local'] ?? 0;
            $uidForeign = $row['uid_foreign'] ?? 0;
            $groupsBySecret[is_numeric($uidLocal) ? (int) $uidLocal : 0][] = is_numeric($uidForeign) ? (int) $uidForeign : 0;
        }

        return $groupsBySecret;
    }

    /**
     * Load groups for a single secret from a given MM table.
     *
     * @param string $mmTable One of the MM relation tables (read/write tier)
     *
     * @return int[]
     */
    private function loadGroupsForSecret(int $secretUid, string $mmTable = self::MM_TABLE_NAME): array
    {
        $queryBuilder = $this->getMmConnection($mmTable)->createQueryBuilder();
        $rows = $queryBuilder
            ->select('uid_foreign')
            ->from($mmTable)
            ->where($queryBuilder->expr()->eq('uid_local', $secretUid))
            ->orderBy('sorting', 'ASC')
            ->executeQuery()
            ->fetchAllAssociative();

        $groups = [];
        foreach ($rows as $row) {
            $uidForeign = $row['uid_foreign'] ?? 0;
            $groups[] = is_numeric($uidForeign) ? (int) $uidForeign : 0;
        }

        return $groups;
    }

    /**
     * Save a group tier for a secret to its MM table (delete-then-insert).
     *
     * @param string $mmTable One of the MM relation tables (read/write tier)
     * @param int[] $groups Group UIDs to persist for this tier
     */
    private function saveGroupsForSecret(Secret $secret, string $mmTable, array $groups): void
    {
        if ($secret->getUid() === null) {
            return;
        }

        $mmConnection = $this->getMmConnection($mmTable);

        // Delete existing relations
        $mmConnection->delete($mmTable, ['uid_local' => $secret->getUid()]);

        // Insert new relations
        foreach ($groups as $sorting => $groupUid) {
            $mmConnection->insert($mmTable, [
                'uid_local' => $secret->getUid(),
                'uid_foreign' => $groupUid,
                'sorting' => $sorting,
                'sorting_foreign' => 0,
            ]);
        }
    }

    private function getConnection(): Connection
    {
        return $this->connectionPool->getConnectionForTable(self::TABLE_NAME);
    }

    /**
     * Resolve the connection for an MM-relations table separately from the
     * main secret table. TYPO3 routes per-table connections via
     * `$GLOBALS['TYPO3_CONF_VARS']['DB']['TableMapping']` (the connection
     * targets themselves live under `['DB']['Connections']`). On the common
     * single-DB setup all tables map to `Default`, so this returns the same
     * connection as `getConnection()` — the indirection only matters on
     * sharded setups, where an admin may have mapped an MM table to a
     * different DB. The original code lost that distinction; MM operations
     * issued via the secret-table connection would have hit the wrong DB.
     */
    private function getMmConnection(string $mmTable = self::MM_TABLE_NAME): Connection
    {
        return $this->connectionPool->getConnectionForTable($mmTable);
    }
}
