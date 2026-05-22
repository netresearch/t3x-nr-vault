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

/**
 * Repository for secret entities.
 */
final readonly class SecretRepository implements SecretRepositoryInterface
{
    private const TABLE_NAME = 'tx_nrvault_secret';

    private const MM_TABLE_NAME = 'tx_nrvault_secret_begroups_mm';

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
        $groups = $this->loadGroupsForSecret(is_numeric($uid) ? (int) $uid : 0);

        return Secret::fromDatabaseRow($row, $groups);
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

        return Secret::fromDatabaseRow($row, $this->loadGroupsForSecret($uid));
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
     */
    public function save(Secret $secret): Secret
    {
        $connection = $this->getConnection();
        $data = $secret->toDatabaseRow();

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

        // Update MM table for groups
        $this->saveGroupsForSecret($secret);

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
                $queryBuilder->andWhere(
                    $queryBuilder->expr()->like('identifier', $queryBuilder->createNamedParameter($filters->prefix . '%')),
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
            $identifier = $row['identifier'] ?? '';
            $identifiers[] = \is_string($identifier) ? $identifier : '';
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

        $connection = $this->getConnection();

        // Find secret UIDs that have any of the specified groups
        $mmQuery = $connection->createQueryBuilder();
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
        $queryBuilder = $connection->createQueryBuilder();
        $rows = $queryBuilder
            ->select('*')
            ->from(self::TABLE_NAME)
            ->where(
                $queryBuilder->expr()->in('uid', $intSecretUids),
                $queryBuilder->expr()->eq('deleted', 0),
            )
            ->executeQuery()
            ->fetchAllAssociative();

        $secrets = [];
        foreach ($rows as $row) {
            $rowUid = $row['uid'] ?? 0;
            $groups = $this->loadGroupsForSecret(is_numeric($rowUid) ? (int) $rowUid : 0);
            $secrets[] = Secret::fromDatabaseRow($row, $groups);
        }

        return $secrets;
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

        return array_map(Secret::fromDatabaseRow(...), $rows);
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

        return array_map(Secret::fromDatabaseRow(...), $rows);
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
                $queryBuilder->andWhere(
                    $queryBuilder->expr()->like('identifier', $queryBuilder->createNamedParameter($filters->prefix . '%')),
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

        if ($rows === []) {
            return [];
        }

        // Collect all UIDs and batch-load MM groups in ONE query so each
        // Secret can be constructed with its allowed-groups list already
        // populated — readonly entity has no post-construction mutator.
        $rowsByUid = [];
        $uids = [];
        foreach ($rows as $row) {
            $uid = $row['uid'] ?? 0;
            $intUid = is_numeric($uid) ? (int) $uid : 0;
            if ($intUid > 0) {
                $rowsByUid[$intUid] = $row;
                $uids[] = $intUid;
            }
        }

        $groupsBySecret = $uids !== [] ? $this->loadGroupsForSecrets($uids) : [];

        $secrets = [];
        foreach ($rowsByUid as $uid => $row) {
            $secrets[] = Secret::fromDatabaseRow($row, $groupsBySecret[$uid] ?? []);
        }

        return $secrets;
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
     * Batch-load groups for multiple secrets from MM table.
     *
     * @param int[] $secretUids
     *
     * @return array<int, int[]> Map of secret UID to group UIDs
     */
    private function loadGroupsForSecrets(array $secretUids): array
    {
        if ($secretUids === []) {
            return [];
        }

        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $rows = $queryBuilder
            ->select('uid_local', 'uid_foreign')
            ->from(self::MM_TABLE_NAME)
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
     * Load groups for a secret from MM table.
     *
     * @return int[]
     */
    private function loadGroupsForSecret(int $secretUid): array
    {
        $queryBuilder = $this->getConnection()->createQueryBuilder();
        $rows = $queryBuilder
            ->select('uid_foreign')
            ->from(self::MM_TABLE_NAME)
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
     * Save groups for a secret to MM table.
     */
    private function saveGroupsForSecret(Secret $secret): void
    {
        if ($secret->getUid() === null) {
            return;
        }

        $connection = $this->getConnection();

        // Delete existing relations
        $connection->delete(self::MM_TABLE_NAME, ['uid_local' => $secret->getUid()]);

        // Insert new relations
        $groups = $secret->getAllowedGroups();
        foreach ($groups as $sorting => $groupUid) {
            $connection->insert(self::MM_TABLE_NAME, [
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
}
