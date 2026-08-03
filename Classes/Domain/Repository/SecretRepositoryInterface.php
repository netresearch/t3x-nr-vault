<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Repository;

use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;

/**
 * Interface for secret repository operations.
 */
interface SecretRepositoryInterface
{
    public function findByIdentifier(string $identifier): ?Secret;

    /**
     * Resolve a secret by identifier INCLUDING one that is disabled
     * (`hidden = 1`), which {@see findByIdentifier()} deliberately cannot see.
     *
     * Reserved for administrative operations that must still reach a disabled
     * record — re-enabling, rotation, deletion, metadata display. Soft-deleted
     * records stay invisible here; only the enable columns are given up. Never
     * use this on a path that returns plaintext: disabling a secret revokes
     * access precisely because the enable-column restriction removes it from
     * the read path's query.
     */
    public function findByIdentifierIncludingDisabled(string $identifier): ?Secret;

    public function findByUid(int $uid): ?Secret;

    public function exists(string $identifier): bool;

    /**
     * Persist the Secret. Returns the (possibly new) Secret instance.
     * On INSERT, the returned instance carries the freshly-assigned
     * UID; on UPDATE, the original is returned unchanged. Callers must
     * use the return value if they need the populated UID — the input
     * is readonly and cannot be mutated in place.
     *
     * `$persistGroupRelations` declares whether the entity's two group
     * tiers are authoritative for this write. With `false` the record
     * keeps the tiers it already has: neither the MM relation rows nor the
     * `allowed_groups`/`write_groups` columns mirroring their count are
     * touched. Callers pass `false` when the tiers were only round-tripped
     * from a read that may not have seen the record's complete relations.
     */
    public function save(Secret $secret, bool $persistGroupRelations = true): Secret;

    public function delete(Secret $secret): void;

    /**
     * @return list<string>
     */
    public function findIdentifiers(?SecretFilters $filters = null): array;

    /**
     * Find all secrets matching filters with groups batch-loaded.
     *
     * @return Secret[]
     */
    public function findAllWithFilters(?SecretFilters $filters = null): array;

    /**
     * Find a window of active secrets ordered by UID, for memory-bounded
     * batch processing. Returns up to `$limit` secrets whose UID is
     * strictly greater than `$afterUid`. An empty result signals the end
     * of the table.
     *
     * @return Secret[]
     */
    public function findPaginatedAfterUid(int $afterUid, int $limit): array;

    /**
     * Find all secrets accessible by specific groups.
     *
     * @param int[] $groupUids
     *
     * @return Secret[]
     */
    public function findByGroups(array $groupUids): array;

    /**
     * Find expired secrets.
     *
     * @return Secret[]
     */
    public function findExpired(): array;

    /**
     * Find secrets expiring within given days.
     *
     * @return Secret[]
     */
    public function findExpiringSoon(int $days): array;

    /**
     * Count all active secrets.
     */
    public function countAll(): int;

    /**
     * Increment read count and update last_read_at atomically.
     */
    public function incrementReadCount(int $uid): void;
}
