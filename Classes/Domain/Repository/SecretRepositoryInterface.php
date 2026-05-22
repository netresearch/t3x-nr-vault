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

    public function findByUid(int $uid): ?Secret;

    public function exists(string $identifier): bool;

    /**
     * Persist the Secret. Returns the (possibly new) Secret instance.
     * On INSERT, the returned instance carries the freshly-assigned
     * UID; on UPDATE, the original is returned unchanged. Callers must
     * use the return value if they need the populated UID — the input
     * is readonly and cannot be mutated in place.
     */
    public function save(Secret $secret): Secret;

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
