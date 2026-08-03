<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Adapter;

use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;

/**
 * Interface for vault storage adapters.
 */
interface VaultAdapterInterface
{
    /**
     * Get the adapter identifier.
     *
     * @return string e.g., "local", "hashicorp", "aws"
     */
    public function getIdentifier(): string;

    /**
     * Check if the adapter is available and configured.
     */
    public function isAvailable(): bool;

    /**
     * Store a secret. Returns the persisted instance; on INSERT this
     * carries the newly-assigned UID (the input has uid=null), on
     * UPDATE the original is returned unchanged. Callers that dispatch
     * events about the just-stored secret MUST use the return value so
     * downstream consumers see the populated UID.
     *
     * `$persistGroupRelations` declares whether the group tiers carried by
     * `$secret` are authoritative for this write. Pass `false` when they
     * were merely round-tripped from a read that may not have seen the
     * record's complete relations — the stored tiers are then left exactly
     * as they are instead of being replaced with an incomplete list.
     */
    public function store(Secret $secret, bool $persistGroupRelations = true): Secret;

    /**
     * Retrieve a secret by identifier.
     *
     * Honours the storage backend's availability flag: a disabled secret is
     * NOT returned here, which is how disabling revokes access to the value
     * everywhere at once.
     */
    public function retrieve(string $identifier): ?Secret;

    /**
     * Retrieve a secret by identifier INCLUDING a disabled one.
     *
     * The administrative counterpart of {@see retrieve()}, for the operations
     * that must still reach a disabled secret — re-enabling, rotating,
     * deleting it, showing its metadata. A secret removed for good (soft
     * delete) stays invisible.
     *
     * Callers on a path that returns plaintext MUST use `retrieve()`: the
     * whole effect of disabling a secret is that this lookup and that one give
     * different answers.
     */
    public function retrieveIncludingDisabled(string $identifier): ?Secret;

    /**
     * Set a secret's availability, addressed by UID.
     *
     * The targeted counterpart of {@see store()} for the availability flag
     * alone: the backend writes that flag (and its record timestamp), nothing
     * else. The distinction is not cosmetic — `store()` persists every scalar
     * field of the entity handed to it, so a value or read-count update that
     * committed since that entity was read would be overwritten with the stale
     * copy. An availability change must not do that: it changes nothing but
     * whether the secret is in service.
     */
    public function setHidden(int $uid, bool $hidden): void;

    /**
     * Delete a secret.
     */
    public function delete(string $identifier): void;

    /**
     * Check if secret exists.
     */
    public function exists(string $identifier): bool;

    /**
     * List all secret identifiers.
     *
     * @return string[]
     */
    public function list(?SecretFilters $filters = null): array;

    /**
     * List all secrets matching filters with groups batch-loaded.
     *
     * @return Secret[]
     */
    public function listSecrets(?SecretFilters $filters = null): array;

    /**
     * Get metadata for a secret without decrypting value.
     *
     * @return array<string, mixed>|null
     */
    public function getMetadata(string $identifier): ?array;

    /**
     * Merge into a secret's metadata without changing the secret value.
     *
     * "Without changing the value" is a requirement on the write, not just a
     * description of the arguments: an implementation that persists a whole
     * entity to change one column restores the envelope, version and read
     * counters from the read it started with, undoing anything that committed
     * in between. Write the metadata alone — see {@see setHidden()} for the
     * same rule on the availability flag.
     *
     * @param array<string, mixed> $metadata
     */
    public function updateMetadata(string $identifier, array $metadata): void;

    /**
     * Increment read count and update last_read_at atomically.
     */
    public function incrementReadCount(int $uid): void;
}
