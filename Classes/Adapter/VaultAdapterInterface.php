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
     */
    public function store(Secret $secret): Secret;

    /**
     * Retrieve a secret by identifier.
     */
    public function retrieve(string $identifier): ?Secret;

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
     * Update metadata without changing the secret value.
     *
     * @param array<string, mixed> $metadata
     */
    public function updateMetadata(string $identifier, array $metadata): void;

    /**
     * Increment read count and update last_read_at atomically.
     */
    public function incrementReadCount(int $uid): void;
}
