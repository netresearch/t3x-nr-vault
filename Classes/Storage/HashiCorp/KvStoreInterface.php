<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\HashiCorp;

/**
 * The three KV v2 operations the storage adapter needs, addressed by secret
 * identifier. The implementation owns path construction, authentication and
 * transport; the adapter owns what is stored.
 */
interface KvStoreInterface
{
    /**
     * @return array<string, mixed>|null The stored key/value data, or null when
     *                                   the key does not exist
     */
    public function read(string $identifier): ?array;

    /**
     * Write a new version of the key.
     *
     * @param array<string, mixed> $data
     */
    public function write(string $identifier, array $data): void;

    /**
     * Remove the key with every version. A key that does not exist is not an
     * error, so a delete can be repeated.
     */
    public function destroy(string $identifier): void;

    /**
     * The path the key lives at, for the registry row's external reference.
     */
    public function reference(string $identifier): string;
}
