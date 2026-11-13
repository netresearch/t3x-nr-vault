<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage\HashiCorp;

use Netresearch\NrVault\Exception\HashiCorpException;

/**
 * A KV store that can create a key only when it does not exist yet, in one
 * request.
 *
 * The adapter needs that to claim a path for a new secret without a window
 * between "is the path empty" and "write to it": a key created by somebody else
 * in that window is refused instead of overwritten. KV v2 offers it as a
 * check-and-set write with `cas=0`.
 *
 * Every write reports the KV version it created, and a rollback is a
 * check-and-set against exactly that version, so Vault applies it only when
 * nobody has written since. No payload is compared.
 *
 * Implementing only {@see KvStoreInterface} is deprecated: the adapter then
 * falls back to a read followed by a write, which leaves that window open, and
 * triggers a deprecation. Version 2.0 will require this interface.
 */
interface AtomicKvStoreInterface extends KvStoreInterface
{
    /**
     * Write the first version of the key, only when the key does not exist.
     *
     * @param array<string, mixed> $data
     *
     * @return int The KV version created
     *
     * @throws HashiCorpException With code 1794400013 when the key exists
     */
    public function create(string $identifier, array $data): int;

    /**
     * Write a new version of the key.
     *
     * @param array<string, mixed> $data
     *
     * @return int The KV version created
     */
    public function writeVersioned(string $identifier, array $data): int;

    /**
     * Write the data as a new version only while the key is still at the given
     * version (check-and-set), to take back a write of this call.
     *
     * @param array<string, mixed> $data
     *
     * @return bool False when somebody wrote since; nothing was changed then
     */
    public function restoreIfCurrent(string $identifier, array $data, int $version): bool;

    /**
     * Remove the key with every version, but only while it is still at the
     * given version, to take back a create of this call. The version is checked
     * immediately before the delete; KV v2 has no conditional delete, so a
     * write landing in that gap is not detected.
     *
     * @return bool False when the key is gone or somebody wrote since
     */
    public function destroyIfCurrent(string $identifier, int $version): bool;
}
