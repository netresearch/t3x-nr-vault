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
     * @throws HashiCorpException With code 1794400013 when the key exists
     */
    public function create(string $identifier, array $data): void;
}
