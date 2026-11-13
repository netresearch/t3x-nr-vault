<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Adapter;

/**
 * An adapter that can take back what its own `store()` did for a new secret,
 * which is not always "delete it": a secret that `store()` took over from an
 * unreferenced earlier write has to be put back, not destroyed.
 *
 * {@see \Netresearch\NrVault\Service\VaultService} calls it when the audit write
 * of a create fails, in place of `delete()`, for an adapter that implements it.
 */
interface CreateCompensatingAdapterInterface
{
    /**
     * Take back the last `store()` of this identifier in this request: remove
     * what it created or put back what it took over, then remove the registry
     * row. Without a record of such a store it behaves like `delete()`.
     */
    public function compensateCreate(string $identifier): void;
}
