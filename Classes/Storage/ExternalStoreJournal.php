<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage;

/**
 * What the external-store adapters did for a secret in this request, so that a
 * later compensation (the audit write failed) can undo exactly that: destroy a
 * secret the adapter created, or put back one it took over. Memory only; it
 * lives as long as the request or CLI run.
 *
 * @internal
 */
final class ExternalStoreJournal
{
    /** @var array<string, array{previous: array<string, mixed>|null, version: int|string|null}> */
    private array $entries = [];

    /**
     * @param array<string, mixed>|null $previous The payload taken over, or null when the secret was created
     */
    public function remember(string $adapter, string $identifier, ?array $previous, int|string|null $version): void
    {
        $this->entries[$adapter . '/' . $identifier] = ['previous' => $previous, 'version' => $version];
    }

    /**
     * @return array{previous: array<string, mixed>|null, version: int|string|null}|null
     */
    public function take(string $adapter, string $identifier): ?array
    {
        $key   = $adapter . '/' . $identifier;
        $entry = $this->entries[$key] ?? null;
        unset($this->entries[$key]);

        return $entry;
    }

    public function forget(string $adapter, string $identifier): void
    {
        unset($this->entries[$adapter . '/' . $identifier]);
    }
}
