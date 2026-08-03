<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures;

use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;

/**
 * A real vault adapter with one addition: every administrative lookup commits
 * a read-count increment before handing the record back.
 *
 * That reproduces, deterministically and in one process, the interleaving that
 * makes the difference between a targeted write and a full-row save
 * observable: another request calls `retrieve()` and commits its
 * `read_count = read_count + 1` AFTER a mutation read the record and BEFORE it
 * writes. A write that persists every scalar column then restores the entity's
 * stale copy of that counter — the concurrent commit is lost — while a write
 * that touches only the column it means to change leaves it alone.
 *
 * `retrieveIncludingDisabled()` is the hook because it is the lookup
 * {@see \Netresearch\NrVault\Service\VaultService::setEnabled()} opens its
 * read-then-write window with. The increment goes through the inner adapter's
 * own targeted statement, so it is a genuine committed row change and not a
 * test-only shortcut.
 */
final readonly class ConcurrentReadAdapter implements VaultAdapterInterface
{
    public function __construct(
        private VaultAdapterInterface $inner,
    ) {}

    public function getIdentifier(): string
    {
        return $this->inner->getIdentifier();
    }

    public function isAvailable(): bool
    {
        return $this->inner->isAvailable();
    }

    public function store(Secret $secret, bool $persistGroupRelations = true): Secret
    {
        return $this->inner->store($secret, $persistGroupRelations);
    }

    public function retrieve(string $identifier): ?Secret
    {
        return $this->inner->retrieve($identifier);
    }

    public function retrieveIncludingDisabled(string $identifier): ?Secret
    {
        $secret = $this->inner->retrieveIncludingDisabled($identifier);

        // The concurrent request, landing inside the caller's window.
        $uid = $secret?->getUid();
        if ($uid !== null) {
            $this->inner->incrementReadCount($uid);
        }

        return $secret;
    }

    public function setHidden(int $uid, bool $hidden): void
    {
        $this->inner->setHidden($uid, $hidden);
    }

    public function delete(string $identifier): void
    {
        $this->inner->delete($identifier);
    }

    public function exists(string $identifier): bool
    {
        return $this->inner->exists($identifier);
    }

    /**
     * @return string[]
     */
    public function list(?SecretFilters $filters = null): array
    {
        return $this->inner->list($filters);
    }

    /**
     * @return Secret[]
     */
    public function listSecrets(?SecretFilters $filters = null): array
    {
        return $this->inner->listSecrets($filters);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function getMetadata(string $identifier): ?array
    {
        return $this->inner->getMetadata($identifier);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function updateMetadata(string $identifier, array $metadata): void
    {
        $this->inner->updateMetadata($identifier, $metadata);
    }

    public function incrementReadCount(int $uid): void
    {
        $this->inner->incrementReadCount($uid);
    }
}
