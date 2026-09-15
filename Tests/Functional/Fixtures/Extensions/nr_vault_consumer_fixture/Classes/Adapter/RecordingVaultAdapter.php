<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Adapter;

use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;

/**
 * A storage adapter that wraps whichever adapter the installation had and
 * records every call. Decoration keeps the database semantics the rest of the
 * test relies on, while proving VaultService reaches the consumer's adapter.
 */
final class RecordingVaultAdapter implements VaultAdapterInterface
{
    /** @var list<string> */
    public array $calls = [];

    public function __construct(
        private readonly VaultAdapterInterface $inner,
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
        $this->calls[] = 'store:' . $secret->getIdentifier();

        return $this->inner->store($secret, $persistGroupRelations);
    }

    public function retrieve(string $identifier): ?Secret
    {
        $this->calls[] = 'retrieve:' . $identifier;

        return $this->inner->retrieve($identifier);
    }

    public function retrieveIncludingDisabled(string $identifier): ?Secret
    {
        $this->calls[] = 'retrieveIncludingDisabled:' . $identifier;

        return $this->inner->retrieveIncludingDisabled($identifier);
    }

    public function setHidden(int $uid, bool $hidden): void
    {
        $this->inner->setHidden($uid, $hidden);
    }

    public function delete(string $identifier): void
    {
        $this->calls[] = 'delete:' . $identifier;
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
