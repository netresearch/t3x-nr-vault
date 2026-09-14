<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\ExtensionPoints;

use Netresearch\NrVault\Adapter\VaultAdapterInterface;
use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;

/**
 * A storage adapter written the way a consuming extension writes one:
 * against the published interface only. It keeps secrets in memory, assigns
 * a UID on insert and honours the availability flag the way the contract
 * describes.
 */
final class SampleVaultAdapter implements VaultAdapterInterface
{
    /** @var array<string, Secret> */
    private array $secrets = [];

    /** @var array<int, true> */
    private array $hiddenUids = [];

    /** @var array<int, int> */
    private array $readCounts = [];

    private int $nextUid = 1;

    public function getIdentifier(): string
    {
        return 'sample';
    }

    public function isAvailable(): bool
    {
        return true;
    }

    public function store(Secret $secret, bool $persistGroupRelations = true): Secret
    {
        $stored = $secret->getUid() === null ? $secret->withUid($this->nextUid++) : $secret;
        $this->secrets[$stored->getIdentifier()] = $stored;

        return $stored;
    }

    public function retrieve(string $identifier): ?Secret
    {
        $secret = $this->retrieveIncludingDisabled($identifier);
        if (!$secret instanceof Secret) {
            return null;
        }

        return isset($this->hiddenUids[$secret->getUid() ?? 0]) ? null : $secret;
    }

    public function retrieveIncludingDisabled(string $identifier): ?Secret
    {
        return $this->secrets[$identifier] ?? null;
    }

    public function setHidden(int $uid, bool $hidden): void
    {
        if ($hidden) {
            $this->hiddenUids[$uid] = true;
        } else {
            unset($this->hiddenUids[$uid]);
        }
    }

    public function delete(string $identifier): void
    {
        unset($this->secrets[$identifier]);
    }

    public function exists(string $identifier): bool
    {
        return isset($this->secrets[$identifier]);
    }

    /**
     * @return string[]
     */
    public function list(?SecretFilters $filters = null): array
    {
        return array_keys($this->secrets);
    }

    /**
     * @return Secret[]
     */
    public function listSecrets(?SecretFilters $filters = null): array
    {
        return array_values($this->secrets);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function getMetadata(string $identifier): ?array
    {
        return ($this->secrets[$identifier] ?? null)?->getMetadata();
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function updateMetadata(string $identifier, array $metadata): void
    {
        $secret = $this->secrets[$identifier] ?? null;
        if ($secret instanceof Secret) {
            $this->secrets[$identifier] = $secret->withMetadata([...$secret->getMetadata(), ...$metadata]);
        }
    }

    public function incrementReadCount(int $uid): void
    {
        $this->readCounts[$uid] = ($this->readCounts[$uid] ?? 0) + 1;
    }
}
