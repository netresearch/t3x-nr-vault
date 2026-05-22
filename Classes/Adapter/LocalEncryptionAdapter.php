<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Adapter;

use Netresearch\NrVault\Domain\Dto\SecretFilters;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Domain\Repository\SecretRepositoryInterface;

/**
 * Local database adapter with envelope encryption.
 */
final readonly class LocalEncryptionAdapter implements VaultAdapterInterface
{
    public function __construct(
        private SecretRepositoryInterface $secretRepository,
    ) {}

    public function getIdentifier(): string
    {
        return 'local';
    }

    public function isAvailable(): bool
    {
        // Local adapter is always available
        return true;
    }

    public function store(Secret $secret): void
    {
        $this->secretRepository->save($secret);
    }

    public function retrieve(string $identifier): ?Secret
    {
        return $this->secretRepository->findByIdentifier($identifier);
    }

    public function delete(string $identifier): void
    {
        $secret = $this->secretRepository->findByIdentifier($identifier);
        if ($secret instanceof Secret) {
            $this->secretRepository->delete($secret);
        }
    }

    public function exists(string $identifier): bool
    {
        return $this->secretRepository->exists($identifier);
    }

    public function list(?SecretFilters $filters = null): array
    {
        return $this->secretRepository->findIdentifiers($filters);
    }

    public function listSecrets(?SecretFilters $filters = null): array
    {
        return $this->secretRepository->findAllWithFilters($filters);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function getMetadata(string $identifier): ?array
    {
        $secret = $this->secretRepository->findByIdentifier($identifier);
        if (!$secret instanceof Secret) {
            return null;
        }

        return [
            'identifier' => $secret->getIdentifier(),
            'description' => $secret->getDescription(),
            'owner' => $secret->getOwnerUid(),
            'groups' => $secret->getAllowedGroups(),
            'context' => $secret->getContext(),
            'version' => $secret->getVersion(),
            'createdAt' => $secret->getCrdate(),
            'updatedAt' => $secret->getTstamp(),
            'expiresAt' => $secret->getExpiresAt() ?: null,
            'lastRotatedAt' => $secret->getLastRotatedAt() ?: null,
            'metadata' => $secret->getMetadata(),
            'adapter' => $secret->getAdapter(),
        ];
    }

    public function incrementReadCount(int $uid): void
    {
        $this->secretRepository->incrementReadCount($uid);
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function updateMetadata(string $identifier, array $metadata): void
    {
        $secret = $this->secretRepository->findByIdentifier($identifier);
        if (!$secret instanceof Secret) {
            return;
        }

        $existing = $secret->getMetadata();
        /** @var array<string, mixed> $merged */
        $merged = array_merge($existing, $metadata);
        $this->secretRepository->save($secret->withMetadata($merged));
    }
}
