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

    public function store(Secret $secret, bool $persistGroupRelations = true): Secret
    {
        return $this->secretRepository->save($secret, $persistGroupRelations);
    }

    public function retrieve(string $identifier): ?Secret
    {
        return $this->secretRepository->findByIdentifier($identifier);
    }

    public function retrieveIncludingDisabled(string $identifier): ?Secret
    {
        return $this->secretRepository->findByIdentifierIncludingDisabled($identifier);
    }

    public function setHidden(int $uid, bool $hidden): void
    {
        $this->secretRepository->setHidden($uid, $hidden);
    }

    /**
     * Deleting resolves the record through the disabled-visible lookup: a
     * disabled secret is still a secret, and its owner must be able to remove
     * it. Using the restricted lookup here would make the delete a silent
     * no-op for exactly the records an operator most likely wants gone.
     */
    public function delete(string $identifier): void
    {
        $secret = $this->secretRepository->findByIdentifierIncludingDisabled($identifier);
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
     * The merge is read-then-write, so the resolved record supplies both the
     * base metadata and the UID the write is addressed to. Only the `metadata`
     * column is written: saving the whole entity back would restore the
     * envelope, version and read counters as they stood at the read above,
     * discarding a `retrieve()` or `rotate()` that committed in between — the
     * exact exposure `setHidden()` avoids, on a method whose contract is
     * "without changing the secret value".
     *
     * @param array<string, mixed> $metadata
     */
    public function updateMetadata(string $identifier, array $metadata): void
    {
        $secret = $this->secretRepository->findByIdentifier($identifier);
        $uid = $secret?->getUid();
        if (!$secret instanceof Secret || $uid === null) {
            return;
        }

        $this->secretRepository->setMetadata($uid, array_merge($secret->getMetadata(), $metadata));
    }
}
