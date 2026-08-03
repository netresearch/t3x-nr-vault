<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

/**
 * Data Transfer Object for secret metadata.
 *
 * Replaces array returns from VaultServiceInterface::list()
 * for type-safe secret metadata handling.
 */
readonly class SecretMetadata
{
    /**
     * @param array<string, mixed> $metadata Custom metadata from the secret
     * @param bool $enabled Whether the secret is available to consumers. A
     *                      disabled secret exists and can be administered but
     *                      resolves to nothing on every read path, so a
     *                      listing that omitted this could not tell the two
     *                      states apart.
     */
    public function __construct(
        public string $identifier,
        public int $ownerUid,
        public int $createdAt,
        public int $updatedAt,
        public int $readCount,
        public ?int $lastReadAt,
        public string $description,
        public int $version,
        public array $metadata = [],
        public bool $enabled = true,
    ) {}

    /**
     * Create from database row array.
     *
     * @param array{identifier: string, owner_uid?: int, crdate?: int, tstamp?: int, read_count?: int, last_read_at?: int|null, description?: string, version?: int, metadata?: array<string, mixed>, hidden?: bool|int} $row
     */
    public static function fromArray(array $row): self
    {
        return new self(
            identifier: $row['identifier'],
            ownerUid: $row['owner_uid'] ?? 0,
            createdAt: $row['crdate'] ?? 0,
            updatedAt: $row['tstamp'] ?? 0,
            readCount: $row['read_count'] ?? 0,
            lastReadAt: $row['last_read_at'] ?? null,
            description: $row['description'] ?? '',
            version: $row['version'] ?? 1,
            metadata: $row['metadata'] ?? [],
            // The row speaks the TCA column's negative form; the DTO speaks
            // the positive one an operator reads in the listing.
            enabled: !((bool) ($row['hidden'] ?? false)),
        );
    }

    /**
     * Convert to array for JSON serialization.
     *
     * @return array{identifier: string, owner_uid: int, crdate: int, tstamp: int, read_count: int, last_read_at: int|null, description: string, version: int, metadata: array<string, mixed>, enabled: bool}
     */
    public function toArray(): array
    {
        return [
            'identifier' => $this->identifier,
            'owner_uid' => $this->ownerUid,
            'crdate' => $this->createdAt,
            'tstamp' => $this->updatedAt,
            'read_count' => $this->readCount,
            'last_read_at' => $this->lastReadAt,
            'description' => $this->description,
            'version' => $this->version,
            'metadata' => $this->metadata,
            'enabled' => $this->enabled,
        ];
    }
}
