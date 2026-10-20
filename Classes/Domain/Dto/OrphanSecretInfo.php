<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

/**
 * Data Transfer Object for orphan secret information.
 *
 * Replaces array{identifier: string, metadata: array<string, mixed>, created_at: int}
 * for type-safe orphan secret handling during cleanup operations.
 */
readonly class OrphanSecretInfo
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public string $identifier,
        public array $metadata,
        public int $createdAt,
    ) {}

    /**
     * Create from array.
     *
     * @param array{identifier: string, metadata?: array<string, mixed>, created_at?: int} $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            identifier: $data['identifier'],
            metadata: $data['metadata'] ?? [],
            createdAt: $data['created_at'] ?? 0,
        );
    }

    /**
     * Get the age of the secret in seconds.
     */
    public function getAgeInSeconds(): int
    {
        return time() - $this->createdAt;
    }

    /**
     * Get the age of the secret in days.
     */
    public function getAgeInDays(): int
    {
        return (int) floor($this->getAgeInSeconds() / 86400);
    }

    /**
     * Check if the secret is older than the given number of days.
     */
    public function isOlderThanDays(int $days): bool
    {
        return $this->getAgeInDays() >= $days;
    }

    /**
     * Get a metadata value by key.
     */
    public function getMetadataValue(string $key, mixed $default = null): mixed
    {
        return $this->metadata[$key] ?? $default;
    }

    /**
     * Convert to array for serialization.
     *
     * @return array{identifier: string, metadata: array<string, mixed>, created_at: int}
     */
    public function toArray(): array
    {
        return [
            'identifier' => $this->identifier,
            'metadata'   => $this->metadata,
            'created_at' => $this->createdAt,
        ];
    }
}
