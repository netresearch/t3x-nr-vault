<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

use function sprintf;

/**
 * Data Transfer Object for orphan secret references.
 *
 * Replaces array{table: string, field: string, uid: int}
 * for type-safe orphan reference handling during cleanup.
 */
readonly class OrphanReference
{
    public function __construct(
        public string $table,
        public string $field,
        public int $uid,
    ) {}

    /**
     * Create from array.
     *
     * @param array{table: string, field: string, uid: int} $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            table: $data['table'],
            field: $data['field'],
            uid: $data['uid'],
        );
    }

    /**
     * Get a human-readable location string.
     */
    public function getLocation(): string
    {
        return sprintf('%s.%s (uid=%d)', $this->table, $this->field, $this->uid);
    }

    /**
     * Convert to array for serialization.
     *
     * @return array{table: string, field: string, uid: int}
     */
    public function toArray(): array
    {
        return [
            'table' => $this->table,
            'field' => $this->field,
            'uid'   => $this->uid,
        ];
    }
}
