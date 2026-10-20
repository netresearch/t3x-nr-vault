<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

/**
 * Data Transfer Object for field migration results.
 *
 * Replaces array{table: string, column: string, migrated: int, failed: int, skipped: int, error?: string}
 * for type-safe migration result handling.
 */
readonly class MigrationResult
{
    public function __construct(
        public string $table,
        public string $column,
        public int $migrated,
        public int $failed,
        public int $skipped,
        public ?string $error = null,
    ) {}

    /**
     * Create a successful result.
     */
    public static function success(string $table, string $column, int $migrated, int $skipped = 0): self
    {
        return new self(
            table: $table,
            column: $column,
            migrated: $migrated,
            failed: 0,
            skipped: $skipped,
        );
    }

    /**
     * Create a result with failures.
     */
    public static function withFailures(string $table, string $column, int $migrated, int $failed, int $skipped = 0): self
    {
        return new self(
            table: $table,
            column: $column,
            migrated: $migrated,
            failed: $failed,
            skipped: $skipped,
        );
    }

    /**
     * Create an error result.
     */
    public static function error(string $table, string $column, string $error): self
    {
        return new self(
            table: $table,
            column: $column,
            migrated: 0,
            failed: 0,
            skipped: 0,
            error: $error,
        );
    }

    /**
     * Check if the migration was fully successful.
     */
    public function isSuccess(): bool
    {
        return $this->error === null && $this->failed === 0;
    }

    /**
     * Check if there was an error.
     */
    public function hasError(): bool
    {
        return $this->error !== null;
    }

    /**
     * Get total records processed.
     */
    public function getTotal(): int
    {
        return $this->migrated + $this->failed + $this->skipped;
    }

    /**
     * Convert to array for JSON serialization.
     *
     * @return array{table: string, column: string, migrated: int, failed: int, skipped: int, error?: string}
     */
    public function toArray(): array
    {
        $result = [
            'table'    => $this->table,
            'column'   => $this->column,
            'migrated' => $this->migrated,
            'failed'   => $this->failed,
            'skipped'  => $this->skipped,
        ];

        if ($this->error !== null) {
            $result['error'] = $this->error;
        }

        return $result;
    }
}
