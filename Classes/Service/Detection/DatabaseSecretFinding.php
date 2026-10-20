<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Detection;

use function sprintf;

/**
 * A detected secret in a database table column.
 */
final readonly class DatabaseSecretFinding implements SecretFinding
{
    /**
     * @param list<string> $patterns
     */
    public function __construct(
        public string $table,
        public string $column,
        public int $recordCount,
        public int $plaintextCount,
        public Severity $severity,
        public array $patterns = [],
    ) {}

    public function getKey(): string
    {
        return "database:{$this->table}.{$this->column}";
    }

    public function getSource(): string
    {
        return 'database';
    }

    public function getSeverity(): Severity
    {
        return $this->severity;
    }

    public function getPatterns(): array
    {
        return $this->patterns;
    }

    public function getDetails(): string
    {
        return sprintf('%d records (%d plaintext)', $this->recordCount, $this->plaintextCount);
    }

    /**
     * @return array{source: string, table: string, column: string, count: int, plaintextCount: int, severity: string, patterns: list<string>}
     */
    public function jsonSerialize(): array
    {
        return [
            'source'         => 'database',
            'table'          => $this->table,
            'column'         => $this->column,
            'count'          => $this->recordCount,
            'plaintextCount' => $this->plaintextCount,
            'severity'       => $this->severity->value,
            'patterns'       => $this->patterns,
        ];
    }
}
