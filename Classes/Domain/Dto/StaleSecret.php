<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

use Netresearch\NrVault\Domain\StalenessRule;

/**
 * A secret flagged as a redaction candidate, with the rules it matched.
 */
final readonly class StaleSecret
{
    /**
     * @param list<StalenessRule> $rules
     */
    public function __construct(
        public int $uid,
        public string $identifier,
        public string $context,
        public string $adapter,
        public ?int $lastReadAt,
        public int $automatedReads,
        public int $manualReveals,
        public int $ageDays,
        public array $rules,
    ) {}

    /**
     * 'danger' if any matched rule is danger, else 'warning'. Used to colour the row.
     */
    public function highestSeverity(): string
    {
        foreach ($this->rules as $rule) {
            if ($rule->severity() === 'danger') {
                return 'danger';
            }
        }

        return 'warning';
    }
}
