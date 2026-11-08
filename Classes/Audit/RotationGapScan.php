<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

/**
 * Outcome of {@see RotationGapScanner::scan()}.
 *
 * `$previousKeyRows` lists the audit rows that verify only under the previous
 * master key. `$problems` lists every finding that rules a re-seal out; the
 * rows are only worth re-sealing when it is empty.
 */
final readonly class RotationGapScan
{
    /**
     * @param list<array{uid: int, action: string, secretIdentifier: string, crdate: int}> $previousKeyRows
     * @param list<string>                                                                 $problems
     */
    public function __construct(
        public array $previousKeyRows = [],
        public array $problems = [],
    ) {}

    public function isRepairable(): bool
    {
        return $this->problems === [];
    }

    public function hasPreviousKeyRows(): bool
    {
        return $this->previousKeyRows !== [];
    }
}
