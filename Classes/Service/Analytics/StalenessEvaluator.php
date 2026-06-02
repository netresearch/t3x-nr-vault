<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Analytics;

use Netresearch\NrVault\Domain\StalenessRule;

/**
 * Pure evaluation of staleness rules for a single secret. No I/O, no clock —
 * the caller passes `now` so the logic is deterministically testable.
 */
final readonly class StalenessEvaluator
{
    public function __construct(
        private int $neverReadDays,
        private int $notReadDays,
        private int $neverRotatedDays,
    ) {}

    /**
     * @return list<StalenessRule>
     */
    public function evaluate(
        int $now,
        int $crdate,
        int $readCount,
        ?int $lastReadAt,
        int $lastRotatedAt,
        int $expiresAt,
        int $automatedReads,
        int $manualReveals,
    ): array {
        $rules = [];

        $ageDays = $this->daysBetween($crdate, $now);
        $lastReadDays = ($lastReadAt === null || $lastReadAt === 0)
            ? null
            : $this->daysBetween($lastReadAt, $now);

        $neverReadAndAged = $readCount === 0 && $ageDays >= $this->neverReadDays;
        $coldRead = $lastReadDays !== null && $lastReadDays >= $this->notReadDays;
        if ($neverReadAndAged || $coldRead) {
            $rules[] = StalenessRule::Dead;
        }

        if ($expiresAt > 0 && $expiresAt < $now) {
            $rules[] = StalenessRule::Expired;
        }

        $rotationBase = $lastRotatedAt > 0 ? $lastRotatedAt : $crdate;
        if ($this->daysBetween($rotationBase, $now) >= $this->neverRotatedDays) {
            $rules[] = StalenessRule::NeverRotated;
        }

        // Only flag automation-stale when the secret is NOT already dead: a
        // secret that IS being manually revealed but never automatically read
        // is a review candidate, not a delete candidate.
        $alreadyDead = \in_array(StalenessRule::Dead, $rules, true);
        if (!$alreadyDead && $automatedReads === 0 && $manualReveals > 0) {
            $rules[] = StalenessRule::AutomationStale;
        }

        return $rules;
    }

    private function daysBetween(int $earlier, int $later): int
    {
        return (int) floor(($later - $earlier) / 86400);
    }
}
