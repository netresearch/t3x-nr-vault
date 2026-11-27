<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

use Netresearch\NrVault\Domain\Dto\OrphanReference;

/**
 * Decides whether a linked secret is an orphan the cleanup may delete.
 *
 * One instance serves one cleanup run: call {@see self::reset()} at the start
 * of a run, so table, column and holder caches and the list of unresolved
 * references describe that run only.
 */
interface OrphanReferenceCheckerInterface
{
    /**
     * Minimum age, in seconds, of a secret before any cleanup may delete it,
     * whatever retention the run is configured with (0 included).
     *
     * Several writers store a secret first and write its identifier into the
     * record right after: a record copy clones the secret and then updates
     * the copy, `vault:migrate-field` and the migration module store and then
     * update the row. Writing the identifier first is not an option there: if
     * the store then failed, the row would point at a secret that does not
     * exist and the plaintext would be gone. Between the two steps no row
     * holds the identifier, so a cleanup running at that moment would delete
     * a secret that is about to be referenced. The gap is one request; 15
     * minutes is far above any request or batch step, including a stalled
     * database connection, and short enough that a real orphan is still
     * retired by the next daily run.
     */
    public const MINIMUM_AGE_SECONDS = 900;

    /**
     * True only when the reference resolves and no row of the linked table
     * holds the identifier in the linked field. Every failure answers false.
     */
    public function isOrphaned(OrphanReference $reference, string $identifier): bool;

    /**
     * The references this run kept because it could not check them.
     *
     * @return list<array{identifier: string, table: string, field: string, uid: int, reason: string}>
     */
    public function getUnresolvedReferences(): array;

    /**
     * Forget every cache and the unresolved references of an earlier run.
     */
    public function reset(): void;

    /**
     * The crdate a secret must be older than (strictly) to be deleted: the
     * retention cutoff, capped by {@see self::MINIMUM_AGE_SECONDS}.
     */
    public function deletionCutoff(int $retentionDays, int $now): int;
}
