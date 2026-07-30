<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Throwable;

/**
 * Implemented by a consuming extension that stores its own sealed envelopes, so
 * `vault:rotate-master-key` re-wraps them too (ADR-033).
 *
 * The problem this solves: `EnvelopeCodecInterface::seal()` wraps a per-payload
 * DEK with the CURRENT master key, but the wrapped DEK is stored in the
 * consumer's table. Rotating the master key re-wraps the DEKs in
 * `tx_nrvault_secret` and cannot reach anyone else's — so without a rotator,
 * every foreign envelope silently becomes undecryptable the moment an operator
 * rotates. Registering one is therefore not optional for a consumer that seals.
 *
 * Register by tagging the service in the consuming extension's
 * `Configuration/Services.yaml`:
 *
 * ```yaml
 * Vendor\Extension\Crypto\MyEnvelopeRotator:
 *   tags: ['nrvault.foreign_envelope_rotator']
 * ```
 *
 * Contract:
 * - {@see rewrapAll()} runs INSIDE the vault's rotation transaction, after the
 *   vault's own secrets and before the commit. Do not open, commit or roll back
 *   a transaction; do not catch and swallow failures.
 * - Throwing from {@see rewrapAll()} rolls the ENTIRE rotation back — the
 *   vault's secrets, the audit-chain re-key and every other consumer's
 *   envelopes. That is deliberate: a partial rotation leaves data encrypted
 *   under a key nobody will still have.
 * - {@see getTables()} must name every table written, so the command can refuse
 *   to run when a table is mapped to a different database connection and
 *   atomicity would be a fiction.
 * - Work in batches. A consumer may hold a large number of rows and the whole
 *   pass happens in one transaction.
 */
interface ForeignEnvelopeRotatorInterface
{
    /**
     * Short human-readable label naming the extension and the data it owns, for
     * the operator-facing rotation report (e.g. `nr-llm: agent run state`).
     */
    public function getIdentifier(): string;

    /**
     * Every table {@see rewrapAll()} writes to.
     *
     * @return list<string>
     */
    public function getTables(): array;

    /**
     * How many sealed envelopes this consumer currently holds.
     *
     * Read-only: used for the dry-run report and the operator summary, and
     * called outside the rotation transaction.
     */
    public function countEnvelopes(): int;

    /**
     * Re-wrap every sealed envelope this consumer owns, returning how many were
     * re-wrapped.
     *
     * @throws Throwable Any failure; the caller rolls the whole rotation back
     */
    public function rewrapAll(EnvelopeRotationContext $context): int;
}
