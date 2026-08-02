<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Anchor;

use JsonSerializable;

/**
 * An externally-published snapshot of the audit chain's tip.
 *
 * The hash chain in `tx_nrvault_audit_log` proves that no row was altered
 * *within* the stored chain, but it cannot prove that the chain is still the
 * same chain: an attacker with DELETE rights can TRUNCATE the table and let the
 * service build a fresh, internally-consistent chain from uid 1. Nothing inside
 * the database distinguishes that from a genuinely young installation.
 *
 * An anchor closes that gap by recording, outside the database, that sequence
 * `$sequence` once carried entry hash `$chainTip`. Verification then has two
 * external facts to check (see {@see ChainTipAnchorServiceInterface::verify()}):
 *
 *  1. the chain must not have shrunk — current max uid >= anchored sequence;
 *  2. the row at the anchored sequence must still hash to the anchored tip.
 *
 * `$hmacEpoch` is carried so an anchor also witnesses the protection level in
 * force when it was taken: a chain re-labelled down to keyless epoch-0 SHA-256
 * is detectable even if the row count and hashes were rebuilt consistently.
 */
final readonly class ChainTipAnchor implements JsonSerializable
{
    /**
     * @param int $sequence Highest audit uid at capture time (0 = empty chain)
     * @param string $chainTip `entry_hash` of that row ('' = empty chain)
     * @param int $timestamp Unix timestamp of capture
     * @param int $hmacEpoch `hmac_key_epoch` in force at capture time
     */
    public function __construct(
        public int $sequence,
        public string $chainTip,
        public int $timestamp,
        public int $hmacEpoch,
    ) {}

    /**
     * Rehydrate an anchor from its decoded JSON form.
     *
     * Returns null for anything that is not a structurally complete anchor, so
     * a truncated final line or a hand-edited file degrades to "no anchor
     * found" rather than to a bogus comparison baseline.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): ?self
    {
        $sequence = $data['sequence'] ?? null;
        $chainTip = $data['chainTip'] ?? null;
        $timestamp = $data['timestamp'] ?? null;
        $hmacEpoch = $data['hmacEpoch'] ?? null;

        if (!is_numeric($sequence) || !\is_string($chainTip) || !is_numeric($timestamp) || !is_numeric($hmacEpoch)) {
            return null;
        }

        return new self(
            sequence: (int) $sequence,
            chainTip: $chainTip,
            timestamp: (int) $timestamp,
            hmacEpoch: (int) $hmacEpoch,
        );
    }

    /**
     * @return array{sequence: int, chainTip: string, timestamp: int, hmacEpoch: int}
     */
    public function toArray(): array
    {
        return [
            'sequence' => $this->sequence,
            'chainTip' => $this->chainTip,
            'timestamp' => $this->timestamp,
            'hmacEpoch' => $this->hmacEpoch,
        ];
    }

    /**
     * @return array{sequence: int, chainTip: string, timestamp: int, hmacEpoch: int}
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Whether this anchor witnesses an actual chain (rather than an empty one).
     *
     * An empty-chain anchor is worth publishing (it dates the installation) but
     * carries no hash to compare against.
     */
    public function isEmpty(): bool
    {
        return $this->sequence <= 0 || $this->chainTip === '';
    }
}
