<?php

/*
 * This file is part of the nr-vault TYPO3 extension.
 *
 * (c) Netresearch DTT GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

/**
 * Value object representing the result of hash chain verification.
 *
 * Used to validate audit log integrity by checking the hash chain.
 */
final readonly class HashChainVerificationResult
{
    /**
     * @param bool $valid Whether the hash chain is valid
     * @param array<int, string> $errors Map of UID => error message for invalid entries
     * @param array<int, string> $warnings Map of UID => warning message (e.g., epoch boundaries)
     * @param list<int> $missingUids UID values missing from the stored chain
     *                               (detected via non-contiguous UID sequence). May be
     *                               legitimate (purged rows) or malicious deletions —
     *                               the verifier reports them so callers can decide.
     *                               Capped at 1000 entries (see `missingUidCount` for
     *                               the true total when the cap is exceeded).
     * @param int $missingUidCount Total number of missing UIDs detected, before the
     *                             per-call cap applied to `$missingUids`. Equals
     *                             count($missingUids) when below the cap.
     * @param AuditChainAnchorStatus $anchorStatus Outcome of the tip-anchor check, which
     *                                             detects tail truncation and full wipes
     *                                             that the walk alone cannot see. Only
     *                                             evaluated on a full-chain pass.
     * @param array<int, int> $epochCounts How many rows in the verified range carry each
     *                                     `hmac_key_epoch`, keyed by epoch and sorted
     *                                     ascending. Free: the walk already visits every
     *                                     row and already reads the epoch to pick the hash
     *                                     algorithm. Empty for an empty range. Reported by
     *                                     `vault:audit-verify`, where "the chain is valid"
     *                                     and "every row is signed at the configured epoch"
     *                                     are separate questions — a chain of epoch-1 rows
     *                                     verifies perfectly and is still missing the MAC
     *                                     over `success` and the attribution fields.
     */
    public function __construct(
        public bool $valid,
        public array $errors = [],
        public array $warnings = [],
        public array $missingUids = [],
        public int $missingUidCount = 0,
        public AuditChainAnchorStatus $anchorStatus = AuditChainAnchorStatus::NotChecked,
        public array $epochCounts = [],
    ) {}

    /**
     * Create a successful verification result.
     *
     * @param array<int, string> $warnings Map of UID => warning message
     * @param list<int> $missingUids UID values missing from the chain (may be empty)
     * @param int $missingUidCount Total number of missing UIDs detected
     * @param AuditChainAnchorStatus $anchorStatus Outcome of the tip-anchor check
     * @param array<int, int> $epochCounts Row count per `hmac_key_epoch` in the range
     */
    public static function valid(
        array $warnings = [],
        array $missingUids = [],
        int $missingUidCount = 0,
        AuditChainAnchorStatus $anchorStatus = AuditChainAnchorStatus::NotChecked,
        array $epochCounts = [],
    ): self {
        return new self(
            valid: true,
            errors: [],
            warnings: $warnings,
            missingUids: $missingUids,
            missingUidCount: $missingUidCount > 0 ? $missingUidCount : \count($missingUids),
            anchorStatus: $anchorStatus,
            epochCounts: $epochCounts,
        );
    }

    /**
     * Create a failed verification result.
     *
     * @param array<int, string> $errors Map of UID => error message
     * @param array<int, string> $warnings Map of UID => warning message
     * @param list<int> $missingUids UID values missing from the chain
     * @param int $missingUidCount Total number of missing UIDs detected
     * @param AuditChainAnchorStatus $anchorStatus Outcome of the tip-anchor check
     * @param array<int, int> $epochCounts Row count per `hmac_key_epoch` in the range
     */
    public static function invalid(
        array $errors,
        array $warnings = [],
        array $missingUids = [],
        int $missingUidCount = 0,
        AuditChainAnchorStatus $anchorStatus = AuditChainAnchorStatus::NotChecked,
        array $epochCounts = [],
    ): self {
        return new self(
            valid: false,
            errors: $errors,
            warnings: $warnings,
            missingUids: $missingUids,
            missingUidCount: $missingUidCount > 0 ? $missingUidCount : \count($missingUids),
            anchorStatus: $anchorStatus,
            epochCounts: $epochCounts,
        );
    }

    /**
     * Check if verification passed.
     */
    public function isValid(): bool
    {
        return $this->valid;
    }

    /**
     * Get error count.
     */
    public function getErrorCount(): int
    {
        return \count($this->errors);
    }

    /**
     * Get warning count.
     */
    public function getWarningCount(): int
    {
        return \count($this->warnings);
    }

    /**
     * Whether any UID gaps were detected in the stored chain.
     */
    public function hasMissingUids(): bool
    {
        return $this->missingUidCount > 0;
    }

    /**
     * Lowest `hmac_key_epoch` any row in the verified range carries, or null
     * for an empty range.
     *
     * The number an operator actually has to act on: raising `auditHmacEpoch`
     * changes what NEW rows are signed with and nothing else, so this is the
     * protection level the OLDEST evidence still rests on.
     */
    public function getMinEpoch(): ?int
    {
        // min()/max() over the keys rather than array_key_first()/_last(), so a
        // caller that hands in an unordered map still gets the right answer —
        // the getters must not depend on how the producer happened to insert.
        return $this->epochCounts === [] ? null : min(array_keys($this->epochCounts));
    }

    /**
     * Highest `hmac_key_epoch` in the verified range, or null for an empty
     * range.
     *
     * The high-water mark the chain-wide downgrade floor is compared against
     * on a full-chain pass, exposed so a caller can see the value behind that
     * verdict instead of only its outcome.
     */
    public function getMaxEpoch(): ?int
    {
        return $this->epochCounts === [] ? null : max(array_keys($this->epochCounts));
    }

    /**
     * Whether the range mixes epochs, i.e. a migration covered part of it.
     */
    public function hasMixedEpochs(): bool
    {
        return \count($this->epochCounts) > 1;
    }

    /**
     * Convert to array for JSON serialization.
     *
     * @return array{valid: bool, errors: array<int, string>, warnings: array<int, string>, missingUids: list<int>, missingUidCount: int, anchorStatus: string, epochCounts: array<int, int>, minEpoch: int|null, maxEpoch: int|null}
     */
    public function toArray(): array
    {
        return [
            'valid' => $this->valid,
            'errors' => $this->errors,
            'warnings' => $this->warnings,
            'missingUids' => $this->missingUids,
            'missingUidCount' => $this->missingUidCount,
            'anchorStatus' => $this->anchorStatus->value,
            'epochCounts' => $this->epochCounts,
            'minEpoch' => $this->getMinEpoch(),
            'maxEpoch' => $this->getMaxEpoch(),
        ];
    }
}
