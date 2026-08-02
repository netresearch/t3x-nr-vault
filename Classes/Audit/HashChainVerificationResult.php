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
     */
    public function __construct(
        public bool $valid,
        public array $errors = [],
        public array $warnings = [],
        public array $missingUids = [],
        public int $missingUidCount = 0,
        public AuditChainAnchorStatus $anchorStatus = AuditChainAnchorStatus::NotChecked,
    ) {}

    /**
     * Create a successful verification result.
     *
     * @param array<int, string> $warnings Map of UID => warning message
     * @param list<int> $missingUids UID values missing from the chain (may be empty)
     * @param int $missingUidCount Total number of missing UIDs detected
     * @param AuditChainAnchorStatus $anchorStatus Outcome of the tip-anchor check
     */
    public static function valid(
        array $warnings = [],
        array $missingUids = [],
        int $missingUidCount = 0,
        AuditChainAnchorStatus $anchorStatus = AuditChainAnchorStatus::NotChecked,
    ): self {
        return new self(
            valid: true,
            errors: [],
            warnings: $warnings,
            missingUids: $missingUids,
            missingUidCount: $missingUidCount > 0 ? $missingUidCount : \count($missingUids),
            anchorStatus: $anchorStatus,
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
     */
    public static function invalid(
        array $errors,
        array $warnings = [],
        array $missingUids = [],
        int $missingUidCount = 0,
        AuditChainAnchorStatus $anchorStatus = AuditChainAnchorStatus::NotChecked,
    ): self {
        return new self(
            valid: false,
            errors: $errors,
            warnings: $warnings,
            missingUids: $missingUids,
            missingUidCount: $missingUidCount > 0 ? $missingUidCount : \count($missingUids),
            anchorStatus: $anchorStatus,
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
     * Convert to array for JSON serialization.
     *
     * @return array{valid: bool, errors: array<int, string>, warnings: array<int, string>, missingUids: list<int>, missingUidCount: int, anchorStatus: string}
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
        ];
    }
}
