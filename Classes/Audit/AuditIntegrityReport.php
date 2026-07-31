<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;

/**
 * Combined result of an audit-integrity verification run.
 *
 * Wider than {@see HashChainVerificationResult}, which only answers "does the
 * stored chain verify against itself". This report adds the external evidence
 * that the stored chain cannot supply:
 *
 *  - is it still the SAME chain the last published anchor witnessed
 *    (`TABLE_RESET`), and
 *  - is external evidence being produced at all (`NO_EXTERNAL_SINK`).
 *
 * Findings are {@see AuditIntegrityAlert} objects rather than plain strings so the
 * same value that `vault:audit-verify` prints is the value dispatched to SIEM
 * listeners — one representation, no drift between what an operator sees and what
 * a collector receives.
 */
final readonly class AuditIntegrityReport
{
    /**
     * @param list<AuditIntegrityAlert> $findings Empty = fully verified
     * @param bool $chainValid Result of the internal hash-chain pass alone
     * @param int $currentSequence Highest audit uid at verification time
     * @param ChainTipAnchor|null $anchor Anchor compared against (null = none available)
     * @param array<int, string> $warnings Non-fatal chain notes, keyed by uid
     */
    public function __construct(
        public array $findings,
        public bool $chainValid,
        public int $currentSequence,
        public ?ChainTipAnchor $anchor = null,
        public array $warnings = [],
    ) {}

    /**
     * Whether the run produced no findings at all.
     */
    public function isValid(): bool
    {
        return $this->findings === [];
    }

    /**
     * Whether any finding is evidence of tampering (as opposed to a
     * configuration or delivery problem).
     *
     * The discriminator between "the audit trail may have been altered" and
     * "the audit pipeline needs attention" — a distinction worth keeping in
     * alerting rules, because only the former is an incident.
     */
    public function hasTamperEvidence(): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->reason->isTamperEvidence()) {
                return true;
            }
        }

        return false;
    }

    public function hasReason(AuditIntegrityReason $reason): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->reason === $reason) {
                return true;
            }
        }

        return false;
    }

    /**
     * Distinct reason codes, in first-seen order, for machine-readable output.
     *
     * @return list<string>
     */
    public function getReasonCodes(): array
    {
        $codes = [];
        foreach ($this->findings as $finding) {
            $code = $finding->reason->value;
            if (!\in_array($code, $codes, true)) {
                $codes[] = $code;
            }
        }

        return $codes;
    }

    /**
     * @return array{
     *     valid: bool,
     *     tamperEvidence: bool,
     *     chainValid: bool,
     *     currentSequence: int,
     *     anchor: array{sequence: int, chainTip: string, timestamp: int, hmacEpoch: int}|null,
     *     reasonCodes: list<string>,
     *     findings: list<array{reason: string, tamperEvidence: bool, detail: string, timestamp: int, context: array<string, bool|int|string>}>,
     *     warnings: array<int, string>,
     * }
     */
    public function toArray(): array
    {
        return [
            'valid' => $this->isValid(),
            'tamperEvidence' => $this->hasTamperEvidence(),
            'chainValid' => $this->chainValid,
            'currentSequence' => $this->currentSequence,
            'anchor' => $this->anchor?->toArray(),
            'reasonCodes' => $this->getReasonCodes(),
            'findings' => array_map(
                static fn (AuditIntegrityAlert $finding): array => $finding->toArray(),
                $this->findings,
            ),
            'warnings' => $this->warnings,
        ];
    }
}
