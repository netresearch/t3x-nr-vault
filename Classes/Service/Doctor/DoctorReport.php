<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor;

/**
 * Result of one `vault:doctor` run: every evaluated control plus the verdict.
 *
 * ## Exit-code aggregation
 *
 * The single rule, applied here rather than in the command so the backend
 * surface and any future consumer cannot disagree with the CLI:
 *
 *   - `2` — at least one {@see FindingSeverity::Critical} finding;
 *   - `1` — otherwise, at least one {@see FindingSeverity::Warning};
 *   - `0` — only passes (this includes an empty report, which the doctor service
 *     never produces because every applicable check reports its passes too).
 *
 * Worst-severity-wins rather than a score: a gate must not be able to average a
 * critical finding away against a long list of passes.
 */
final readonly class DoctorReport
{
    /**
     * @param list<Finding> $findings Every evaluated control, passing ones included
     */
    public function __construct(
        public DoctorContext $context,
        public array $findings,
    ) {}

    /**
     * The verdict: the highest severity present.
     */
    public function highestSeverity(): FindingSeverity
    {
        $highest = FindingSeverity::Pass;
        foreach ($this->findings as $finding) {
            if ($finding->severity->rank() > $highest->rank()) {
                $highest = $finding->severity;
            }
        }

        return $highest;
    }

    /**
     * Process exit code per the aggregation rule in the class docblock.
     */
    public function exitCode(): int
    {
        return match ($this->highestSeverity()) {
            FindingSeverity::Critical => 2,
            FindingSeverity::Warning => 1,
            FindingSeverity::Pass => 0,
        };
    }

    /**
     * Is the configuration audit-ready — no finding above Pass?
     */
    public function isAuditReady(): bool
    {
        return $this->highestSeverity() === FindingSeverity::Pass;
    }

    /**
     * @return list<Finding>
     */
    public function findingsOfSeverity(FindingSeverity $severity): array
    {
        return array_values(array_filter(
            $this->findings,
            static fn (Finding $finding): bool => $finding->severity === $severity,
        ));
    }

    /**
     * Every finding that is not a pass, criticals first.
     *
     * The ordering is the point: an operator scanning a long report must hit the
     * blocking findings before the advisory ones.
     *
     * @return list<Finding>
     */
    public function problems(): array
    {
        return [
            ...$this->findingsOfSeverity(FindingSeverity::Critical),
            ...$this->findingsOfSeverity(FindingSeverity::Warning),
        ];
    }

    /**
     * Number of controls evaluated.
     */
    public function totalControls(): int
    {
        return \count($this->findings);
    }

    /**
     * Number of controls satisfied.
     */
    public function passedControls(): int
    {
        return \count($this->findingsOfSeverity(FindingSeverity::Pass));
    }

    /**
     * @return array{
     *     profile: string,
     *     configuredProfile: string,
     *     profileOverridden: bool,
     *     auditReady: bool,
     *     highestSeverity: string,
     *     exitCode: int,
     *     summary: array{total: int, pass: int, warning: int, critical: int},
     *     findings: list<array{
     *         id: string,
     *         severity: string,
     *         summary: string,
     *         risk: string,
     *         remediation: string,
     *         docsUrl: string,
     *         details: array<string, bool|int|string>,
     *     }>,
     * }
     */
    public function toArray(): array
    {
        return [
            'profile' => $this->context->profile->value,
            'configuredProfile' => $this->context->configuredProfile->value,
            'profileOverridden' => $this->context->isProfileOverridden(),
            'auditReady' => $this->isAuditReady(),
            'highestSeverity' => $this->highestSeverity()->value,
            'exitCode' => $this->exitCode(),
            'summary' => [
                'total' => $this->totalControls(),
                'pass' => $this->passedControls(),
                'warning' => \count($this->findingsOfSeverity(FindingSeverity::Warning)),
                'critical' => \count($this->findingsOfSeverity(FindingSeverity::Critical)),
            ],
            'findings' => array_map(
                static fn (Finding $finding): array => $finding->toArray(),
                $this->findings,
            ),
        ];
    }
}
