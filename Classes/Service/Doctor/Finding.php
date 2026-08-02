<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor;

/**
 * One evaluated readiness control.
 *
 * ## Why four text fields instead of one message
 *
 * A deployment gate that only says "audit.external_sink: critical" tells the
 * operator nothing they can act on at 23:50 on a release evening. The three
 * prose fields answer the three questions that actually come up, and keeping
 * them separate means the CLI, the backend module and a CI log all show the
 * same answer instead of each inventing its own phrasing:
 *
 *  - `summary` — what was observed;
 *  - `risk` — what an attacker or auditor gets out of it (empty for Pass);
 *  - `remediation` — the concrete next action, ideally a command (empty for Pass).
 *
 * ## Identifier scheme
 *
 * `<area>.<control>`, lower snake within a segment: `provider.key_permissions`,
 * `audit.external_sink`, `breakglass.window_open`. Dotted rather than numbered
 * (`NRVAULT-DOC-001`) so an id survives inserting a control in the middle and
 * still reads as a sentence in a monitoring rule.
 *
 * **The ids are external API.** They appear in `--format=json`, in CI gate
 * allow-lists and in monitoring rules; renaming one silently changes what a
 * downstream gate is asserting. Add a new id rather than repurposing an old one.
 *
 * `details` carries machine-readable specifics (counts, reason codes, octal file
 * modes). It is deliberately scalar-only and must never carry key material, a
 * master-key path, or a secret value — the JSON form travels into CI logs.
 */
final readonly class Finding
{
    /**
     * @param string $id Stable dotted control id, e.g. `audit.external_sink`
     * @param string $summary What was observed, one sentence
     * @param string $risk What the finding costs the operator ('' for Pass)
     * @param string $remediation Concrete next action ('' for Pass)
     * @param string $docsUrl Deep link into the rendered documentation ('' when none applies)
     * @param array<string, bool|int|string> $details Machine-readable specifics — never secret material
     */
    public function __construct(
        public string $id,
        public FindingSeverity $severity,
        public string $summary,
        public string $risk = '',
        public string $remediation = '',
        public string $docsUrl = '',
        public array $details = [],
    ) {}

    /**
     * @param array<string, bool|int|string> $details
     */
    public static function pass(string $id, string $summary, string $docsUrl = '', array $details = []): self
    {
        return new self(
            id: $id,
            severity: FindingSeverity::Pass,
            summary: $summary,
            docsUrl: $docsUrl,
            details: $details,
        );
    }

    /**
     * @param array<string, bool|int|string> $details
     */
    public static function warning(
        string $id,
        string $summary,
        string $risk,
        string $remediation,
        string $docsUrl = '',
        array $details = [],
    ): self {
        return new self(
            id: $id,
            severity: FindingSeverity::Warning,
            summary: $summary,
            risk: $risk,
            remediation: $remediation,
            docsUrl: $docsUrl,
            details: $details,
        );
    }

    /**
     * @param array<string, bool|int|string> $details
     */
    public static function critical(
        string $id,
        string $summary,
        string $risk,
        string $remediation,
        string $docsUrl = '',
        array $details = [],
    ): self {
        return new self(
            id: $id,
            severity: FindingSeverity::Critical,
            summary: $summary,
            risk: $risk,
            remediation: $remediation,
            docsUrl: $docsUrl,
            details: $details,
        );
    }

    /**
     * Escalate a warning to critical, keeping every text field.
     *
     * Several controls are the same observation at two severities depending on
     * the target profile (an unlogged read is hygiene under `standard` and a
     * broken promise under `hardened`). Building the finding once and raising it
     * keeps the wording identical between profiles, which is what makes a
     * `--profile=hardened` dry run comparable to the live report.
     */
    public function escalatedTo(FindingSeverity $severity): self
    {
        if ($severity === $this->severity) {
            return $this;
        }

        return new self(
            id: $this->id,
            severity: $severity,
            summary: $this->summary,
            risk: $this->risk,
            remediation: $this->remediation,
            docsUrl: $this->docsUrl,
            details: $this->details,
        );
    }

    public function isPass(): bool
    {
        return $this->severity === FindingSeverity::Pass;
    }

    /**
     * @return array{
     *     id: string,
     *     severity: string,
     *     summary: string,
     *     risk: string,
     *     remediation: string,
     *     docsUrl: string,
     *     details: array<string, bool|int|string>,
     * }
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'severity' => $this->severity->value,
            'summary' => $this->summary,
            'risk' => $this->risk,
            'remediation' => $this->remediation,
            'docsUrl' => $this->docsUrl,
            'details' => $this->details,
        ];
    }
}
