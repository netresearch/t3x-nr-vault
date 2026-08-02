<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor;

use Netresearch\NrVault\Configuration\SecurityProfile;

/**
 * One area of the vault's deployment readiness.
 *
 * Implementations are discovered through the `nr_vault.readiness_check` tag
 * (applied automatically by the `_instanceof` block in `Services.yaml`) and
 * injected into {@see VaultDoctorService} as an iterator, so a consuming
 * extension adds its own control by implementing this interface — no edit to the
 * doctor service, and no way for a check to be silently forgotten.
 *
 * Two contract rules matter:
 *
 *  1. **Read-only.** A check runs on a production system during a deployment
 *     gate and on every render of the backend status surface. It must not write
 *     configuration, secrets, audit rows or files.
 *  2. **Report, don't throw.** A check SHOULD contain its own expected failures
 *     and report them as {@see Finding}s. Unexpected throwables are contained by
 *     {@see VaultDoctorService} and surface as a `check.crashed` critical
 *     finding — that safety net exists so one broken check cannot blank the
 *     report, not as the normal error path.
 */
interface ReadinessCheckInterface
{
    /**
     * Stable dotted identifier of the area this check covers, e.g. `audit`.
     *
     * Used for crash attribution and for ordering the report. The `<area>`
     * segment of every {@see Finding} id this check emits SHOULD match it, so an
     * operator reading `audit.external_sink` knows which check to look at.
     */
    public function getId(): string;

    /**
     * Does this check have anything to assert for the target profile?
     *
     * Profile-independent checks return `true` for both and vary only the
     * severity they report. Returning `false` removes the check from the run
     * entirely — including from the "N of M controls passed" denominator, which
     * is why it is a declaration and not something a check decides inside
     * {@see self::run()}.
     */
    public function appliesTo(SecurityProfile $profile): bool;

    /**
     * Evaluate the controls in this area.
     *
     * Returns one {@see Finding} per control — including passing ones, so the
     * report is a full control list rather than a defect list.
     *
     * @return list<Finding>
     */
    public function run(DoctorContext $context): array;
}
