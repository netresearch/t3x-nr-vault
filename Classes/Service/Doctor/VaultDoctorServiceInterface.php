<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor;

use Netresearch\NrVault\Configuration\SecurityProfile;

/**
 * Runs every applicable readiness check and aggregates one verdict.
 *
 * The single entry point behind both `vault:doctor` and the backend security
 * status panel, so a deployment gate and the module can never disagree about
 * whether the vault is audit-ready.
 */
interface VaultDoctorServiceInterface
{
    /**
     * Evaluate readiness against a target profile.
     *
     * @param SecurityProfile|null $targetProfile Profile to assert against; null
     *                                            uses the configured profile
     *                                            ("is this deployment ready for
     *                                            what it claims to be?")
     */
    public function run(?SecurityProfile $targetProfile = null): DoctorReport;
}
