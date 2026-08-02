<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Doctor;

use Netresearch\NrVault\Configuration\SecurityProfile;

/**
 * The profile a readiness run is judged against.
 *
 * Two profiles, not one, because the useful question before a hardening
 * migration is "would this configuration pass as hardened?" — answerable only by
 * evaluating the live configuration against a target profile it does not
 * currently claim. `vault:doctor --profile=hardened` therefore changes what the
 * checks *require*, never what the vault *does*: no configuration is written and
 * no enforcement path is affected.
 *
 * `$configuredProfile` is retained alongside so output can state which profile
 * is actually in force — a report that only showed the target would let an
 * operator read a passing `--profile=hardened` dry run as proof that hardening
 * is already live.
 */
final readonly class DoctorContext
{
    public function __construct(
        /** The profile the checks assert against. */
        public SecurityProfile $profile,
        /** The profile actually configured in the extension configuration. */
        public SecurityProfile $configuredProfile,
        /**
         * Whether the run may perform ACTIVE probes (deliver a test record
         * through every enabled audit sink). Off by default: the passive
         * checks are safe on every page load of the status panel, while a
         * probe talks to external systems and belongs to an explicit
         * `vault:doctor --active-probes` invocation.
         */
        public bool $activeProbes = false,
    ) {}

    /**
     * Judge the configured profile against itself — the default for a live
     * readiness report and for the backend status surface.
     */
    public static function forConfiguredProfile(SecurityProfile $profile): self
    {
        return new self(profile: $profile, configuredProfile: $profile);
    }

    /**
     * Is the run asserting against a profile other than the configured one?
     */
    public function isProfileOverridden(): bool
    {
        return $this->profile !== $this->configuredProfile;
    }

    /**
     * Does the run assert the hardened policy?
     */
    public function isHardened(): bool
    {
        return $this->profile->isHardened();
    }
}
