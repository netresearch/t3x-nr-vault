<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

/**
 * Read-only health probe for the vault master-key / encryption subsystem.
 *
 * Exists so that presentation-layer controllers can render a setup/health
 * panel WITHOUT depending on the Crypto namespace directly (ARCHITECTURE-2):
 * the probe talks to the master-key providers; the controller talks only to
 * this service.
 */
interface VaultHealthServiceInterface
{
    /**
     * Probe whether a master key provider is configured, available, and able
     * to yield a usable key (encryption self-test).
     *
     * Never returns raw exception text or key material — failures are logged
     * via PSR-3 and reduced to the booleans / provider id on the result.
     */
    public function checkHealth(): VaultHealthStatus;
}
