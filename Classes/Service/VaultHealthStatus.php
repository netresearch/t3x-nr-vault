<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service;

/**
 * Immutable result of a vault health probe.
 *
 * Carries only operational booleans, the provider identifier, and generic,
 * already-localizable UI hint keys — never raw exception text or key material.
 * Detailed error context is logged via PSR-3 inside {@see VaultHealthService},
 * not surfaced here (see SEC-INJECTION-LEAK-2).
 */
final readonly class VaultHealthStatus
{
    public function __construct(
        public bool $masterKeyAvailable,
        public string $masterKeyProvider,
        public bool $encryptionWorking,
        public bool $hasIssues,
    ) {}
}
