<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Configuration;

/**
 * Operating profile of the vault.
 *
 * A profile is a single, internally consistent security policy — not a bag of
 * independent toggles. Enforcement happens in code (provider selection, access
 * control, audit anchoring), never only in documentation.
 *
 * - Standard: secure defaults with zero-configuration TYPO3 integration.
 * - Hardened: fail-closed, audit-ready configuration for regulated
 *   environments. Requires an explicit external master-key provider,
 *   forbids provider auto-detection and any fallback to the TYPO3
 *   encryption key.
 */
enum SecurityProfile: string
{
    case Standard = 'standard';

    case Hardened = 'hardened';

    public function isHardened(): bool
    {
        return $this === self::Hardened;
    }
}
