<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use SensitiveParameter;

/**
 * Finds the audit rows sealed under the previous master key after a rotation:
 * rows written between the rotation commit and the configuration switch.
 */
interface RotationGapScannerInterface
{
    /**
     * Read-only. Reports every row after the newest successful
     * `master_key_rotate_end` or `audit_chain_rekey` row (the end of the last
     * rotation or of the last repair) that verifies only under `$previousMasterKey`,
     * and every finding that rules re-sealing them out: a row that verifies
     * under neither key, a broken link, a uid gap, an epoch downgrade, or any
     * error of the regular chain verification on another row or on the anchor.
     */
    public function scan(#[SensitiveParameter] string $previousMasterKey): RotationGapScan;
}
