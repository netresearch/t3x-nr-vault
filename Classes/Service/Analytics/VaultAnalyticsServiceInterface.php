<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Service\Analytics;

use Netresearch\NrVault\Domain\Dto\StaleSecret;
use Netresearch\NrVault\Domain\Dto\VaultUsageStats;

/**
 * Read-only usage analytics over the vault's secrets + audit log.
 */
interface VaultAnalyticsServiceInterface
{
    public function getUsageStats(int $windowDays): VaultUsageStats;

    /**
     * @return list<StaleSecret>
     */
    public function getRedactionCandidates(int $windowDays): array;
}
