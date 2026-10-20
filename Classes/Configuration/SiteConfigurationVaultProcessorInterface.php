<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Configuration;

use TYPO3\CMS\Core\Site\Entity\Site;

/**
 * Interface for site configuration vault processor.
 *
 * Allows mocking in unit tests while keeping implementation final.
 */
interface SiteConfigurationVaultProcessorInterface
{
    /**
     * Process configuration array and resolve vault references.
     *
     * @param array<string, mixed> $configuration The site configuration
     * @param Site|null            $site          Optional site for site-specific prefix resolution
     *
     * @return array<string, mixed> Configuration with vault references resolved
     */
    public function processConfiguration(array $configuration, ?Site $site = null): array;
}
