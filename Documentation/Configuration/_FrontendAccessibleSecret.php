<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
declare(strict_types=1);

namespace Acme\SitePackage\Service;

use Netresearch\NrVault\Service\VaultServiceInterface;

final readonly class FrontendAccessibleSecret
{
    public function __construct(private VaultServiceInterface $vaultService) {}

    public function storeApiKey(string $apiKey): void
    {
        $this->vaultService->store(
            'google_maps_key',
            $apiKey,
            ['frontendAccessible' => true],
        );
    }
}
