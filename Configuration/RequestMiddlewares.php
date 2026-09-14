<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\Middleware\VaultOverviewModuleResolver;

return [
    'backend' => [
        // Must run before core resolves the vault parent module to a submodule;
        // see the class docblock for what TYPO3 13 does there and why.
        // `backend-routing` has put the Route on the request by then, and
        // `authentication` has established $GLOBALS['BE_USER'], which the core
        // validator needs right after us.
        'netresearch/nr-vault/overview-module-resolver' => [
            'target' => VaultOverviewModuleResolver::class,
            'after' => [
                'typo3/cms-backend/authentication',
            ],
            'before' => [
                'typo3/cms-backend/backend-module-validator',
            ],
        ],
    ],
];
