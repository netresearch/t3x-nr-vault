<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\Controller\AjaxController;

/**
 * AJAX routes for vault backend operations.
 *
 * These routes are accessible via TYPO3.settings.ajaxUrls['route_name']
 * in JavaScript.
 *
 * `access => 'user'` only means "any authenticated backend user may reach the
 * endpoint". Authorization is the controller's job: both actions re-check their
 * operation permission (`secret.reveal` / `secret.rotate`) via
 * `AccessControlServiceInterface::isGranted()` and answer with the uniform 403
 * envelope otherwise — see SEC-ACCESS-6 in AjaxController.
 */
return [
    // Reveal a secret value (for FormEngine and list view)
    'vault_reveal' => [
        'path' => '/vault/reveal',
        'methods' => ['POST'],
        'access' => 'user',
        'target' => AjaxController::class . '::revealAction',
    ],

    // Rotate a secret value (for list view modal)
    'vault_rotate' => [
        'path' => '/vault/rotate',
        'methods' => ['POST'],
        'access' => 'user',
        'target' => AjaxController::class . '::rotateAction',
    ],
];
