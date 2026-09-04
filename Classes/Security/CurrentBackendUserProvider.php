<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use Psr\Http\Message\ServerRequestInterface;
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;

/**
 * Provides access to the current backend user from the request context.
 *
 * This replaces direct $GLOBALS['BE_USER'] access with proper dependency injection.
 * The backend user is resolved from the request attribute 'backend.user' which is
 * set by TYPO3's backend routing and authentication middleware.
 */
class CurrentBackendUserProvider implements CurrentBackendUserProviderInterface
{
    public function __construct(
        private readonly ServerRequestInterface $request,
    ) {}

    /**
     * Get the current backend user from the request context.
     */
    public function get(): ?BackendUserAuthentication
    {
        $backendUser = $this->request->getAttribute('backend.user') ?? null;

        return $backendUser instanceof BackendUserAuthentication ? $backendUser : null;
    }
}