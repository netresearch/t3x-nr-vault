<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;

/**
 * Interface for providing access to the current backend user from the request context.
 */
interface CurrentBackendUserProviderInterface
{
    /**
     * Get the current backend user from the request context.
     */
    public function get(): ?BackendUserAuthentication;
}