<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use Netresearch\NrVault\Domain\Model\Secret;

/**
 * Interface for access control operations.
 */
interface AccessControlServiceInterface
{
    /**
     * Check if current user can read a secret.
     */
    public function canRead(Secret $secret): bool;

    /**
     * Check if current user can write/update a secret.
     */
    public function canWrite(Secret $secret): bool;

    /**
     * Check if current user can delete a secret.
     */
    public function canDelete(Secret $secret): bool;

    /**
     * Check if current user can create secrets.
     */
    public function canCreate(): bool;

    /**
     * Is the current actor a TYPO3 backend admin?
     *
     * Returns `true` for BE users where `BackendUserAuthentication::isAdmin()`
     * is true. Non-BE actor types (CLI / scheduler / API) MUST return `false`
     * — callers that legitimately need to bypass admin gates should handle
     * actor type explicitly, not rely on this method.
     */
    public function isCurrentActorAdmin(): bool;

    /**
     * Get the current actor UID.
     *
     * @return int Backend user UID (0 for CLI/system)
     */
    public function getCurrentActorUid(): int;

    /**
     * Get the current actor type.
     *
     * @return string One of: 'backend', 'cli', 'api', 'scheduler'
     */
    public function getCurrentActorType(): string;

    /**
     * Get the current actor's username.
     */
    public function getCurrentActorUsername(): string;

    /**
     * Get groups the current user belongs to.
     *
     * @return int[]
     */
    public function getCurrentUserGroups(): array;
}
