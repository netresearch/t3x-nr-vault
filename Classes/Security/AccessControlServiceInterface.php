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
     * Check if the current actor can READ a secret.
     *
     * Granted to: owner, admin, system maintainer, read-tier groups
     * (`allowedGroups`) and write-tier groups (`writeGroups`), CLI (when
     * allowed), and any frontend/API context for `frontend_accessible`
     * secrets. The broadest tier (ADR-005 least-privilege split).
     */
    public function canRead(Secret $secret): bool;

    /**
     * Check if the current actor can WRITE/UPDATE a secret.
     *
     * Granted to: owner, admin, system maintainer, and write-tier groups
     * (`writeGroups`). NOT granted to read-tier groups or the frontend
     * (ADR-005 least-privilege split).
     */
    public function canWrite(Secret $secret): bool;

    /**
     * Check if the current actor can DELETE a secret.
     *
     * The most restrictive tier: granted only to owner, admin, and system
     * maintainer. No group tier — neither read- nor write-tier group
     * members can delete (ADR-005 least-privilege split).
     */
    public function canDelete(Secret $secret): bool;

    /**
     * Check if current user can create secrets.
     */
    public function canCreate(): bool;

    /**
     * Is the current actor granted an OPERATION permission?
     *
     * Orthogonal to the per-secret tiers above: `canRead()` answers "may this
     * actor touch THIS secret?", `isGranted()` answers "may this actor perform
     * this KIND of operation at all?". Both gates apply — e.g. revealing a
     * secret needs `VaultPermission::SecretReveal` *and* `canRead()` for that
     * identifier.
     *
     * Resolution (fail-closed at every step, mirroring the actor resolution of
     * the per-secret tiers):
     *
     * - active `TechnicalActorContext::runAs()` scope → the actor's admin flag
     *   decides, with `VaultPermission::SecretUse` granted unconditionally so
     *   headless consumers keep working under their per-secret ACL;
     * - frontend request → `false`, always (no operation permissions in a
     *   context whose output is shared with anonymous visitors);
     * - trusted CLI operator without an authenticated backend user → the
     *   vault's `allowCliAccess` switch decides (off by default);
     * - authenticated backend user → admin / system maintainer are granted
     *   everything, anyone else needs the matching custom permission option
     *   (`tx_nrvault:<permission>`) on one of their groups;
     * - disabled user, no user at all → `false`.
     */
    public function isGranted(VaultPermission $permission): bool;

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
     * 'technical' marks an active `TechnicalActorContext::runAs()` scope
     * and supersedes all ambient detection — the audit log records the
     * named technical identity, not the CLI operator it runs under.
     *
     * @return string One of: 'backend', 'cli', 'api', 'scheduler', 'technical'
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
