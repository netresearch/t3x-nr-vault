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
     * Granted to owner, admin/system maintainer when their bypass applies, and
     * write-tier groups (`writeGroups`). A trusted CLI operator additionally
     * follows allowCliAccess/cliAccessGroups. Read-tier groups and the frontend
     * cannot write (ADR-005 least-privilege split).
     */
    public function canWrite(Secret $secret): bool;

    /**
     * Check if the current actor can DELETE a secret.
     *
     * The most restrictive per-user tier: owner or an active admin/system-
     * maintainer bypass. Neither read- nor write-tier groups can delete.
     * A trusted CLI operator may delete only when CLI access is allowed and
     * cliAccessGroups is empty; the separate operation permission still applies.
     */
    public function canDelete(Secret $secret): bool;

    /**
     * Check if current user can create secrets.
     */
    public function canCreate(): bool;

    /**
     * Is the current actor granted an OPERATION permission?
     *
     * Orthogonal to the per-secret tiers above: canRead() answers whether the
     * actor may touch THIS secret; isGranted() answers whether it may perform
     * this KIND of operation. Both gates apply: revealing needs SecretReveal
     * and canRead() for that identifier.
     *
     * Resolution, in precedence order:
     *
     * - Active TechnicalActorContext::runAs() scope: an active admin bypass
     *   grants every operation. Otherwise SecretUse is implicit, and other
     *   operations require matching tx_nrvault custom options on the actor's
     *   existing groups. Missing groups/database access grant no extra operation.
     * - Frontend request: false, including an ambient backend session.
     * - Trusted CLI operator without an authenticated backend user: both
     *   allowCliAccess and membership in cliAllowedOperations are required.
     * - Authenticated backend user: disabled users are refused; an active
     *   admin/system-maintainer bypass grants every operation. Other users need
     *   the matching tx_nrvault custom permission option in their groupData.
     * - No attributable actor outside a real CLI context: false.
     *
     * The admin/system-maintainer bypass, here and in the per-secret tiers, is
     * removable: in SecurityProfile::Hardened with disableAdminOverride set,
     * it requires an active BreakGlassServiceInterface window. Group grants
     * and the technical actor's implicit SecretUse are independent of that bypass.
     */
    public function isGranted(VaultPermission $permission): bool;

    /**
     * Does the current actor hold the admin bypass?
     *
     * An active technical actor is evaluated first using its admin flag;
     * otherwise this checks the authenticated backend user's isAdmin() flag.
     * A disabled backend user and an unattributed CLI/system actor answer false.
     *
     * This is a bypass question, not a role lookup. In the hardened profile
     * with disableAdminOverride set, either admin identity answers false unless
     * a break-glass window is open. Do not use it as a user label or for audit
     * attribution; use the actor accessors instead.
     */
    public function isCurrentActorAdmin(): bool;

    /**
     * Get the current actor UID.
     *
     * @return int Backend/technical user UID, or 0 for an unattributed CLI/system actor
     */
    public function getCurrentActorUid(): int;

    /**
     * Get the current actor type.
     *
     * 'technical' marks an active TechnicalActorContext::runAs() scope and
     * supersedes ambient detection. CLI scheduler/worker execution is 'cli';
     * a backend-user instance is 'backend', otherwise this is 'api'. The type
     * label alone does not establish authentication or an enabled user.
     *
     * @return string One of: 'backend', 'cli', 'api', 'technical'
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
