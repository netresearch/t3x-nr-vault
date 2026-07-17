<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

/**
 * Immutable snapshot of a validated technical-actor identity.
 *
 * Built exclusively by `TechnicalActorContext` from a real, enabled,
 * non-deleted `be_users` record; consumers (notably `AccessControlService`)
 * treat it as equivalent to an authenticated backend user for the duration
 * of a `runAs()` scope.
 */
final readonly class TechnicalActor
{
    /**
     * @param positive-int $uid be_users uid the actor acts as
     * @param string $username be_users username (audit attribution)
     * @param bool $admin be_users admin flag
     * @param list<int> $groupIds resolved be_groups uids (incl. subgroups)
     */
    public function __construct(
        public int $uid,
        public string $username,
        public bool $admin,
        public array $groupIds,
    ) {}
}
