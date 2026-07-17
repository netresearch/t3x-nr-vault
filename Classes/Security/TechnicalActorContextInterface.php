<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Security;

use Netresearch\NrVault\Exception\TechnicalActorException;

/**
 * Scoped technical-actor identity for headless vault consumers.
 *
 * Messenger workers, scheduler runs, and CLI jobs that need vault-gated
 * secrets under a NAMED backend-user identity (per-consumer audit
 * attribution, group-scoped vault ACL) call `runAs()` instead of mutating
 * `$GLOBALS['BE_USER']`. `AccessControlService` consults the active actor
 * directly — before its BE_USER/CLI branches — so the ambient global is
 * never touched and no privileged identity can leak past the scope.
 *
 * Trust model: `runAs()` is NOT an authentication mechanism. Any PHP code
 * with access to this service can act as any enabled backend user — the
 * same power `$GLOBALS['BE_USER']` mutation already grants every
 * extension. The value of the API is scoping (identity always restored,
 * even on exceptions), validation (deleted/disabled/time-restricted/
 * off-root users are refused), and audit attribution
 * (`actor_type` = `technical`).
 */
interface TechnicalActorContextInterface
{
    /**
     * Run `$fn` while vault access checks evaluate as backend user `$beUserUid`.
     *
     * The user record is loaded and validated on entry; the callable never
     * runs when validation fails. Nested calls stack: the innermost actor
     * wins, and each scope restores the previous actor on exit — including
     * when `$fn` throws.
     *
     * @template T
     *
     * @param positive-int $beUserUid be_users uid to act as
     * @param callable(): T $fn
     *
     * @throws TechnicalActorException if `$beUserUid` is not positive, or the
     *                                 record is missing/deleted, disabled,
     *                                 outside its start/end time window, or
     *                                 not at root level (`pid` != 0)
     *
     * @return T
     */
    public function runAs(int $beUserUid, callable $fn): mixed;

    /**
     * The innermost active technical actor, or null outside any `runAs()` scope.
     */
    public function getCurrentActor(): ?TechnicalActor;
}
