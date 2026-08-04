<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Service;

use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Security\TechnicalActorContextInterface;
use Netresearch\NrVault\Service\VaultService;
use Netresearch\NrVault\Service\VaultServiceInterface;
use Netresearch\NrVault\Tests\Functional\AbstractVaultFunctionalTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use Throwable;

/**
 * Cross-actor isolation of the read path inside ONE long-running process.
 *
 * The scenario is a Symfony Messenger / Scheduler worker: the shared
 * VaultService singleton serves several technical-actor scopes in sequence.
 * A plaintext read performed for actor A must never leak to a later actor B —
 * every retrieve() has to re-run the per-secret ACL, the expiry check and the
 * audit trail against the CURRENT actor. (Regression test for the plaintext
 * request cache that short-circuited all of these before any check ran.)
 *
 * Fixture: be_users 10 `tech_owner` and 13 `tech_other`, both enabled,
 * root-level, without any group that could widen access.
 */
#[CoversClass(VaultService::class)]
final class VaultServiceCrossActorTest extends AbstractVaultFunctionalTestCase
{
    protected ?string $backendUserFixture = __DIR__ . '/Fixtures/cross_actor_users.csv';

    /** No ambient backend user: headless-worker reality. */
    protected ?int $backendUserUid = null;

    #[Test]
    public function actorWithoutPermissionIsDeniedAfterAnotherActorReadTheSecret(): void
    {
        $vault = $this->get(VaultServiceInterface::class);
        $context = $this->get(TechnicalActorContextInterface::class);

        // Actor A creates and reads its own secret: the plaintext passes
        // through the shared service instance.
        $context->runAs(10, static function () use ($vault): void {
            $vault->store('cross_actor_owned', 'owner-only-value');
            self::assertSame('owner-only-value', $vault->retrieve('cross_actor_owned'));
        });

        // Actor B follows in the SAME process on the SAME service instance.
        // B is neither owner nor group member, so the read must be denied —
        // never satisfied from anything actor A's read left behind.
        // (Caught as Throwable and narrowed by assertion: PHPStan cannot see
        // through runAs()'s callable indirection that retrieve() throws.)
        $denied = null;

        try {
            $context->runAs(13, static fn (): ?string => $vault->retrieve('cross_actor_owned'));
        } catch (Throwable $throwable) {
            $denied = $throwable;
        }

        self::assertInstanceOf(
            AccessDeniedException::class,
            $denied,
            "actor 13 must not read actor 10's secret",
        );

        // The denial is attributed to actor B in the audit trail.
        $auditLog = $this->get(AuditLogServiceInterface::class);
        $deniedEntries = array_values(array_filter(
            $auditLog->query(),
            static fn ($entry): bool => $entry->action === 'access_denied'
                && $entry->secretIdentifier === 'cross_actor_owned',
        ));

        self::assertCount(1, $deniedEntries);
        self::assertSame(13, $deniedEntries[0]->actorUid);
    }

    #[Test]
    public function everyRetrieveWritesItsOwnReadAuditEntry(): void
    {
        $vault = $this->get(VaultServiceInterface::class);
        $context = $this->get(TechnicalActorContextInterface::class);

        $context->runAs(10, static function () use ($vault): void {
            $vault->store('cross_actor_audited', 'audited-value');
            $vault->retrieve('cross_actor_audited');
            $vault->retrieve('cross_actor_audited');
        });

        // Two reads => two read audit entries. A plaintext cache would have
        // collapsed the second read into a silent, unaudited hit.
        $auditLog = $this->get(AuditLogServiceInterface::class);
        $readEntries = array_values(array_filter(
            $auditLog->query(),
            static fn ($entry): bool => $entry->action === 'read'
                && $entry->success
                && $entry->secretIdentifier === 'cross_actor_audited',
        ));

        self::assertCount(2, $readEntries);
    }
}
