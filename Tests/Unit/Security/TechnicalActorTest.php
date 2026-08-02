<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Security;

use Netresearch\NrVault\Security\TechnicalActor;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

/**
 * `AccessControlService` treats this snapshot as equivalent to an authenticated
 * backend user for the duration of a `runAs()` scope, so its three
 * decision-relevant fields — the admin flag and the resolved group ids, plus the
 * uid used for audit attribution — must be exactly what `TechnicalActorContext`
 * read out of `be_users`, and must stay immutable while the scope is open.
 */
#[CoversClass(TechnicalActor::class)]
final class TechnicalActorTest extends TestCase
{
    #[Test]
    public function exposesEveryConstructorArgumentUnchanged(): void
    {
        $actor = new TechnicalActor(42, '_vault_technical', false, [3, 7, 11]);

        self::assertSame(42, $actor->uid);
        self::assertSame('_vault_technical', $actor->username);
        self::assertFalse($actor->admin);
        self::assertSame([3, 7, 11], $actor->groupIds);
    }

    /**
     * The admin flag is the input to the one admin-bypass seam. It is stored as
     * given — never inferred from uid 1 or from an empty group list.
     */
    #[Test]
    public function adminFlagIsStoredAsGivenAndNotInferred(): void
    {
        self::assertTrue((new TechnicalActor(1, 'admin', true, []))->admin);
        self::assertFalse((new TechnicalActor(1, 'admin', false, []))->admin);
    }

    /**
     * A non-admin actor in no group is the least-privileged case and must be
     * representable — it is what an unprivileged technical user resolves to.
     */
    #[Test]
    public function representsAnActorWithoutAnyGroups(): void
    {
        $actor = new TechnicalActor(9, 'restricted', false, []);

        self::assertSame([], $actor->groupIds);
    }

    /**
     * The list is the resolved closure including subgroups; order and duplicates
     * are the resolver's business, so the snapshot must not silently reorder or
     * deduplicate what it was handed.
     */
    #[Test]
    public function groupIdsAreKeptInTheOrderTheResolverProducedThem(): void
    {
        $actor = new TechnicalActor(5, 'svc', false, [11, 3, 11, 2]);

        self::assertSame([11, 3, 11, 2], $actor->groupIds);
    }

    /**
     * Immutability is the point of the snapshot: nothing inside a `runAs()`
     * scope may promote the actor to admin or widen its groups after the
     * identity was validated. Enforced by the engine, so the guarantee is the
     * `readonly` declaration itself — dropping it would silently reopen the
     * privilege fields to a consumer.
     */
    #[Test]
    public function everyFieldIsReadonlyAndTheClassIsFinal(): void
    {
        $reflection = new ReflectionClass(TechnicalActor::class);

        self::assertTrue($reflection->isReadOnly(), 'TechnicalActor must stay a readonly class');
        self::assertTrue($reflection->isFinal(), 'TechnicalActor must not be subclassable');

        foreach (['uid', 'username', 'admin', 'groupIds'] as $property) {
            self::assertTrue(
                $reflection->getProperty($property)->isReadOnly(),
                \sprintf('%s must be readonly', $property),
            );
        }
    }
}
