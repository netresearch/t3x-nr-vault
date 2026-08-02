<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Event;

use DateTimeImmutable;
use DateTimeZone;
use Netresearch\NrVault\Event\BreakGlassDeactivatedEvent;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

/**
 * Closing a window early is itself an auditable act, so the event carries the
 * same four facts as the activation — including `expiresAt`, which here means
 * "when it WOULD have lapsed". That distinction only holds if the value is
 * passed through unchanged rather than replaced by the closing time.
 */
#[CoversClass(BreakGlassDeactivatedEvent::class)]
final class BreakGlassDeactivatedEventTest extends TestCase
{
    #[Test]
    public function everyConstructorArgumentIsReadableUnchanged(): void
    {
        $expiresAt = new DateTimeImmutable('2026-08-02 14:30:00', new DateTimeZone('UTC'));

        $event = new BreakGlassDeactivatedEvent(42, 'incident.responder', 'incident closed', $expiresAt);

        self::assertSame(42, $event->getActorUid());
        self::assertSame('incident.responder', $event->getActorUsername());
        self::assertSame('incident closed', $event->getReason());
        self::assertSame($expiresAt, $event->getExpiresAt());
    }

    /**
     * The expiry is the window's original deadline, not "now" — a listener
     * subtracting it from the current time learns how much of the window was
     * given back.
     */
    #[Test]
    public function expiryMayLieInTheFutureBecauseTheWindowWasClosedEarly(): void
    {
        $expiresAt = new DateTimeImmutable('+30 minutes');

        $event = new BreakGlassDeactivatedEvent(3, 'admin', 'no longer needed', $expiresAt);

        self::assertGreaterThan(time(), $event->getExpiresAt()->getTimestamp());
        self::assertSame($expiresAt->getTimestamp(), $event->getExpiresAt()->getTimestamp());
    }

    #[Test]
    public function expiryKeepsItsInstantAndTimezone(): void
    {
        $expiresAt = new DateTimeImmutable('2026-08-02 16:45:00', new DateTimeZone('Europe/Berlin'));

        $event = new BreakGlassDeactivatedEvent(1, 'admin', 'reason', $expiresAt);

        self::assertSame($expiresAt->getTimestamp(), $event->getExpiresAt()->getTimestamp());
        self::assertSame('Europe/Berlin', $event->getExpiresAt()->getTimezone()->getName());
    }

    #[Test]
    public function reasonIsCarriedVerbatimIncludingWhitespaceAndUnicode(): void
    {
        $reason = "  Notzugriff beendet — Ursache behoben\n(zweite Zeile)  ";

        $event = new BreakGlassDeactivatedEvent(7, 'ops', $reason, new DateTimeImmutable('@1750000000'));

        self::assertSame($reason, $event->getReason());
    }

    #[Test]
    public function acceptsAZeroActorUidWithoutComplaint(): void
    {
        $event = new BreakGlassDeactivatedEvent(0, '_cli_', 'drill over', new DateTimeImmutable('@0'));

        self::assertSame(0, $event->getActorUid());
        self::assertSame('_cli_', $event->getActorUsername());
    }

    #[Test]
    public function isReadonlyAndFinal(): void
    {
        $reflection = new ReflectionClass(BreakGlassDeactivatedEvent::class);

        self::assertTrue($reflection->isReadOnly());
        self::assertTrue($reflection->isFinal());
    }
}
