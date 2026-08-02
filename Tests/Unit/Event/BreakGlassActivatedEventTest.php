<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Event;

use DateTimeImmutable;
use DateTimeZone;
use Netresearch\NrVault\Event\BreakGlassActivatedEvent;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;

/**
 * The event carries the four facts an out-of-band alert needs: who opened the
 * window, why, and when it closes by itself. All four have to survive the
 * hand-off verbatim — a paging listener quotes them into an incident ticket, and
 * the justification is the operator's own text, not something to be normalised.
 */
#[CoversClass(BreakGlassActivatedEvent::class)]
final class BreakGlassActivatedEventTest extends TestCase
{
    #[Test]
    public function everyConstructorArgumentIsReadableUnchanged(): void
    {
        $expiresAt = new DateTimeImmutable('2026-08-02 14:30:00', new DateTimeZone('UTC'));

        $event = new BreakGlassActivatedEvent(42, 'incident.responder', 'INC-4711 payment outage', $expiresAt);

        self::assertSame(42, $event->getActorUid());
        self::assertSame('incident.responder', $event->getActorUsername());
        self::assertSame('INC-4711 payment outage', $event->getReason());
        self::assertSame($expiresAt, $event->getExpiresAt());
    }

    /**
     * The expiry is the one field a listener does arithmetic on (window length,
     * "still open?" checks), so its instant and timezone must arrive untouched.
     */
    #[Test]
    public function expiryKeepsItsInstantAndTimezone(): void
    {
        $expiresAt = new DateTimeImmutable('2026-08-02 16:45:00', new DateTimeZone('Europe/Berlin'));

        $event = new BreakGlassActivatedEvent(1, 'admin', 'reason', $expiresAt);

        self::assertSame($expiresAt->getTimestamp(), $event->getExpiresAt()->getTimestamp());
        self::assertSame('Europe/Berlin', $event->getExpiresAt()->getTimezone()->getName());
    }

    /**
     * The justification is free-form operator input and is reproduced byte for
     * byte — no trimming, no case folding, no length clamp.
     */
    #[Test]
    public function reasonIsCarriedVerbatimIncludingWhitespaceAndUnicode(): void
    {
        $reason = "  Schlüsselverlust — Notzugriff\n(zweite Zeile)  ";

        $event = new BreakGlassActivatedEvent(7, 'ops', $reason, new DateTimeImmutable('@1750000000'));

        self::assertSame($reason, $event->getReason());
    }

    /**
     * Nothing is validated at construction: the service decides what a valid
     * window is, the event only reports what it decided. A zero uid (CLI /
     * technical actor) must not be rejected here.
     */
    #[Test]
    public function acceptsAZeroActorUidWithoutComplaint(): void
    {
        $event = new BreakGlassActivatedEvent(0, '_cli_', 'scheduled drill', new DateTimeImmutable('@0'));

        self::assertSame(0, $event->getActorUid());
        self::assertSame('_cli_', $event->getActorUsername());
    }

    /**
     * Readonly: a listener cannot rewrite the announcement before the next
     * listener sees it.
     */
    #[Test]
    public function isReadonlyAndFinal(): void
    {
        $reflection = new ReflectionClass(BreakGlassActivatedEvent::class);

        self::assertTrue($reflection->isReadOnly());
        self::assertTrue($reflection->isFinal());
    }
}
