<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Event;

use DateTimeImmutable;
use Netresearch\NrVault\Event\MasterKeyRotatedEvent;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(MasterKeyRotatedEvent::class)]
final class MasterKeyRotatedEventTest extends TestCase
{
    #[Test]
    public function constructorSetsProperties(): void
    {
        $rotatedAt = new DateTimeImmutable('2024-01-15 10:30:00');
        $event     = new MasterKeyRotatedEvent(150, 1, $rotatedAt);

        self::assertEquals(150, $event->getSecretsReEncrypted());
        self::assertEquals(1, $event->getActorUid());
        self::assertSame($rotatedAt, $event->getRotatedAt());
    }
}
