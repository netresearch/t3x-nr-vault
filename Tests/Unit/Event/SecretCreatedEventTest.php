<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Event;

use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Event\SecretCreatedEvent;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(SecretCreatedEvent::class)]
final class SecretCreatedEventTest extends TestCase
{
    #[Test]
    public function constructorSetsProperties(): void
    {
        $secret = new Secret(identifier: 'api-key');

        $event = new SecretCreatedEvent('api-key', $secret, 5);

        self::assertEquals('api-key', $event->getIdentifier());
        self::assertSame($secret, $event->getSecret());
        self::assertEquals(5, $event->getActorUid());
    }
}
