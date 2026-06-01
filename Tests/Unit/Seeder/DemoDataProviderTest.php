<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Seeder;

use Netresearch\NrVault\Seeder\DemoDataProvider;
use Netresearch\NrVault\Seeder\DemoEvent;
use Netresearch\NrVault\Seeder\DemoSecretSpec;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(DemoDataProvider::class)]
#[CoversClass(DemoSecretSpec::class)]
#[CoversClass(DemoEvent::class)]
final class DemoDataProviderTest extends TestCase
{
    #[Test]
    public function providesSpecsCoveringEveryBucket(): void
    {
        $specs = (new DemoDataProvider())->specs();

        self::assertGreaterThanOrEqual(15, \count($specs));
        self::assertContainsOnlyInstancesOf(DemoSecretSpec::class, $specs);

        $identifiers = array_map(static fn (DemoSecretSpec $s): string => $s->identifier, $specs);
        self::assertSame($identifiers, array_unique($identifiers), 'identifiers must be unique');

        // at least one never-read aged (dead) specimen
        self::assertNotEmpty(array_filter($specs, static fn (DemoSecretSpec $s): bool => $s->readCount === 0 && $s->createdDaysAgo >= 60));
        // at least one expired specimen
        self::assertNotEmpty(array_filter($specs, static fn (DemoSecretSpec $s): bool => $s->expiresInDays !== null && $s->expiresInDays < 0));
        // at least one manual-only specimen (events: backend reads, no automated)
        self::assertNotEmpty(array_filter(
            $specs,
            static fn (DemoSecretSpec $s): bool =>
            $s->events !== []
            && array_filter($s->events, static fn ($e): bool => $e->action === 'read' && $e->actorType === 'backend') !== []
            && array_filter($s->events, static fn ($e): bool => $e->action === 'read' && \in_array($e->actorType, ['api', 'cli', 'scheduler'], true)) === [],
        ));
        // at least one healthy actively-read specimen
        self::assertNotEmpty(array_filter($specs, static fn (DemoSecretSpec $s): bool => $s->readCount >= 20 && $s->lastReadDaysAgo !== null && $s->lastReadDaysAgo <= 5));
    }
}
