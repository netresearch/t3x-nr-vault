<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Controller;

use DateTimeImmutable;
use Netresearch\NrVault\Controller\BreakGlassBannerProvider;
use Netresearch\NrVault\Security\BreakGlassSession;
use Netresearch\NrVault\Security\BreakGlassStateInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(BreakGlassBannerProvider::class)]
#[AllowMockObjectsWithoutExpectations]
final class BreakGlassBannerProviderTest extends TestCase
{
    #[Test]
    public function reportsInactiveWithACompleteShape(): void
    {
        // The Fluid partial reads every key unconditionally; a missing one would
        // render as an empty string and could turn a live warning into a
        // half-blank box.
        $banner = $this->createSubject(null)->forView();

        self::assertFalse($banner['active']);
        self::assertSame(
            ['active', 'username', 'uid', 'reason', 'expiresAt', 'remainingMinutes'],
            array_keys($banner),
        );
    }

    #[Test]
    public function exposesTheOpenWindowForTheBanner(): void
    {
        $expiresAt = time() + 601;
        $banner = $this->createSubject($this->session($expiresAt))->forView();

        self::assertTrue($banner['active']);
        self::assertSame('alice', $banner['username']);
        self::assertSame(7, $banner['uid']);
        self::assertSame('INC-4711 rotate leaked key', $banner['reason']);
        self::assertSame(date('Y-m-d H:i', $expiresAt), $banner['expiresAt']);
    }

    #[Test]
    public function roundsTheRemainingMinutesUp(): void
    {
        // Showing "0 minutes left" while the bypass is still live understates
        // the exposure the banner exists to warn about.
        $banner = $this->createSubject($this->session(time() + 1))->forView();

        self::assertSame(1, $banner['remainingMinutes']);
    }

    private function createSubject(?BreakGlassSession $session): BreakGlassBannerProvider
    {
        $state = $this->createMock(BreakGlassStateInterface::class);
        $state->method('getActiveSession')->willReturn($session);

        return new BreakGlassBannerProvider($state);
    }

    private function session(int $expiresAt): BreakGlassSession
    {
        return new BreakGlassSession(
            activatedByUid: 7,
            activatedByUsername: 'alice',
            reason: 'INC-4711 rotate leaked key',
            activatedAt: new DateTimeImmutable(),
            expiresAt: (new DateTimeImmutable())->setTimestamp($expiresAt),
        );
    }
}
