<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Service\Doctor\Check;

use DateTimeImmutable;
use Netresearch\NrVault\Configuration\SecurityProfile;
use Netresearch\NrVault\Security\BreakGlassSession;
use Netresearch\NrVault\Security\BreakGlassStateInterface;
use Netresearch\NrVault\Service\Doctor\Check\BreakGlassCheck;
use Netresearch\NrVault\Service\Doctor\FindingSeverity;
use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Tests\Unit\Traits\DoctorFindingTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(BreakGlassCheck::class)]
final class BreakGlassCheckTest extends TestCase
{
    use DoctorFindingTrait;

    #[Test]
    public function appliesToBothProfiles(): void
    {
        $check = $this->check(null);

        self::assertTrue($check->appliesTo(SecurityProfile::Standard));
        self::assertTrue($check->appliesTo(SecurityProfile::Hardened));
    }

    #[Test]
    public function noOpenWindowPasses(): void
    {
        $findings = $this->check(null)->run($this->doctorContext(SecurityProfile::Hardened));

        self::assertSame(['breakglass.window_open'], $this->findingIds($findings));
        self::assertTrue($findings[0]->isPass());
    }

    /**
     * The reason an open window is reported at all: the backend banner cannot
     * reach a CI gate or a monitoring probe, and a release shipped during someone
     * else's bypass window is a release nobody can attribute afterwards.
     *
     * Warning, not critical — an open window is a justified deliberate act, and a
     * red gate would push operators to close it mid-incident just to deploy.
     */
    #[Test]
    public function anOpenWindowIsAWarningNamingWhoWhyAndUntilWhen(): void
    {
        $expiresAt = (new DateTimeImmutable())->setTimestamp(time() + 900);
        $session = new BreakGlassSession(
            activatedByUid: 7,
            activatedByUsername: 'alice',
            reason: 'INC-4711 rotate leaked key',
            activatedAt: new DateTimeImmutable(),
            expiresAt: $expiresAt,
        );

        $finding = $this->assertFindingSeverity(
            FindingSeverity::Warning,
            $this->check($session)->run($this->doctorContext(SecurityProfile::Hardened)),
            'breakglass.window_open',
        );

        self::assertStringContainsString('alice', $finding->summary);
        self::assertStringContainsString('INC-4711 rotate leaked key', $finding->summary);
        self::assertStringContainsString($expiresAt->format('Y-m-d H:i'), $finding->summary);
        self::assertSame(7, $finding->details['activatedByUid']);
        self::assertSame('alice', $finding->details['activatedByUsername']);
        self::assertSame($expiresAt->getTimestamp(), $finding->details['expiresAt']);
    }

    /**
     * Round the remaining time UP: reporting "0 minutes left" while the bypass is
     * still live understates the exposure being warned about.
     */
    #[Test]
    public function theRemainingMinutesAreRoundedUp(): void
    {
        $session = new BreakGlassSession(
            activatedByUid: 1,
            activatedByUsername: 'bob',
            reason: 'incident',
            activatedAt: new DateTimeImmutable(),
            expiresAt: (new DateTimeImmutable())->setTimestamp(time() + 61),
        );

        $finding = $this->findingById(
            $this->check($session)->run($this->doctorContext(SecurityProfile::Standard)),
            'breakglass.window_open',
        );

        self::assertSame(2, $finding->details['remainingMinutes']);
    }

    private function check(?BreakGlassSession $session): BreakGlassCheck
    {
        $state = self::createStub(BreakGlassStateInterface::class);
        $state->method('getActiveSession')->willReturn($session);
        $state->method('isActive')->willReturn($session instanceof BreakGlassSession);

        return new BreakGlassCheck($state);
    }
}
