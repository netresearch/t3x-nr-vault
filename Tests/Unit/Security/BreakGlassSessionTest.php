<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Security;

use DateTimeImmutable;
use Netresearch\NrVault\Security\BreakGlassSession;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

#[CoversClass(BreakGlassSession::class)]
final class BreakGlassSessionTest extends TestCase
{
    #[Test]
    public function roundTripsThroughTheRegistryPayload(): void
    {
        $session = new BreakGlassSession(
            activatedByUid: 7,
            activatedByUsername: 'alice',
            reason: 'INC-4711 rotate leaked deploy key',
            activatedAt: (new DateTimeImmutable())->setTimestamp(1_760_000_000),
            expiresAt: (new DateTimeImmutable())->setTimestamp(1_760_000_900),
        );

        $restored = BreakGlassSession::fromArray($session->toArray());

        self::assertInstanceOf(BreakGlassSession::class, $restored);
        self::assertSame(7, $restored->activatedByUid);
        self::assertSame('alice', $restored->activatedByUsername);
        self::assertSame('INC-4711 rotate leaked deploy key', $restored->reason);
        self::assertSame(1_760_000_000, $restored->activatedAt->getTimestamp());
        self::assertSame(1_760_000_900, $restored->expiresAt->getTimestamp());
    }

    #[Test]
    public function storesOnlyScalarsSoAnAuditorCanReadTheRegistryRow(): void
    {
        $session = $this->createSession(expiresAt: 1_760_000_900);

        foreach ($session->toArray() as $key => $value) {
            self::assertIsScalar($value, \sprintf('payload key "%s" must be scalar', $key));
        }
    }

    /**
     * A malformed payload must read as "no session", never as an open-ended
     * one: a half-written or hand-edited registry row is exactly the input an
     * attacker would try to widen into a permanent bypass.
     *
     * @param array<array-key, mixed> $payload
     */
    #[Test]
    #[DataProvider('malformedPayloadProvider')]
    public function rejectsAMalformedPayload(array $payload): void
    {
        self::assertNull(BreakGlassSession::fromArray($payload));
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>}>
     */
    public static function malformedPayloadProvider(): iterable
    {
        $valid = [
            'activatedByUid' => 1,
            'activatedByUsername' => 'alice',
            'reason' => 'incident',
            'activatedAt' => 1_760_000_000,
            'expiresAt' => 1_760_000_900,
        ];

        yield 'empty' => [[]];

        foreach (array_keys($valid) as $missing) {
            $payload = $valid;
            unset($payload[$missing]);

            yield 'missing ' . $missing => [$payload];
        }

        yield 'non-numeric expiry' => [[...$valid, 'expiresAt' => 'never']];
        yield 'non-string reason' => [[...$valid, 'reason' => ['incident']]];
        yield 'non-string username' => [[...$valid, 'activatedByUsername' => 42]];
        yield 'non-numeric uid' => [[...$valid, 'activatedByUid' => 'alice']];
    }

    #[Test]
    public function acceptsNumericStringsBecauseTheRegistryMayReturnThem(): void
    {
        $restored = BreakGlassSession::fromArray([
            'activatedByUid' => '7',
            'activatedByUsername' => 'alice',
            'reason' => 'incident',
            'activatedAt' => '1760000000',
            'expiresAt' => '1760000900',
        ]);

        self::assertInstanceOf(BreakGlassSession::class, $restored);
        self::assertSame(7, $restored->activatedByUid);
        self::assertSame(1_760_000_900, $restored->expiresAt->getTimestamp());
    }

    #[Test]
    public function isExpiredWhenTheExpiryHasPassed(): void
    {
        $session = $this->createSession(expiresAt: 1_760_000_900);

        self::assertTrue($session->isExpiredAt($this->at(1_760_000_901)));
    }

    #[Test]
    public function isExpiredExactlyAtTheExpiry(): void
    {
        // Inclusive on purpose: the window is closed at the instant it lapses,
        // not one second later.
        $session = $this->createSession(expiresAt: 1_760_000_900);

        self::assertTrue($session->isExpiredAt($this->at(1_760_000_900)));
    }

    #[Test]
    public function isNotExpiredBeforeTheExpiry(): void
    {
        $session = $this->createSession(expiresAt: 1_760_000_900);

        self::assertFalse($session->isExpiredAt($this->at(1_760_000_899)));
    }

    #[Test]
    public function reportsTheRemainingSeconds(): void
    {
        $session = $this->createSession(expiresAt: 1_760_000_900);

        self::assertSame(300, $session->remainingSeconds($this->at(1_760_000_600)));
    }

    #[Test]
    public function clampsTheRemainingSecondsToZeroOnceExpired(): void
    {
        $session = $this->createSession(expiresAt: 1_760_000_900);

        self::assertSame(0, $session->remainingSeconds($this->at(1_760_009_999)));
    }

    private function createSession(int $expiresAt): BreakGlassSession
    {
        return new BreakGlassSession(
            activatedByUid: 1,
            activatedByUsername: 'alice',
            reason: 'incident',
            activatedAt: $this->at($expiresAt - 900),
            expiresAt: $this->at($expiresAt),
        );
    }

    private function at(int $timestamp): DateTimeImmutable
    {
        return (new DateTimeImmutable())->setTimestamp($timestamp);
    }
}
