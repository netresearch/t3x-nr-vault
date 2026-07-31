<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Security;

use DateTimeImmutable;
use Netresearch\NrVault\Security\BreakGlassSession;
use Netresearch\NrVault\Security\BreakGlassState;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use RuntimeException;
use TYPO3\CMS\Core\Registry;

/**
 * Registry-backed break-glass state.
 *
 * Time is frozen by crafting the stored expiry relative to `time()` rather than
 * by injecting a clock: expiry is a read-time comparison against the real clock
 * by design (no cron can stall and silently extend a window), so the test
 * exercises the same comparison production does.
 */
#[CoversClass(BreakGlassState::class)]
#[AllowMockObjectsWithoutExpectations]
final class BreakGlassStateTest extends TestCase
{
    private Registry&MockObject $registry;

    private BreakGlassState $subject;

    protected function setUp(): void
    {
        parent::setUp();

        $this->registry = $this->createMock(Registry::class);
        $this->subject = new BreakGlassState($this->registry);
    }

    #[Test]
    public function reportsAnUnexpiredSessionAsActive(): void
    {
        $this->givenStoredPayload($this->payload(expiresIn: 600));

        $session = $this->subject->getActiveSession();

        self::assertInstanceOf(BreakGlassSession::class, $session);
        self::assertSame('alice', $session->activatedByUsername);
        self::assertSame('INC-4711', $session->reason);
        self::assertTrue($this->subject->isActive());
    }

    #[Test]
    public function reportsAnExpiredSessionAsInactive(): void
    {
        // The whole point of read-time expiry: no cleanup job ran, the row is
        // still there, and the bypass is nonetheless gone.
        $this->givenStoredPayload($this->payload(expiresIn: -1));

        self::assertNull($this->subject->getActiveSession());
        self::assertFalse($this->subject->isActive());
    }

    #[Test]
    public function readsAreFreeOfSideEffects(): void
    {
        // `canRead()` reaches this on every secret access, including in the
        // frontend — a lazy purge-on-read would put a DB write on that path.
        $this->givenStoredPayload($this->payload(expiresIn: -1));
        $this->registry->expects(self::never())->method('remove');
        $this->registry->expects(self::never())->method('set');

        $this->subject->isActive();
    }

    #[Test]
    public function reportsInactiveWhenNothingIsStored(): void
    {
        $this->givenStoredPayload(null);

        self::assertNull($this->subject->getActiveSession());
        self::assertFalse($this->subject->isActive());
    }

    #[Test]
    public function reportsInactiveForAMalformedPayload(): void
    {
        $this->givenStoredPayload(['reason' => 'incident']);

        self::assertFalse($this->subject->isActive());
    }

    #[Test]
    public function reportsInactiveForANonArrayPayload(): void
    {
        $this->givenStoredPayload('yes');

        self::assertFalse($this->subject->isActive());
    }

    #[Test]
    public function failsClosedWhenTheRegistryIsUnreadable(): void
    {
        // Bootstrap contexts (install tool, upgrade wizards, a CLI run before
        // the schema exists) must not turn an unreadable `sys_registry` into
        // either a fatal error in an unrelated code path or an open window.
        $this->registry
            ->method('get')
            ->willThrowException(new RuntimeException('sys_registry missing', 1753900099));

        self::assertFalse($this->subject->isActive());
    }

    #[Test]
    public function readsTheVaultNamespace(): void
    {
        $this->registry
            ->expects(self::once())
            ->method('get')
            ->with(BreakGlassState::REGISTRY_NAMESPACE, BreakGlassState::REGISTRY_KEY)
            ->willReturn(null);

        self::assertFalse($this->subject->isActive());
    }

    #[Test]
    public function storesTheSessionPayloadUnderTheVaultNamespace(): void
    {
        $session = new BreakGlassSession(
            activatedByUid: 7,
            activatedByUsername: 'alice',
            reason: 'INC-4711',
            activatedAt: (new DateTimeImmutable())->setTimestamp(1_760_000_000),
            expiresAt: (new DateTimeImmutable())->setTimestamp(1_760_000_900),
        );

        $this->registry
            ->expects(self::once())
            ->method('set')
            ->with(
                BreakGlassState::REGISTRY_NAMESPACE,
                BreakGlassState::REGISTRY_KEY,
                $session->toArray(),
            );

        $this->subject->store($session);
    }

    #[Test]
    public function clearRemovesTheRegistryEntry(): void
    {
        $this->registry
            ->expects(self::once())
            ->method('remove')
            ->with(BreakGlassState::REGISTRY_NAMESPACE, BreakGlassState::REGISTRY_KEY);

        $this->subject->clear();
    }

    private function givenStoredPayload(mixed $payload): void
    {
        // No `with()` constraint here — the namespace/key contract of the read
        // is asserted once in `readsTheVaultNamespace()`; repeating it in every
        // stub only adds mock configuration noise.
        $this->registry
            ->method('get')
            ->willReturn($payload);
    }

    /**
     * @return array<string, int|string>
     */
    private function payload(int $expiresIn): array
    {
        $now = time();

        return [
            'activatedByUid' => 7,
            'activatedByUsername' => 'alice',
            'reason' => 'INC-4711',
            'activatedAt' => $now - 60,
            'expiresAt' => $now + $expiresIn,
        ];
    }
}
