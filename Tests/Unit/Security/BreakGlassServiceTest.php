<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Security;

use DateTimeImmutable;
use Netresearch\NrVault\Audit\AuditAction;
use Netresearch\NrVault\Audit\AuditLogServiceInterface;
use Netresearch\NrVault\Audit\GenericContext;
use Netresearch\NrVault\Event\BreakGlassActivatedEvent;
use Netresearch\NrVault\Event\BreakGlassDeactivatedEvent;
use Netresearch\NrVault\Exception\AccessDeniedException;
use Netresearch\NrVault\Exception\ValidationException;
use Netresearch\NrVault\Security\AccessControlServiceInterface;
use Netresearch\NrVault\Security\BreakGlassService;
use Netresearch\NrVault\Security\BreakGlassServiceInterface;
use Netresearch\NrVault\Security\BreakGlassSession;
use Netresearch\NrVault\Security\BreakGlassState;
use Netresearch\NrVault\Security\VaultPermission;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\EventDispatcher\EventDispatcherInterface;
use TYPO3\CMS\Core\Registry;

/**
 * Activation policy, mandatory justification, TTL clamp and evidence trail.
 *
 * The audit row and the event are asserted here rather than left to the
 * functional suite because they are not decoration: a break-glass window that
 * opens without them is the plain admin override with extra steps.
 *
 * @see \Netresearch\NrVault\Tests\Functional\Security\BreakGlassServiceTest for the
 *      end-to-end persistence, hash chain and access-control integration
 */
#[CoversClass(BreakGlassService::class)]
#[AllowMockObjectsWithoutExpectations]
final class BreakGlassServiceTest extends TestCase
{
    private const ACTIVATION_REASON = 'INC-4711 rotate leaked key';

    private Registry&MockObject $registry;

    private AccessControlServiceInterface&MockObject $accessControlService;

    private AuditLogServiceInterface&MockObject $auditLogService;

    private EventDispatcherInterface&MockObject $eventDispatcher;

    private BreakGlassService $subject;

    protected function setUp(): void
    {
        parent::setUp();

        // `BreakGlassState` is final and stays real: the only thing worth
        // faking is the database behind it, so the Registry mock IS the seam.
        // That also makes the persistence assertions below observe exactly what
        // production writes.
        $this->registry = $this->createMock(Registry::class);
        $this->accessControlService = $this->createMock(AccessControlServiceInterface::class);
        $this->auditLogService = $this->createMock(AuditLogServiceInterface::class);
        $this->eventDispatcher = $this->createMock(EventDispatcherInterface::class);

        $this->subject = new BreakGlassService(
            new BreakGlassState($this->registry),
            $this->accessControlService,
            $this->auditLogService,
            $this->eventDispatcher,
        );

        unset($GLOBALS['BE_USER']);
    }

    protected function tearDown(): void
    {
        unset($GLOBALS['BE_USER']);
        parent::tearDown();
    }

    #[Test]
    public function anAdminMayActivate(): void
    {
        $this->givenBackendActor(isAdmin: true);
        $this->registry->expects(self::once())->method('set');

        $session = $this->subject->activate(self::ACTIVATION_REASON);

        self::assertSame(self::ACTIVATION_REASON, $session->reason);
        self::assertSame(5, $session->activatedByUid);
        self::assertSame('alice', $session->activatedByUsername);
    }

    #[Test]
    public function aSystemMaintainerMayActivate(): void
    {
        $this->givenBackendActor(isAdmin: false, isSystemMaintainer: true);
        $this->registry->expects(self::once())->method('set');

        $this->subject->activate('incident');
    }

    #[Test]
    public function aRealCliOperatorMayActivate(): void
    {
        // A shell on the host already reaches the master key and settings.php,
        // so CLI is trusted — and deliberately not gated on `allowCliAccess`,
        // which governs unattended secret reads, a different question.
        $this->accessControlService->method('getCurrentActorType')->willReturn('cli');
        $this->accessControlService->method('getCurrentActorUid')->willReturn(0);
        $this->accessControlService->method('getCurrentActorUsername')->willReturn('CLI');
        $this->registry->expects(self::once())->method('set');

        $session = $this->subject->activate('incident');

        self::assertSame('CLI', $session->activatedByUsername);
    }

    #[Test]
    public function aNonAdminBackendUserMayNotActivate(): void
    {
        // Even holding every `custom_options` grant: break-glass is not one of
        // the granular permissions, it is the thing that restores them.
        $this->givenBackendActor(isAdmin: false);
        $this->registry->expects(self::never())->method('set');

        $this->expectException(AccessDeniedException::class);
        $this->expectExceptionCode(1753900001);

        $this->subject->activate('incident');
    }

    #[Test]
    public function aDisabledAdminMayNotActivate(): void
    {
        $this->givenBackendActor(isAdmin: true, disabled: true);
        $this->registry->expects(self::never())->method('set');

        $this->expectException(AccessDeniedException::class);

        $this->subject->activate('incident');
    }

    #[Test]
    public function noActorAtAllMayNotActivate(): void
    {
        $this->accessControlService->method('getCurrentActorType')->willReturn('api');
        $this->registry->expects(self::never())->method('set');

        $this->expectException(AccessDeniedException::class);

        $this->subject->activate('incident');
    }

    #[Test]
    public function aTechnicalActorScopeMayNotActivate(): void
    {
        // `runAs()` is explicitly NOT an authentication boundary — any code with
        // DI access can open a scope, so accepting it would let arbitrary
        // extension code mint its own bypass with a synthetic justification.
        $this->accessControlService->method('getCurrentActorType')->willReturn('technical');
        $this->registry->expects(self::never())->method('set');

        $this->expectException(AccessDeniedException::class);

        $this->subject->activate('incident');
    }

    /**
     * Closing the window is gated like opening it: a non-admin who could end an
     * incident responder's break-glass session mid-incident could deny them the
     * very bypass the incident needs, and the audit row would name the wrong
     * operator as the one who closed it.
     */
    #[Test]
    public function aNonAdminBackendUserMayNotDeactivate(): void
    {
        $this->givenBackendActor(isAdmin: false);
        $this->givenOpenWindow();
        $this->registry->expects(self::never())->method('remove');
        $this->auditLogService->expects(self::never())->method('log');

        $this->expectException(AccessDeniedException::class);

        $this->subject->deactivate('incident over');
    }

    #[Test]
    #[DataProvider('emptyReasonProvider')]
    public function activationRequiresANonEmptyReason(string $reason): void
    {
        $this->givenBackendActor(isAdmin: true);
        $this->registry->expects(self::never())->method('set');

        $this->expectException(ValidationException::class);
        $this->expectExceptionCode(1753900002);

        $this->subject->activate($reason);
    }

    #[Test]
    #[DataProvider('emptyReasonProvider')]
    public function deactivationRequiresANonEmptyReason(string $reason): void
    {
        $this->givenBackendActor(isAdmin: true);
        $this->registry->expects(self::never())->method('remove');

        $this->expectException(ValidationException::class);

        $this->subject->deactivate($reason);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function emptyReasonProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'spaces' => ['   '];
        yield 'tab and newline' => ["\t\n"];
    }

    #[Test]
    public function theReasonIsStoredTrimmed(): void
    {
        $this->givenBackendActor(isAdmin: true);

        $session = $this->subject->activate('  INC-4711  ');

        self::assertSame('INC-4711', $session->reason);
    }

    /**
     * Clamping rather than rejecting: a fat-fingered value during an incident
     * should yield the ceiling, not an error the operator re-reads under
     * pressure. The ceiling is what carries the security property.
     */
    #[Test]
    #[DataProvider('ttlProvider')]
    public function clampsTheTtl(int $requested, int $expectedMinutes): void
    {
        $this->givenBackendActor(isAdmin: true);

        $session = $this->subject->activate('incident', $requested);

        self::assertSame(
            $expectedMinutes * 60,
            $session->expiresAt->getTimestamp() - $session->activatedAt->getTimestamp(),
        );
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function ttlProvider(): iterable
    {
        yield 'zero clamps to the floor' => [0, BreakGlassServiceInterface::MIN_TTL_MINUTES];
        yield 'negative clamps to the floor' => [-30, BreakGlassServiceInterface::MIN_TTL_MINUTES];
        yield 'floor is honoured' => [1, 1];
        yield 'in range' => [30, 30];
        yield 'ceiling is honoured' => [60, 60];
        yield 'above the ceiling clamps down' => [600, BreakGlassServiceInterface::MAX_TTL_MINUTES];
    }

    #[Test]
    public function defaultsToTheDocumentedTtl(): void
    {
        $this->givenBackendActor(isAdmin: true);

        $session = $this->subject->activate('incident');

        self::assertSame(
            BreakGlassServiceInterface::DEFAULT_TTL_MINUTES * 60,
            $session->expiresAt->getTimestamp() - $session->activatedAt->getTimestamp(),
        );
    }

    #[Test]
    public function activationAuditsBeforeGrantingThePower(): void
    {
        // Order matters: the two stores cannot be written atomically, and only
        // this order makes "window open without evidence" impossible.
        $this->givenBackendActor(isAdmin: true);

        $calls = [];
        $this->auditLogService
            ->method('log')
            ->willReturnCallback(static function () use (&$calls): void {
                $calls[] = 'audit';
            });
        $this->registry
            ->method('set')
            ->willReturnCallback(static function () use (&$calls): void {
                $calls[] = 'store';
            });

        $this->subject->activate('incident');

        self::assertSame(['audit', 'store'], $calls);
    }

    #[Test]
    public function activationWritesTheAuditRowWithTheActionAndReason(): void
    {
        $this->givenBackendActor(isAdmin: true);

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with(
                BreakGlassService::AUDIT_PSEUDO_IDENTIFIER,
                AuditAction::BreakGlassActivated->value,
                true,
                null,
                'INC-4711',
            );

        $this->subject->activate('INC-4711');
    }

    #[Test]
    public function activationDispatchesTheEvent(): void
    {
        $this->givenBackendActor(isAdmin: true);

        $dispatched = null;
        $this->eventDispatcher
            ->expects(self::once())
            ->method('dispatch')
            ->willReturnCallback(static function (object $event) use (&$dispatched): object {
                $dispatched = $event;

                return $event;
            });

        $session = $this->subject->activate('INC-4711');

        self::assertInstanceOf(BreakGlassActivatedEvent::class, $dispatched);
        self::assertSame('INC-4711', $dispatched->getReason());
        self::assertSame('alice', $dispatched->getActorUsername());
        self::assertSame(5, $dispatched->getActorUid());
        self::assertSame($session->expiresAt->getTimestamp(), $dispatched->getExpiresAt()->getTimestamp());
    }

    #[Test]
    public function deactivationRevokesBeforeLogging(): void
    {
        $this->givenBackendActor(isAdmin: true);
        $this->givenOpenWindow();

        $calls = [];
        $this->registry
            ->method('remove')
            ->willReturnCallback(static function () use (&$calls): void {
                $calls[] = 'clear';
            });
        $this->auditLogService
            ->method('log')
            ->willReturnCallback(static function () use (&$calls): void {
                $calls[] = 'audit';
            });

        $this->subject->deactivate('done');

        self::assertSame(['clear', 'audit'], $calls);
    }

    #[Test]
    public function deactivationWritesTheAuditRowWithTheActionAndReason(): void
    {
        $this->givenBackendActor(isAdmin: true);
        $this->givenOpenWindow();

        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->with(
                BreakGlassService::AUDIT_PSEUDO_IDENTIFIER,
                AuditAction::BreakGlassDeactivated->value,
                true,
                null,
                'INC-4711 closed',
            );

        $this->subject->deactivate('INC-4711 closed');
    }

    /**
     * The audit row is the whole point of break-glass.
     *
     * The window itself leaves no other trace: once it closes, the only record
     * that an administrator held an override is this row, and it is worth
     * nothing unless it names who, until when, and for how long. Eleven
     * mutations of this context — dropping `actorUid`, or turning any of the
     * pairs into a comparison — survived the suite, which is to say every field
     * could have been lost and every test would still have passed.
     */
    #[Test]
    public function theActivationAuditRowNamesTheOperatorAndTheWindow(): void
    {
        $this->givenBackendActor(isAdmin: true);

        $context = null;
        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->willReturnCallback(
                function (...$arguments) use (&$context): void {
                    $context = $arguments[7];
                },
            );

        $session = $this->subject->activate(self::ACTIVATION_REASON, 15);

        self::assertInstanceOf(GenericContext::class, $context);
        self::assertSame(
            [
                'actorUid' => 5,
                'actorUsername' => 'alice',
                'expiresAt' => $session->expiresAt->getTimestamp(),
                'ttlMinutes' => 15,
            ],
            $context->toArray(),
        );
    }

    /**
     * Deactivation names both operators: the one closing the window and the one
     * who opened it. They are not always the same person, and which of the two
     * a row is missing changes what the record means.
     */
    #[Test]
    public function theDeactivationAuditRowNamesBothOperatorsAndTheWindowItCloses(): void
    {
        $this->givenBackendActor(isAdmin: true);
        // One session, used both as the stored window and as the expectation.
        // `givenOpenWindow()` builds its own, so the two expiry timestamps
        // would differ and the assertion below could only check the key.
        $session = $this->openSession();
        $this->registry->method('get')->willReturn($session->toArray());

        $context = null;
        $this->auditLogService
            ->expects(self::once())
            ->method('log')
            ->willReturnCallback(
                function (...$arguments) use (&$context): void {
                    $context = $arguments[7];
                },
            );

        $this->subject->deactivate('INC-4711 closed');

        self::assertInstanceOf(GenericContext::class, $context);
        $data = $context->toArray();
        self::assertSame(5, $data['actorUid'] ?? null);
        self::assertSame('alice', $data['actorUsername'] ?? null);
        self::assertSame($session->activatedByUid, $data['activatedByUid'] ?? null);
        self::assertSame($session->activatedByUsername, $data['activatedByUsername'] ?? null);
        self::assertSame($session->reason, $data['activationReason'] ?? null);
        self::assertSame($session->expiresAt->getTimestamp(), $data['expiresAt'] ?? null);
    }

    #[Test]
    public function deactivationDispatchesTheEvent(): void
    {
        $this->givenBackendActor(isAdmin: true);
        $this->givenOpenWindow();

        $dispatched = null;
        $this->eventDispatcher
            ->expects(self::once())
            ->method('dispatch')
            ->willReturnCallback(static function (object $event) use (&$dispatched): object {
                $dispatched = $event;

                return $event;
            });

        $this->subject->deactivate('INC-4711 closed');

        self::assertInstanceOf(BreakGlassDeactivatedEvent::class, $dispatched);
        self::assertSame('INC-4711 closed', $dispatched->getReason());
    }

    #[Test]
    public function deactivatingAClosedWindowLeavesNoTrace(): void
    {
        // Closing an already-closed window is the desired end state, not an
        // error — but no audit row and no event may imply a window that was not
        // open.
        $this->givenBackendActor(isAdmin: true);
        $this->registry->method('get')->willReturn(null);

        $this->auditLogService->expects(self::never())->method('log');
        $this->eventDispatcher->expects(self::never())->method('dispatch');
        $this->registry->expects(self::once())->method('remove');

        $this->subject->deactivate('cleanup');
    }

    #[Test]
    public function readAccessorsDelegateToTheState(): void
    {
        $this->givenOpenWindow();

        $session = $this->subject->getActiveSession();

        self::assertInstanceOf(BreakGlassSession::class, $session);
        self::assertSame('INC-4711', $session->reason);
        self::assertTrue($this->subject->isActive());
    }

    private function givenOpenWindow(): void
    {
        $this->registry->method('get')->willReturn($this->openSession()->toArray());
    }

    private function openSession(): BreakGlassSession
    {
        return new BreakGlassSession(
            activatedByUid: 5,
            activatedByUsername: 'alice',
            reason: 'INC-4711',
            activatedAt: new DateTimeImmutable(),
            expiresAt: (new DateTimeImmutable())->setTimestamp(time() + 600),
        );
    }

    private function givenBackendActor(
        bool $isAdmin,
        bool $isSystemMaintainer = false,
        bool $disabled = false,
    ): void {
        $this->accessControlService->method('getCurrentActorType')->willReturn('backend');
        $this->accessControlService->method('getCurrentActorUid')->willReturn(5);
        $this->accessControlService->method('getCurrentActorUsername')->willReturn('alice');

        // Every operation permission granted, to prove the activation policy
        // does not read the granular grants at all — break-glass is not one of
        // them, it is what restores them.
        $GLOBALS['BE_USER'] = $this->createMockBackendUser(
            uid: 5,
            isAdmin: $isAdmin,
            disabled: $disabled,
            isSystemMaintainer: $isSystemMaintainer,
            grantedPermissions: VaultPermission::cases(),
        );
    }
}
