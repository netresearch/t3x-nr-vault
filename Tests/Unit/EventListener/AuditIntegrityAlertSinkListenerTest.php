<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\EventListener;

use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Event\AuditIntegrityAlertEvent;
use Netresearch\NrVault\EventListener\AuditIntegrityAlertSinkListener;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use TYPO3\CMS\Core\Attribute\AsEventListener;

/**
 * The listener is the default wiring that turns an integrity finding into a SIEM
 * alert. It must forward the alert unchanged and unconditionally: filtering by
 * reason code, or by whether the finding is tamper evidence, is the collector's
 * job — a listener that dropped `SINK_FAILURE` would hide exactly the outage
 * that makes the other codes undetectable.
 */
#[CoversClass(AuditIntegrityAlertSinkListener::class)]
final class AuditIntegrityAlertSinkListenerTest extends TestCase
{
    #[Test]
    public function forwardsTheAlertInstanceUnchangedToTheRegistry(): void
    {
        $alert = new AuditIntegrityAlert(
            AuditIntegrityReason::HashMismatch,
            'row 7 hashes differently',
            1_750_000_000,
            ['affectedRows' => 1],
        );

        $registry = $this->createMock(AuditSinkRegistryInterface::class);
        $registry->expects(self::once())
            ->method('dispatchAlert')
            ->with(self::identicalTo($alert))
            ->willReturn(2);

        (new AuditIntegrityAlertSinkListener($registry))(new AuditIntegrityAlertEvent($alert));
    }

    /**
     * Every reason code is forwarded — availability findings included.
     */
    #[Test]
    #[DataProvider('everyReasonProvider')]
    public function forwardsRegardlessOfTheReasonCode(AuditIntegrityReason $reason): void
    {
        $alert = AuditIntegrityAlert::create($reason, 'detail');

        $registry = $this->createMock(AuditSinkRegistryInterface::class);
        $registry->expects(self::once())
            ->method('dispatchAlert')
            ->with(self::identicalTo($alert))
            ->willReturn(1);

        (new AuditIntegrityAlertSinkListener($registry))(new AuditIntegrityAlertEvent($alert));
    }

    /**
     * A dispatch that reached no sink is not an error here: the registry decides
     * what a delivery failure means and contains it. The listener must not turn
     * a zero into an exception inside the audited operation's write path.
     */
    #[Test]
    public function acceptsAZeroAcceptedCountWithoutThrowing(): void
    {
        $registry = $this->createMock(AuditSinkRegistryInterface::class);
        $registry->expects(self::once())->method('dispatchAlert')->willReturn(0);

        $listener = new AuditIntegrityAlertSinkListener($registry);
        $listener(new AuditIntegrityAlertEvent(
            AuditIntegrityAlert::create(AuditIntegrityReason::SinkFailure, 'webhook refused'),
        ));
    }

    /**
     * Only `dispatchAlert()` is used: the listener must not consult
     * `hasExternalAuditSink()` and skip on a default installation, because the
     * registry already skips disabled sinks itself.
     */
    #[Test]
    public function touchesNoOtherRegistryMethod(): void
    {
        $registry = $this->createMock(AuditSinkRegistryInterface::class);
        $registry->expects(self::once())->method('dispatchAlert')->willReturn(1);
        $registry->expects(self::never())->method('hasExternalAuditSink');
        $registry->expects(self::never())->method('dispatch');
        $registry->expects(self::never())->method('dispatchAnchor');
        $registry->expects(self::never())->method('getEnabledSinkIdentifiers');

        (new AuditIntegrityAlertSinkListener($registry))(new AuditIntegrityAlertEvent(
            AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'chain shrank'),
        ));
    }

    /**
     * One invocation forwards exactly once — no retry loop that would multiply
     * an alert storm across the collector.
     */
    #[Test]
    public function forwardsOncePerInvocation(): void
    {
        $registry = $this->createMock(AuditSinkRegistryInterface::class);
        $registry->expects(self::exactly(3))->method('dispatchAlert')->willReturn(1);

        $listener = new AuditIntegrityAlertSinkListener($registry);
        foreach ([AuditIntegrityReason::UidGap, AuditIntegrityReason::EpochDowngrade, AuditIntegrityReason::BreakGlass] as $reason) {
            $listener(new AuditIntegrityAlertEvent(AuditIntegrityAlert::create($reason, 'detail')));
        }
    }

    /**
     * The registration is what makes this "on by default"; the identifier is the
     * handle an integrator uses to override or remove the listener, so it is API.
     */
    #[Test]
    public function isRegisteredAsAnEventListenerUnderItsPublishedIdentifier(): void
    {
        $attributes = (new ReflectionClass(AuditIntegrityAlertSinkListener::class))
            ->getAttributes(AsEventListener::class);

        self::assertCount(1, $attributes);
        self::assertSame(
            'nr-vault/audit-integrity-alert-sinks',
            $attributes[0]->newInstance()->identifier,
        );
    }

    /**
     * @return iterable<string, array{AuditIntegrityReason}>
     */
    public static function everyReasonProvider(): iterable
    {
        foreach (AuditIntegrityReason::cases() as $reason) {
            yield $reason->value => [$reason];
        }
    }
}
