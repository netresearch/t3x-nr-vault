<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Event;

use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Event\AuditIntegrityAlertEvent;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use ReflectionMethod;

/**
 * The event is what a SIEM / paging listener subscribes to. Two things matter to
 * such a listener: it gets the alert unchanged (it forwards the payload
 * verbatim), and the two convenience accessors agree with the alert they are
 * derived from — a listener that routes on `isTamperEvidence()` must not reach a
 * different verdict than one that reads `getAlert()->reason` itself.
 */
#[CoversClass(AuditIntegrityAlertEvent::class)]
final class AuditIntegrityAlertEventTest extends TestCase
{
    #[Test]
    public function getAlertReturnsTheVeryInstanceItWasConstructedWith(): void
    {
        $alert = new AuditIntegrityAlert(
            AuditIntegrityReason::HashMismatch,
            'row 7 hashes differently',
            1_750_000_000,
            ['affectedRows' => 1],
        );

        $event = new AuditIntegrityAlertEvent($alert);

        self::assertSame($alert, $event->getAlert());
    }

    /**
     * A listener switching on the reason code must see exactly the alert's code,
     * not a re-derived one.
     */
    #[Test]
    #[DataProvider('everyReasonProvider')]
    public function getReasonMirrorsTheAlertsReason(AuditIntegrityReason $reason): void
    {
        $event = new AuditIntegrityAlertEvent(AuditIntegrityAlert::create($reason, 'detail'));

        self::assertSame($reason, $event->getReason());
    }

    /**
     * The discriminator between "page someone" and "log it". It is delegated, so
     * the event can never disagree with the enum about what counts as tampering.
     */
    #[Test]
    #[DataProvider('everyReasonProvider')]
    public function isTamperEvidenceDelegatesToTheReason(AuditIntegrityReason $reason): void
    {
        $event = new AuditIntegrityAlertEvent(AuditIntegrityAlert::create($reason, 'detail'));

        self::assertSame($reason->isTamperEvidence(), $event->isTamperEvidence());
    }

    #[Test]
    public function tamperCodesAreFlaggedAndDeliveryProblemsAreNot(): void
    {
        $tamper = new AuditIntegrityAlertEvent(
            AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'chain shrank from 9 to 2'),
        );
        $delivery = new AuditIntegrityAlertEvent(
            AuditIntegrityAlert::create(AuditIntegrityReason::SinkFailure, 'webhook refused'),
        );

        self::assertTrue($tamper->isTamperEvidence());
        self::assertFalse($delivery->isTamperEvidence());
    }

    /**
     * The event is informational, not vetoable: it exposes no mutator and no
     * cancellation flag, so a listener cannot alter what the dispatch site
     * already committed.
     */
    #[Test]
    public function exposesOnlyReadAccessors(): void
    {
        $methods = array_map(
            static fn (ReflectionMethod $method): string => $method->getName(),
            (new ReflectionClass(AuditIntegrityAlertEvent::class))->getMethods(ReflectionMethod::IS_PUBLIC),
        );
        sort($methods);

        self::assertSame(
            ['__construct', 'getAlert', 'getReason', 'isTamperEvidence'],
            $methods,
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
