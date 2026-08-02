<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Sink;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditIntegrityReason;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\Sink\Rfc5424Formatter;
use Netresearch\NrVault\Audit\Sink\SyslogAuditSink;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;

/**
 * `syslog()` writes to a process-global handle whose output a unit test cannot
 * read back, so the message CONTENT is asserted where it is pure and
 * observable — {@see Rfc5424FormatterTest} — and this class covers what remains
 * observable about the sink itself: enablement, the identifier, and that each
 * publish path runs the real `openlog()`/`syslog()`/`closelog()` sequence to
 * completion without throwing.
 *
 * The publish tests do write to the host's syslog. That is intentional: it is the
 * only way to exercise the real emit path, and one `LOG_LOCAL0` line per test is
 * harmless.
 */
#[CoversClass(SyslogAuditSink::class)]
final class SyslogAuditSinkTest extends TestCase
{
    #[Test]
    public function identifierIsStable(): void
    {
        self::assertSame('syslog', $this->createSubject()->getIdentifier());
    }

    #[Test]
    public function disabledConfigurationReportsNotEnabled(): void
    {
        self::assertFalse($this->createSubject(enabled: false)->isEnabled());
    }

    #[Test]
    public function enabledConfigurationReportsEnabled(): void
    {
        self::assertTrue($this->createSubject()->isEnabled());
    }

    #[Test]
    public function publishCompletesTheEmitSequence(): void
    {
        $this->createSubject()->publish($this->createEntry(), 'tip-abc');

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function publishAnchorCompletesTheEmitSequence(): void
    {
        $this->createSubject()->publishAnchor(new ChainTipAnchor(9, 'tip', 1_750_000_000, 3));

        $this->expectNotToPerformAssertions();
    }

    #[Test]
    public function publishAlertCompletesTheEmitSequence(): void
    {
        $this->createSubject()->publishAlert(
            AuditIntegrityAlert::create(AuditIntegrityReason::TableReset, 'chain shrank'),
        );

        $this->expectNotToPerformAssertions();
    }

    /**
     * `openlog()` mutates process-global state, so the ident must be taken from
     * the configuration layer (which substitutes the default for a blank value)
     * on every emit rather than captured once.
     */
    #[Test]
    public function identIsReadFromConfigurationOnEveryEmit(): void
    {
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration->method('isAuditSinkSyslogEnabled')->willReturn(true);
        $configuration->expects(self::exactly(2))
            ->method('getAuditSinkSyslogIdent')
            ->willReturn('nr-vault');

        $sink = new SyslogAuditSink($configuration, new Rfc5424Formatter());
        $sink->publish($this->createEntry(), 'tip');
        $sink->publishAnchor(new ChainTipAnchor(1, 'tip', 1, 3));
    }

    private function createSubject(bool $enabled = true): SyslogAuditSink
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('isAuditSinkSyslogEnabled')->willReturn($enabled);
        $configuration->method('getAuditSinkSyslogIdent')->willReturn('nr-vault-test');

        return new SyslogAuditSink($configuration, new Rfc5424Formatter());
    }

    private function createEntry(): AuditLogEntry
    {
        return new AuditLogEntry(
            uid: 1,
            secretIdentifier: 'api/stripe',
            action: 'read',
            success: true,
            errorMessage: null,
            reason: null,
            actorUid: 7,
            actorType: 'be_user',
            actorUsername: 'editor',
            actorRole: 'groups:1',
            ipAddress: '203.0.113.7',
            userAgent: 'Mozilla/5.0',
            requestId: 'req-1',
            previousHash: 'prev',
            entryHash: 'hash-1',
            hashBefore: '',
            hashAfter: '',
            crdate: 1_750_000_000,
            context: [],
        );
    }
}
