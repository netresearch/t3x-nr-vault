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
use Netresearch\NrVault\Audit\Sink\SyslogCallRecorder;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;
use Netresearch\NrVault\Tests\Unit\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\Attributes\Test;

/**
 * Isolated call capture verifies PHP API calls, priorities and process-global
 * cleanup. It does not establish operating-system or collector delivery.
 * Message serialization is independently covered by Rfc5424FormatterTest.
 */
#[CoversClass(SyslogAuditSink::class)]
#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
final class SyslogAuditSinkTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__ . '/../../Fixtures/SyslogCallRecorder.php';
        SyslogCallRecorder::$calls = [];
    }

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
    public function publishUsesInfoAndClosesItsHandle(): void
    {
        $entry = $this->createEntry();
        $this->createSubject()->publish($entry, 'tip-abc');
        $this->assertEmit(
            LOG_INFO,
            (new Rfc5424Formatter())->formatEntry($entry, 'tip-abc'),
        );
    }

    #[Test]
    public function failedEntriesUseWarning(): void
    {
        $entry = $this->createEntry(false);
        $this->createSubject()->publish($entry, 'tip-abc');
        $this->assertEmit(
            LOG_WARNING,
            (new Rfc5424Formatter())->formatEntry($entry, 'tip-abc'),
        );
    }

    #[Test]
    public function anchorsUseNoticeAndCloseTheirHandle(): void
    {
        $anchor = new ChainTipAnchor(9, 'tip', 1750000000, 3);
        $this->createSubject()->publishAnchor($anchor);
        $this->assertEmit(
            LOG_NOTICE,
            (new Rfc5424Formatter())->formatAnchor($anchor),
        );
    }

    #[Test]
    public function tamperAlertsUseCritical(): void
    {
        $alert = AuditIntegrityAlert::create(
            AuditIntegrityReason::TableReset,
            'chain shrank',
        );
        $this->createSubject()->publishAlert($alert);
        $this->assertEmit(
            LOG_CRIT,
            (new Rfc5424Formatter())->formatAlert($alert),
        );
    }

    #[Test]
    public function deliveryAlertsUseError(): void
    {
        $alert = AuditIntegrityAlert::create(
            AuditIntegrityReason::SinkFailure,
            'collector unavailable',
        );
        $this->createSubject()->publishAlert($alert);
        $this->assertEmit(
            LOG_ERR,
            (new Rfc5424Formatter())->formatAlert($alert),
        );
    }

    #[Test]
    public function identIsReadFromConfigurationOnEveryEmit(): void
    {
        $configuration = $this->createMock(ExtensionConfigurationInterface::class);
        $configuration
            ->expects(self::exactly(2))
            ->method('getAuditSinkSyslogIdent')
            ->willReturnOnConsecutiveCalls('first-instance', 'second-instance');
        $sink = new SyslogAuditSink($configuration, new Rfc5424Formatter());
        $entry = $this->createEntry();
        $anchor = new ChainTipAnchor(1, 'tip', 1, 3);
        $sink->publish($entry, 'tip');
        $sink->publishAnchor($anchor);
        self::assertSame(
            [
                [
                    'openlog',
                    ['first-instance', LOG_PID | LOG_ODELAY, LOG_LOCAL0],
                ],
                [
                    'syslog',
                    [
                        LOG_INFO,
                        (new Rfc5424Formatter())->formatEntry($entry, 'tip'),
                    ],
                ],
                ['closelog', []],
                [
                    'openlog',
                    ['second-instance', LOG_PID | LOG_ODELAY, LOG_LOCAL0],
                ],
                [
                    'syslog',
                    [
                        LOG_NOTICE,
                        (new Rfc5424Formatter())->formatAnchor($anchor),
                    ],
                ],
                ['closelog', []],
            ],
            SyslogCallRecorder::$calls,
        );
    }

    private function assertEmit(int $priority, string $message): void
    {
        self::assertSame(
            [
                ['openlog', ['nr-vault-test', LOG_PID | LOG_ODELAY, LOG_LOCAL0]],
                ['syslog', [$priority, $message]],
                ['closelog', []],
            ],
            SyslogCallRecorder::$calls,
        );
    }

    private function createSubject(bool $enabled = true): SyslogAuditSink
    {
        $configuration = self::createStub(ExtensionConfigurationInterface::class);
        $configuration->method('isAuditSinkSyslogEnabled')->willReturn($enabled);
        $configuration
            ->method('getAuditSinkSyslogIdent')
            ->willReturn('nr-vault-test');

        return new SyslogAuditSink($configuration, new Rfc5424Formatter());
    }

    private function createEntry(bool $success = true): AuditLogEntry
    {
        return new AuditLogEntry(
            uid: 1,
            secretIdentifier: 'api/stripe',
            action: 'read',
            success: $success,
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
            crdate: 1750000000,
            context: [],
        );
    }
}
