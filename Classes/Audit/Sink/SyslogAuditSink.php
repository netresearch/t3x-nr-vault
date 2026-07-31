<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Sink;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Configuration\ExtensionConfigurationInterface;

/**
 * Mirrors audit evidence to the local syslog as RFC 5424 structured data.
 *
 * The cheapest useful external sink: on any host with a log shipper (rsyslog,
 * syslog-ng, journald + vector, a container runtime's log driver) the audit
 * chain leaves the TYPO3 database with zero additional infrastructure, and a
 * database-write attacker can no longer erase the evidence without also owning
 * the log pipeline.
 *
 * Facility is fixed at `LOG_LOCAL0` — the conventional slot for
 * application-defined audit streams, and the one a collector rule can rely on
 * without a per-installation lookup. Only the `openlog()` ident is configurable
 * (it becomes RFC 5424's APP-NAME), which is the field operators actually need
 * to vary when several TYPO3 instances share a host.
 *
 * Severity mapping:
 *  - `LOG_INFO` — successful audit entry
 *  - `LOG_WARNING` — failed audit entry (denied access, failed rotation, …)
 *  - `LOG_NOTICE` — chain-tip anchor
 *  - `LOG_CRIT` — integrity alert that is tamper evidence
 *  - `LOG_ERR` — integrity alert that is a delivery failure
 *
 * Message construction lives in {@see Rfc5424Formatter} (see its docblock for
 * the SD-ID choice and the escaping rules).
 */
final readonly class SyslogAuditSink implements AuditSinkInterface
{
    public const IDENTIFIER = 'syslog';

    public function __construct(
        private ExtensionConfigurationInterface $extensionConfiguration,
        private Rfc5424Formatter $formatter,
    ) {}

    public function publish(AuditLogEntry $entry, string $chainTip): void
    {
        $this->emit(
            $entry->success ? LOG_INFO : LOG_WARNING,
            $this->formatter->formatEntry($entry, $chainTip),
        );
    }

    public function publishAnchor(ChainTipAnchor $anchor): void
    {
        $this->emit(LOG_NOTICE, $this->formatter->formatAnchor($anchor));
    }

    public function publishAlert(AuditIntegrityAlert $alert): void
    {
        $this->emit(
            $alert->reason->isTamperEvidence() ? LOG_CRIT : LOG_ERR,
            $this->formatter->formatAlert($alert),
        );
    }

    public function getIdentifier(): string
    {
        return self::IDENTIFIER;
    }

    public function isEnabled(): bool
    {
        // No usability probe beyond the toggle: `openlog()` against a missing
        // socket does not fail here but at `syslog()` time, which the registry
        // already reports as a sink failure. Claiming "enabled but unusable"
        // would need a test write on every isEnabled() call.
        return $this->extensionConfiguration->isAuditSinkSyslogEnabled();
    }

    /**
     * Open the log with our ident, write, and close again.
     *
     * `closelog()` is deliberate rather than wasteful: `openlog()` mutates
     * process-global state, so leaving our ident installed would relabel
     * unrelated `syslog()` calls made later in the same request (TYPO3 core,
     * other extensions) as nr-vault audit records — silently corrupting the
     * audit stream a collector trusts.
     */
    private function emit(int $priority, string $message): void
    {
        openlog($this->extensionConfiguration->getAuditSinkSyslogIdent(), LOG_PID | LOG_ODELAY, LOG_LOCAL0);

        try {
            syslog($priority, $message);
        } finally {
            closelog();
        }
    }
}
