<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\EventListener;

use Netresearch\NrVault\Audit\Sink\AuditSinkRegistryInterface;
use Netresearch\NrVault\Event\AuditIntegrityAlertEvent;
use TYPO3\CMS\Core\Attribute\AsEventListener;

/**
 * Forwards every audit-integrity alert to the enabled external sinks.
 *
 * Registered by default so an installation that enables the webhook sink gets
 * SIEM alerting without extra wiring: the same collector that receives audit
 * entries also receives `HASH_MISMATCH`, `UID_GAP`, `TABLE_RESET` and
 * `EPOCH_DOWNGRADE` findings. Sinks that are disabled are skipped by the
 * registry, so the listener is a no-op on a default installation.
 *
 * Delivery failures are contained by
 * {@see AuditSinkRegistryInterface::dispatchAlert()}, which never throws and
 * suppresses the nested `SINK_FAILURE` alert that would otherwise recurse.
 */
#[AsEventListener(identifier: 'nr-vault/audit-integrity-alert-sinks')]
final readonly class AuditIntegrityAlertSinkListener
{
    public function __construct(
        private AuditSinkRegistryInterface $sinkRegistry,
    ) {}

    public function __invoke(AuditIntegrityAlertEvent $event): void
    {
        $this->sinkRegistry->dispatchAlert($event->getAlert());
    }
}
