<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Audit;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\Sink\AuditSinkInterface;

/**
 * An external audit destination as a consuming extension ships one. It keeps
 * what it receives in memory, where the functional test reads it.
 */
final class RecordingAuditSink implements AuditSinkInterface
{
    /** @var list<array{identifier: string, action: string, chainTip: string}> */
    public array $entries = [];

    /** @var list<ChainTipAnchor> */
    public array $anchors = [];

    /** @var list<AuditIntegrityAlert> */
    public array $alerts = [];

    public function publish(AuditLogEntry $entry, string $chainTip): void
    {
        $this->entries[] = [
            'identifier' => $entry->secretIdentifier,
            'action' => $entry->action,
            'chainTip' => $chainTip,
        ];
    }

    public function publishAnchor(ChainTipAnchor $anchor): void
    {
        $this->anchors[] = $anchor;
    }

    public function publishAlert(AuditIntegrityAlert $alert): void
    {
        $this->alerts[] = $alert;
    }

    public function getIdentifier(): string
    {
        return 'nr_vault_consumer_fixture';
    }

    public function isEnabled(): bool
    {
        return true;
    }
}
