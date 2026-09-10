<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\ExtensionPoints;

use Netresearch\NrVault\Audit\Anchor\ChainTipAnchor;
use Netresearch\NrVault\Audit\AuditIntegrityAlert;
use Netresearch\NrVault\Audit\AuditLogEntry;
use Netresearch\NrVault\Audit\Sink\AuditSinkInterface;

/**
 * An audit sink written the way a consuming extension writes one: against
 * the published interface only. It keeps what it receives in memory.
 */
final class SampleAuditSink implements AuditSinkInterface
{
    /** @var list<AuditLogEntry> */
    public array $entries = [];

    /** @var list<ChainTipAnchor> */
    public array $anchors = [];

    /** @var list<AuditIntegrityAlert> */
    public array $alerts = [];

    public function publish(AuditLogEntry $entry, string $chainTip): void
    {
        $this->entries[] = $entry;
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
        return 'sample';
    }

    public function isEnabled(): bool
    {
        return true;
    }
}
