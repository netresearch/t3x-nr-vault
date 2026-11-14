<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Acknowledgement;

use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingOverlay;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingOverlayInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;

/**
 * Overlay for unit tests of its consumers: builds the items exactly like the
 * real one but without a database, and acknowledges nothing.
 */
final readonly class PassthroughOverlay implements AuditFindingOverlayInterface
{
    public function chainItems(HashChainVerificationResult $raw): array
    {
        return AuditFindingOverlay::itemsFrom($raw, []);
    }

    public function apply(array $items, HashChainVerificationResult $raw, int $fromUid = 0): array
    {
        return $items;
    }
}
