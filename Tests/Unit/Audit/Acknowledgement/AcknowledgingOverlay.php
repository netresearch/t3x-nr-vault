<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Audit\Acknowledgement;

use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingItem;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingOverlay;
use Netresearch\NrVault\Audit\Acknowledgement\AuditFindingOverlayInterface;
use Netresearch\NrVault\Audit\HashChainVerificationResult;

use function in_array;

/**
 * Overlay for unit tests: builds the items like the real one without a
 * database and acknowledges the items starting at the given uids.
 */
final readonly class AcknowledgingOverlay implements AuditFindingOverlayInterface
{
    /**
     * @param list<int> $acknowledgedUids
     */
    public function __construct(private array $acknowledgedUids) {}

    public function chainItems(HashChainVerificationResult $raw): array
    {
        return AuditFindingOverlay::itemsFrom($raw, []);
    }

    public function apply(array $items, HashChainVerificationResult $raw, int $fromUid = 0): array
    {
        return array_map(
            fn (AuditFindingItem $item): AuditFindingItem => in_array($item->rangeStart, $this->acknowledgedUids, true)
                ? $item->withAcknowledgement(99)
                : $item,
            $items,
        );
    }
}
