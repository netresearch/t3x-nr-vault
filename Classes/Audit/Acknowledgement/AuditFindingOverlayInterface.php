<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit\Acknowledgement;

use Netresearch\NrVault\Audit\HashChainVerificationResult;

/**
 * Turns the raw result of a hash-chain pass into acknowledgeable items and marks
 * the ones an administrator has acknowledged.
 *
 * Sits ABOVE {@see \Netresearch\NrVault\Audit\AuditLogServiceInterface::verifyHashChain()}
 * on purpose. That method also guards the re-seal paths (HMAC migration,
 * master-key rotation, rotation-gap repair); an acknowledgement must never make
 * it return valid, or the next re-seal would rewrite the broken segment and
 * launder it.
 */
interface AuditFindingOverlayInterface
{
    /**
     * One item per failing row, per uid gap and per chain-level error of the raw
     * result, with the acknowledgement not yet applied.
     *
     * @return list<AuditFindingItem>
     */
    public function chainItems(HashChainVerificationResult $raw): array;

    /**
     * Mark every item that a valid acknowledgement row covers.
     *
     * An acknowledgement row counts only when it sits inside the verified range,
     * is not itself reported as failing by `$raw`, was written at an HMAC epoch
     * whose MAC covers its `reason`, `context` and actor fields, and was chained
     * directly after the tip it recorded. An item is covered only when the
     * acknowledgement lists its key, which includes the stored content of the
     * affected row, and when the row follows the item.
     *
     * @param list<AuditFindingItem> $items
     * @param int                    $fromUid First uid of the verified range (acknowledgement rows below it are ignored)
     *
     * @return list<AuditFindingItem>
     */
    public function apply(array $items, HashChainVerificationResult $raw, int $fromUid = 0): array;
}
