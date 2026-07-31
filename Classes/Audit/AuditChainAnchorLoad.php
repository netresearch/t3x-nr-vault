<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

/**
 * Result of a read-only anchor load.
 *
 * `$raw` carries the bytes exactly as they were stored. The verifier compares
 * two consecutive loads byte-wise to decide whether a re-seal committed while
 * it was reading (see the double-read stability rule in
 * `AuditLogService::verifyAnchor()`); comparing the parsed value objects would
 * not distinguish "unchanged" from "rewritten to the same tip".
 */
final readonly class AuditChainAnchorLoad
{
    public function __construct(
        public AuditChainAnchorStatus $status,
        public ?AuditChainAnchor $anchor = null,
        public string $raw = '',
    ) {}
}
