<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Audit;

use SensitiveParameter;

/**
 * Caller-supplied inputs for a single audit-log write.
 *
 * Internal value object used between `AuditLogService::log()` (public API)
 * and `AuditLogService::buildEntryData()` (private row builder). Exists to
 * keep the row builder under PHP's "many parameters" smell threshold while
 * preserving the public `log()` signature.
 *
 * @internal
 */
final readonly class AuditLogInputs
{
    public function __construct(
        public string $secretIdentifier,
        public string $action,
        public bool $success,
        public ?string $errorMessage = null,
        public ?string $reason = null,
        #[SensitiveParameter]
        public ?string $hashBefore = null,
        #[SensitiveParameter]
        public ?string $hashAfter = null,
        public ?AuditContextInterface $context = null,
    ) {}
}
