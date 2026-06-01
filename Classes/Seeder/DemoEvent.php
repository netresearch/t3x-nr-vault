<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Seeder;

/**
 * One backdated audit event in a demo secret's history.
 */
final readonly class DemoEvent
{
    /**
     * @param string $action AuditAction backing value (read, rotate, delete, ...)
     * @param string $actorType backend|cli|api|scheduler
     */
    public function __construct(
        public string $action,
        public string $actorType,
        public string $actorUsername,
        public int $actorUid,
        public int $daysAgo,
        public bool $success = true,
    ) {}
}
