<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Seeder;

/**
 * Blueprint for one demo secret and its historic state (relative day offsets;
 * resolved to absolute timestamps by the seeder command).
 */
final readonly class DemoSecretSpec
{
    /**
     * @param list<DemoEvent> $events
     */
    public function __construct(
        public string $identifier,
        public string $value,
        public string $description,
        public string $context,
        public int $createdDaysAgo,
        public int $readCount,
        public ?int $lastReadDaysAgo,
        public ?int $lastRotatedDaysAgo,
        public ?int $expiresInDays,
        public bool $frontendAccessible,
        public array $events,
    ) {}
}
