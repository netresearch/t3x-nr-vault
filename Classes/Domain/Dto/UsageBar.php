<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Domain\Dto;

/**
 * One horizontal bar in a distribution chart (rendered as a Bootstrap progress bar).
 */
final readonly class UsageBar
{
    public function __construct(
        public string $label,
        public int $value,
        public int $percent,
    ) {}
}
