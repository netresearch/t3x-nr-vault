<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Functional\Fixtures\Extensions\nr_vault_consumer_fixture\Classes\Http;

use Netresearch\NrVault\Http\CancellationSignalInterface;

/**
 * A caller-owned cancellation signal whose state the caller decides up front.
 */
final readonly class PresetCancellationSignal implements CancellationSignalInterface
{
    public function __construct(
        private bool $cancelled,
    ) {}

    public function isCancelled(): bool
    {
        return $this->cancelled;
    }
}
