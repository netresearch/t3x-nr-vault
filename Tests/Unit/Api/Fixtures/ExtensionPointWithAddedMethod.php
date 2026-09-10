<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\Fixtures;

use Netresearch\NrVault\Attribute\ExtensionPoint;

/**
 * ExtensionPointFixture plus one method. Additive for every caller, and a
 * fatal error for every class that implemented the baseline.
 */
#[ExtensionPoint]
interface ExtensionPointWithAddedMethod
{
    public function label(): string;

    public function shout(): string;
}
