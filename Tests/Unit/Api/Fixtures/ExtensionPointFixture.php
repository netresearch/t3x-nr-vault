<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\Fixtures;

use Netresearch\NrVault\Attribute\ExtensionPoint;

/**
 * An extension point with one method — the baseline the implementer-side
 * classification is measured against.
 */
#[ExtensionPoint]
interface ExtensionPointFixture
{
    public function label(): string;
}
