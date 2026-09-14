<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\Fixtures;

use Netresearch\NrVault\Attribute\ExtensionPoint;

/**
 * ExtensionPointFixture whose method gained an OPTIONAL parameter. No call
 * breaks — but an implementation declaring `label(): string` no longer
 * matches the interface, and PHP refuses to load it.
 */
#[ExtensionPoint]
interface ExtensionPointWithOptionalParameter
{
    public function label(string $prefix = ''): string;
}
