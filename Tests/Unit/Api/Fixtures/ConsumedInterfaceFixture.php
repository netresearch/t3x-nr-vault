<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\Fixtures;

/**
 * An interface WITHOUT the extension-point mark: meant to be called, not
 * implemented outside the package. The counterpart to ExtensionPointFixture.
 */
interface ConsumedInterfaceFixture
{
    public function label(): string;
}
