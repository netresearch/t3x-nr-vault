<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\Fixtures;

/**
 * ConsumedInterfaceFixture plus one method — additive, because nobody
 * outside the package is supposed to implement it.
 */
interface ConsumedInterfaceWithAddedMethod
{
    public function label(): string;

    public function shout(): string;
}
