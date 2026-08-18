<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\Fixtures;

/**
 * An own-namespace base whose public constructor is the effective
 * constructor of every subclass that declares none.
 */
abstract class InheritedConstructorBase
{
    public function __construct(protected readonly string $endpoint) {}
}
