<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\Fixtures;

/**
 * A backed enum for the renderer tests: the backing values are part of the
 * rendered surface (in this package they are persisted vocabulary), so a
 * value change must classify as breaking even when every case name stays.
 */
enum BackedFixtureEnum: string
{
    case Read = 'read';
    case Write = 'write';
}
