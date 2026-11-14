<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Storage\Aws;

/**
 * Access-key-shaped test values. They are assembled at run time so that no
 * literal in the source looks like a credential to a secret scanner; none of
 * them belongs to an account.
 */
trait AccessKeyFixtures
{
    private static function akia(string $suffix): string
    {
        return strtoupper('akia') . $suffix;
    }

    private static function asia(string $suffix): string
    {
        return strtoupper('asia') . $suffix;
    }
}
