<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

use function sprintf;

/**
 * Thrown when a requested secret does not exist.
 */
final class SecretNotFoundException extends VaultException
{
    public static function forIdentifier(string $identifier): self
    {
        return new self(
            sprintf('Secret with identifier "%s" not found', $identifier),
            1703800001,
        );
    }
}
