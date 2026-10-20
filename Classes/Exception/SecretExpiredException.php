<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

use function sprintf;

/**
 * Thrown when attempting to access an expired secret.
 */
final class SecretExpiredException extends VaultException
{
    public static function forIdentifier(string $identifier, int $expiredAt): self
    {
        return new self(
            sprintf(
                'Secret "%s" expired at %s',
                $identifier,
                date('Y-m-d H:i:s', $expiredAt),
            ),
            1703800002,
        );
    }
}
