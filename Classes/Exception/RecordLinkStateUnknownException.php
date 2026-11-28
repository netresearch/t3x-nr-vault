<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

use Throwable;

use function sprintf;

/**
 * A record link was written, a later step failed, and taking the link back
 * failed too: whether the registry row holds the link is unknown. The
 * original failure is the previous exception; the critical log entry names
 * both.
 *
 * @internal
 */
final class RecordLinkStateUnknownException extends VaultException
{
    public static function afterFailedTakeBack(string $identifier, Throwable $failure, Throwable $revertFailure): self
    {
        return new self(
            sprintf(
                'The record link of secret "%s" could not be verified (%s) and could not be taken back (%s)',
                $identifier,
                $failure->getMessage(),
                $revertFailure->getMessage(),
            ),
            1795855061,
            $failure,
        );
    }
}
