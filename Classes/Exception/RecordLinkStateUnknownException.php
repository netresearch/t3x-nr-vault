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
 * A record link was written, a later step failed (its read-back or its
 * audit entry), and taking the link back failed too: whether the registry
 * row holds the link is unknown. The failure of that later step is the
 * previous exception; the critical log entry names both.
 *
 * @internal
 */
final class RecordLinkStateUnknownException extends VaultException
{
    /** Why taking the link back failed; the step that failed first is the previous exception. */
    private ?Throwable $takeBackFailure = null;

    public static function afterFailedTakeBack(string $identifier, Throwable $failure, Throwable $revertFailure): self
    {
        $exception = new self(
            sprintf(
                'A step after writing the record link of secret "%s" failed (%s), and the link could not be taken back (%s)',
                $identifier,
                $failure->getMessage(),
                $revertFailure->getMessage(),
            ),
            1795855061,
            $failure,
        );
        $exception->takeBackFailure = $revertFailure;

        return $exception;
    }

    public function getTakeBackFailure(): ?Throwable
    {
        return $this->takeBackFailure;
    }
}
