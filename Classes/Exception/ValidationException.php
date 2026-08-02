<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

/**
 * Thrown when validation of input fails.
 */
final class ValidationException extends VaultException
{
    public static function invalidIdentifier(string $identifier, string $reason): self
    {
        return new self(
            \sprintf('Invalid secret identifier "%s": %s', $identifier, $reason),
            1703800012,
        );
    }

    public static function emptySecret(): self
    {
        return new self('Secret value cannot be empty', 1703800013);
    }

    public static function invalidOption(string $option, string $reason): self
    {
        return new self(
            \sprintf('Invalid option "%s": %s', $option, $reason),
            1703800014,
        );
    }

    /**
     * A justification that only exists in the audit log is worthless if it is
     * empty, so the reason is a hard precondition rather than an optional
     * annotation.
     */
    public static function missingReason(string $operation): self
    {
        return new self(
            \sprintf('A non-empty reason is required for %s', $operation),
            1753900002,
        );
    }
}
