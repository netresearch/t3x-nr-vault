<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

/**
 * Thrown when a sealed envelope cannot be parsed at all (ADR-032).
 *
 * Deliberately a sibling of {@see EncryptionException} rather than a subclass:
 * "this string is not a well-formed envelope" and "this envelope failed
 * authentication" call for different handling. The first is corruption, a
 * truncated column or a value that was never sealed; the second means the
 * ciphertext was tampered with, moved to a different AAD context, or written
 * under a key this host does not have. A consumer that catches only
 * `EncryptionException` must not silently absorb malformed input as if it were
 * a failed MAC check.
 */
final class EnvelopeFormatException extends VaultException
{
    public static function missingMarker(): self
    {
        return new self('Sealed envelope is missing its version marker', 1753900001);
    }

    public static function notBase64(): self
    {
        return new self('Sealed envelope body is not valid base64', 1753900002);
    }

    public static function notJson(): self
    {
        return new self('Sealed envelope body is not valid JSON', 1753900003);
    }

    public static function malformedFields(): self
    {
        return new self('Sealed envelope is missing required fields or has fields of the wrong type', 1753900004);
    }
}
