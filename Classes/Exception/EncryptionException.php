<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Exception;

use function sprintf;

/**
 * Thrown when encryption or decryption operations fail.
 */
final class EncryptionException extends VaultException
{
    public static function encryptionFailed(string $reason = ''): self
    {
        $message = 'Encryption failed';
        if ($reason !== '') {
            $message .= ': ' . $reason;
        }

        return new self($message, 1703800005);
    }

    public static function decryptionFailed(string $reason = ''): self
    {
        $message = 'Decryption failed';
        if ($reason !== '') {
            $message .= ': ' . $reason;
        }

        return new self($message, 1703800006);
    }

    public static function algorithmNotAvailable(string $algorithm): self
    {
        return new self(
            sprintf('Encryption algorithm "%s" is not available', $algorithm),
            1703800007,
        );
    }
}
