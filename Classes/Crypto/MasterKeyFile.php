<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Exception\MasterKeyException;

use function strlen;

/**
 * Reads a master key from a file an operator names on the command line
 * (`--old-key`, `--new-key`), independent of the configured provider.
 */
final class MasterKeyFile
{
    private const KEY_LENGTH = 32;

    /**
     * @throws MasterKeyException When the file is missing, unreadable or holds no 32-byte key
     */
    public static function read(string $path): string
    {
        if (!file_exists($path)) {
            throw MasterKeyException::notFound($path);
        }

        if (!is_readable($path)) {
            throw MasterKeyException::notFound($path . ' (not readable)');
        }

        $key = file_get_contents($path);
        if ($key === false) {
            throw MasterKeyException::notFound($path);
        }

        // Resolve the key, mirroring FileMasterKeyProvider::loadRawKey() ordering.
        // Order matters: never trim() a value that is already binary key material,
        // or a valid 32-byte raw key whose first/last byte happens to be a trim
        // char (\t \n \r space \0 \x0B) is silently corrupted to 30/31 bytes.
        $trimmed = trim($key);

        // 1) Trimmed value as raw binary key.
        if (strlen($trimmed) === self::KEY_LENGTH) {
            return $trimmed;
        }

        // 2) base64 decode of the trimmed text.
        $decoded = base64_decode($trimmed, true);
        if ($decoded !== false && strlen($decoded) === self::KEY_LENGTH) {
            return $decoded;
        }

        // 3) Raw file contents as binary (no trimming of binary data).
        if (strlen($key) === self::KEY_LENGTH) {
            return $key;
        }

        throw MasterKeyException::invalidLength(self::KEY_LENGTH, strlen($trimmed));
    }
}
