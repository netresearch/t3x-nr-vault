<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Utility;

use Netresearch\NrVault\Exception\ValidationException;

/**
 * Validates secret identifiers.
 */
final class IdentifierValidator
{
    private const MIN_LENGTH = 3;

    private const MAX_LENGTH = 255;

    /** User-friendly identifier pattern (e.g., my_api_key). */
    private const USER_PATTERN = '/^[a-zA-Z]\w*$/';

    /** UUID v7 pattern for TCA/FlexForm vault field identifiers. */
    private const UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

    /**
     * Validate a secret identifier.
     *
     * Accepts two formats:
     * - User-friendly: starts with letter, contains letters/numbers/underscores (e.g., my_api_key)
     * - UUID v7: standard UUID v7 format used by TCA/FlexForm vault fields
     *
     * @throws ValidationException If identifier is invalid
     */
    public static function validate(string $identifier): void
    {
        if ($identifier === '') {
            throw ValidationException::invalidIdentifier($identifier, 'cannot be empty');
        }

        // Check if it's a valid UUID v7 (used by TCA/FlexForm vault fields)
        if (preg_match(self::UUID_PATTERN, $identifier)) {
            return;
        }

        // Otherwise validate as user-friendly identifier
        $length = \strlen($identifier);
        if ($length < self::MIN_LENGTH) {
            throw ValidationException::invalidIdentifier(
                $identifier,
                \sprintf('must be at least %d characters', self::MIN_LENGTH),
            );
        }

        if ($length > self::MAX_LENGTH) {
            throw ValidationException::invalidIdentifier(
                $identifier,
                \sprintf('cannot exceed %d characters', self::MAX_LENGTH),
            );
        }

        if (!preg_match(self::USER_PATTERN, $identifier)) {
            throw ValidationException::invalidIdentifier(
                $identifier,
                'must start with a letter and contain only letters, numbers, and underscores',
            );
        }
    }

    /**
     * Check if identifier is valid without throwing.
     */
    public static function isValid(string $identifier): bool
    {
        try {
            self::validate($identifier);

            return true;
        } catch (ValidationException) {
            return false;
        }
    }

    /**
     * Generate a UUID v7 for vault identifiers.
     *
     * UUID v7 contains a 48-bit Unix timestamp (milliseconds) followed by random data.
     * This provides time-ordered IDs with better database index performance.
     */
    public static function generateUuid(): string
    {
        // 48-bit timestamp in milliseconds
        $time = (int) (microtime(true) * 1000);

        // 10 random bytes for the remaining fields
        $random = random_bytes(10);

        // Build UUID v7:
        // - Bytes 0-5: timestamp (48 bits)
        // - Byte 6: version (0111) + 4 random bits
        // - Byte 7: 8 random bits
        // - Byte 8: variant (10) + 6 random bits
        // - Bytes 9-15: 56 random bits
        return \sprintf(
            '%08x-%04x-7%03x-%04x-%012x',
            ($time >> 16) & 0xFFFFFFFF,           // timestamp high 32 bits
            $time & 0xFFFF,                        // timestamp low 16 bits
            \ord($random[0]) << 4 | \ord($random[1]) >> 4 & 0x0FFF, // version 7 + 12 random bits
            ((\ord($random[1]) << 8 | \ord($random[2])) & 0x3FFF) | 0x8000, // variant 10 + 14 random bits
            (\ord($random[3]) << 40) | (\ord($random[4]) << 32) | (\ord($random[5]) << 24)
                | (\ord($random[6]) << 16) | (\ord($random[7]) << 8) | \ord($random[8]), // 48 random bits
        );
    }

    /**
     * Check if a value looks like a vault identifier.
     *
     * Recognises three formats:
     * - UUID v7 (current TCA/FlexForm vault fields)
     * - Vault reference syntax: %vault(identifier)%
     * - Legacy TCA format: table__field__uid (e.g. tx_myext_config__api_key__123)
     */
    public static function looksLikeVaultIdentifier(string $value): bool
    {
        return preg_match(self::UUID_PATTERN, $value) === 1
            || preg_match('/^%vault\([^)]+\)%$/', $value) === 1;
    }

    /**
     * Sanitize a string to create a valid identifier.
     */
    public static function sanitize(string $input): string
    {
        // Convert to lowercase
        $identifier = strtolower($input);

        // Replace invalid characters with underscores
        $replaced = preg_replace('/[^a-z0-9_]/', '_', $identifier);
        $identifier = \is_string($replaced) ? $replaced : $identifier;

        // Ensure starts with letter
        if ($identifier !== '' && !ctype_alpha($identifier[0])) {
            $identifier = 'secret_' . $identifier;
        }

        // Remove consecutive underscores
        $replaced = preg_replace('/_+/', '_', $identifier);
        $identifier = \is_string($replaced) ? $replaced : $identifier;

        // Trim underscores
        $identifier = trim($identifier, '_');

        // Enforce length limits
        if (\strlen($identifier) < self::MIN_LENGTH) {
            $identifier = str_pad($identifier, self::MIN_LENGTH, '_');
        }

        if (\strlen($identifier) > self::MAX_LENGTH) {
            return substr($identifier, 0, self::MAX_LENGTH);
        }

        return $identifier;
    }
}
