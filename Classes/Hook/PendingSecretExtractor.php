<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Hook;

use Netresearch\NrVault\Hook\Dto\PendingSecret;
use Netresearch\NrVault\Utility\IdentifierValidator;

/**
 * Turns a raw vault field value (from a TCA field or a FlexForm vDEF node)
 * into a {@see PendingSecret}, applying the shared new/update detection and
 * UUID-generation rules.
 *
 * This is the single source of truth for the value-extraction pipeline that
 * was previously duplicated byte-for-byte between {@see DataHandlerHook} and
 * {@see FlexFormVaultHook}.
 */
final class PendingSecretExtractor
{
    /**
     * Extract a pending secret from a raw field value.
     *
     * Returns:
     * - a {@see PendingSecret} with a non-empty value for a new/updated secret,
     * - a {@see PendingSecret} with an empty value (and a prior checksum) when
     *   the field was cleared and the secret must be deleted,
     * - null when there is nothing to do (empty value and no prior secret).
     *
     * @param mixed $value The raw field value (string, int, or the array shape
     *                     emitted by the vault FormEngine element)
     */
    public function extract(mixed $value): ?PendingSecret
    {
        ['value' => $secretValue, 'identifier' => $existingIdentifier, 'checksum' => $originalChecksum] = $this->classifyValue($value);

        // Nothing to do: empty value and no prior secret.
        if ($secretValue === '' && $originalChecksum === '') {
            return null;
        }

        $isNewSecret = $existingIdentifier === '' || $originalChecksum === '';
        $vaultIdentifier = $isNewSecret ? IdentifierValidator::generateUuid() : $existingIdentifier;

        return $isNewSecret
            ? PendingSecret::createNew($secretValue, $vaultIdentifier)
            : PendingSecret::createUpdate($secretValue, $vaultIdentifier, $originalChecksum);
    }

    /**
     * Normalize the raw field value (array shape vs. scalar) into the three
     * string components used by the extraction pipeline.
     *
     * @param mixed $value The raw field value (string, int, or the array shape
     *                     emitted by the vault FormEngine element)
     *
     * @return array{value: string, identifier: string, checksum: string}
     */
    private function classifyValue(mixed $value): array
    {
        if (\is_array($value)) {
            $rawSecretValue = $value['value'] ?? $value[0] ?? '';
            $rawIdentifier = $value['_vault_identifier'] ?? '';
            $rawChecksum = $value['_vault_checksum'] ?? '';

            return [
                'value' => \is_string($rawSecretValue) || \is_int($rawSecretValue) ? (string) $rawSecretValue : '',
                'identifier' => \is_string($rawIdentifier) ? $rawIdentifier : '',
                'checksum' => \is_string($rawChecksum) ? $rawChecksum : '',
            ];
        }

        return [
            'value' => \is_string($value) || \is_int($value) ? (string) $value : '',
            'identifier' => '',
            'checksum' => '',
        ];
    }
}
