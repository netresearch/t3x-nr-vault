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
     * The secret plaintext is never rendered back into the edit form, so an
     * empty submitted value does NOT by itself mean "clear this secret". The
     * vault FormEngine element submits a checksum alongside an existing secret
     * and blanks that checksum when its clear control is used — that
     * presence/absence is what distinguishes an untouched re-save from an
     * explicit clear.
     *
     * Returns:
     * - a {@see PendingSecret} with a non-empty value for a new / rotated secret,
     * - a {@see PendingSecret} with an empty value to DELETE the secret, but only
     *   when the field was explicitly cleared (checksum blanked while an
     *   identifier is still present),
     * - null when there is nothing to do: either an untouched existing secret,
     *   which must be kept (issue #223 — a plain re-save must never wipe the
     *   key), or an empty field that never held a secret.
     *
     * @param mixed $value The raw field value (string, int, or the array shape
     *                     emitted by the vault FormEngine element)
     */
    public function extract(mixed $value): ?PendingSecret
    {
        ['value' => $secretValue, 'identifier' => $existingIdentifier, 'checksum' => $originalChecksum] = $this->classifyValue($value);

        // A new plaintext value was entered: store it as a new secret, or rotate
        // the existing one when an identifier + checksum are present.
        if ($secretValue !== '') {
            $isNewSecret = $existingIdentifier === '' || $originalChecksum === '';
            $vaultIdentifier = $isNewSecret ? IdentifierValidator::generateUuid() : $existingIdentifier;

            return $isNewSecret
                ? PendingSecret::createNew($secretValue, $vaultIdentifier)
                : PendingSecret::createUpdate($secretValue, $vaultIdentifier, $originalChecksum);
        }

        // The submitted value is empty. Because the stored secret is never shown
        // in the form, an untouched save also arrives empty — so a present
        // checksum means "left untouched": keep the secret intact by doing
        // nothing (the DataHandler hook leaves the DB field as-is on null).
        if ($originalChecksum !== '') {
            return null;
        }

        // Empty value and no checksum: the clear control blanked the checksum. If
        // an identifier still remains, the user explicitly cleared the field, so
        // delete the stored secret (empty-value PendingSecret => delete).
        if ($existingIdentifier !== '') {
            return PendingSecret::createUpdate('', $existingIdentifier, '');
        }

        // Empty field that never held a secret — nothing to do.
        return null;
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
