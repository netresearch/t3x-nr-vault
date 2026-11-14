<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Storage;

use Closure;
use Netresearch\NrVault\Domain\Model\Secret;
use Netresearch\NrVault\Exception\ValidationException;
use SensitiveParameter;
use Throwable;

use function is_int;
use function is_string;

/**
 * The payload an external-store adapter keeps for one secret, and its reading.
 *
 * Pure: it holds no state and calls no store. Binary fields are base64, so the
 * JSON document the store keeps is lossless. Ownership, claiming and rollback
 * stay in the adapters.
 *
 * @internal
 */
final class ExternalEnvelopeCodec
{
    public const FORMAT = 1;

    /**
     * @return array<string, mixed>
     */
    public static function encode(Secret $secret, string $installation): array
    {
        return [
            'format'               => self::FORMAT,
            'installation'         => $installation,
            'identifier'           => $secret->getIdentifier(),
            'encrypted_value'      => base64_encode($secret->getEncryptedValue() ?? ''),
            'encrypted_dek'        => base64_encode($secret->getEncryptedDek()),
            'dek_nonce'            => base64_encode($secret->getDekNonce()),
            'value_nonce'          => base64_encode($secret->getValueNonce()),
            'value_checksum'       => $secret->getValueChecksum(),
            'encryption_version'   => $secret->getEncryptionVersion(),
            'encryption_algorithm' => $secret->getEncryptionAlgorithm(),
        ];
    }

    /**
     * @return array{string, string, string, string, string, int, string}
     */
    public static function envelopeOf(Secret $secret): array
    {
        return [
            $secret->getEncryptedValue() ?? '',
            $secret->getEncryptedDek(),
            $secret->getDekNonce(),
            $secret->getValueNonce(),
            $secret->getValueChecksum(),
            $secret->getEncryptionVersion(),
            $secret->getEncryptionAlgorithm(),
        ];
    }

    /**
     * The row with the envelope the payload holds.
     *
     * @param array<string, mixed>       $payload
     * @param Closure(string): Throwable $unusable builds the adapter's "backing object is unusable" exception for an identifier
     *
     * @throws Throwable The exception $unusable builds, when the payload is not an envelope of this row
     */
    public static function decode(Secret $row, #[SensitiveParameter] array $payload, Closure $unusable): Secret
    {
        $identifier = $row->getIdentifier();
        if (($payload['identifier'] ?? null) !== $identifier || ($payload['format'] ?? null) !== self::FORMAT) {
            throw $unusable($identifier);
        }

        $version = $payload['encryption_version'] ?? null;
        $fields  = [];
        foreach (['encrypted_value', 'encrypted_dek', 'dek_nonce', 'value_nonce'] as $key) {
            $decoded = is_string($payload[$key] ?? null) ? base64_decode($payload[$key], true) : false;
            if ($decoded === false) {
                throw $unusable($identifier);
            }

            $fields[$key] = $decoded;
        }

        $checksum  = $payload['value_checksum'] ?? null;
        $algorithm = $payload['encryption_algorithm'] ?? null;
        if (!is_string($checksum) || !is_string($algorithm) || !is_int($version)) {
            throw $unusable($identifier);
        }

        try {
            return $row->withEnvelope(
                $fields['encrypted_value'],
                $fields['encrypted_dek'],
                $fields['dek_nonce'],
                $fields['value_nonce'],
                $checksum,
                $version,
                $algorithm,
            );
        } catch (ValidationException) {
            // An envelope marker this version does not know, such as an unknown
            // algorithm, is an unusable object like any other.
            throw $unusable($identifier);
        }
    }
}
