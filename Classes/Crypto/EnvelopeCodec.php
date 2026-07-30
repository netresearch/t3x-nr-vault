<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use JsonException;
use Netresearch\NrVault\Exception\EnvelopeFormatException;
use SensitiveParameter;

/**
 * Framing for {@see EnvelopeCodecInterface}: pack an {@see EncryptedData} into one
 * string and parse it back, with strict field validation (ADR-032).
 *
 * The JSON body is exactly `EncryptedData::toArray()`, and parsing reads only the
 * fields it needs while ignoring any extra ones — so a body written by an older
 * or newer vault, or one carrying the change-detection checksum, still opens.
 */
final readonly class EnvelopeCodec implements EnvelopeCodecInterface
{
    /**
     * Depth limit for the envelope body. The structure is one flat object, so
     * anything deeper is not an envelope.
     */
    private const JSON_DEPTH = 8;

    public function __construct(
        private EncryptionServiceInterface $encryptionService,
    ) {}

    public function seal(#[SensitiveParameter] string $plaintext, string $identifier): string
    {
        $encrypted = $this->encryptionService->encrypt($plaintext, $identifier);

        return self::MARKER . base64_encode(
            json_encode($encrypted->toArray(), JSON_THROW_ON_ERROR),
        );
    }

    public function open(string $sealed, string $identifier): string
    {
        $envelope = $this->validate($this->decodeBody($sealed));

        return $this->encryptionService->decrypt(
            $envelope['encrypted_value'],
            $envelope['encrypted_dek'],
            $envelope['dek_nonce'],
            $envelope['value_nonce'],
            $identifier,
            $envelope['encryption_version'],
            $envelope['encryption_algorithm'],
        );
    }

    public function isSealed(string $value): bool
    {
        return str_starts_with($value, self::MARKER);
    }

    public function rewrap(
        string $sealed,
        string $identifier,
        #[SensitiveParameter]
        string $oldMasterKey,
        #[SensitiveParameter]
        string $newMasterKey,
    ): string {
        $body = $this->decodeBody($sealed);
        $envelope = $this->validate($body);

        $reEncrypted = $this->encryptionService->reEncryptDek(
            $envelope['encrypted_dek'],
            $envelope['dek_nonce'],
            $identifier,
            $oldMasterKey,
            $newMasterKey,
            $envelope['encryption_version'],
            $envelope['encryption_algorithm'],
        );

        // Rewrite the DEK layer ON TOP of the body as it was read, rather than
        // rebuilding the body from the fields this version happens to know. The
        // read path deliberately tolerates unknown fields, so rebuilding would make
        // rotation lossy in exactly the case the tolerance exists for: a body
        // written by a newer vault would open fine until an operator rotated, and
        // then come back stripped — irreversibly, once the old key is gone. It also
        // preserves the ABSENCE of an optional field instead of inventing an empty
        // value for it.
        //
        // The payload ciphertext, its nonce and the version/algorithm markers are
        // untouched, so re-wrapping is not a re-encryption and never materialises
        // the plaintext.
        $body['encrypted_dek'] = $reEncrypted->encryptedDek;
        $body['dek_nonce'] = $reEncrypted->nonce;

        return self::MARKER . base64_encode(json_encode($body, JSON_THROW_ON_ERROR));
    }

    /**
     * Split off the marker and decode the body, without inspecting its fields.
     *
     * @throws EnvelopeFormatException
     *
     * @return array<string, mixed>
     */
    private function decodeBody(string $sealed): array
    {
        if (!$this->isSealed($sealed)) {
            throw EnvelopeFormatException::missingMarker();
        }

        $json = base64_decode(substr($sealed, \strlen(self::MARKER)), true);
        if ($json === false) {
            throw EnvelopeFormatException::notBase64();
        }

        try {
            $decoded = json_decode($json, true, self::JSON_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw EnvelopeFormatException::notJson();
        }

        if (!\is_array($decoded)) {
            throw EnvelopeFormatException::notJson();
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * Check that every field the codec needs is present with the right type.
     *
     * Unknown fields are deliberately ignored rather than rejected, so a body
     * written by an older or newer vault still opens.
     *
     * @param array<string, mixed> $decoded
     *
     * @throws EnvelopeFormatException
     *
     * @return array{
     *     encrypted_value: string,
     *     encrypted_dek: string,
     *     dek_nonce: string,
     *     value_nonce: string,
     *     value_checksum: string,
     *     encryption_version: int,
     *     encryption_algorithm: string,
     * }
     */
    private function validate(array $decoded): array
    {
        $value = $decoded['encrypted_value'] ?? null;
        $dek = $decoded['encrypted_dek'] ?? null;
        $dekNonce = $decoded['dek_nonce'] ?? null;
        $valNonce = $decoded['value_nonce'] ?? null;
        $version = $decoded['encryption_version'] ?? null;
        $algorithm = $decoded['encryption_algorithm'] ?? null;
        // Carried through re-wrapping but not required to open an envelope: it is
        // a change-detection token, and integrity is the AEAD tag's job.
        $checksum = $decoded['value_checksum'] ?? '';

        if (!\is_string($value) || !\is_string($dek) || !\is_string($dekNonce)
            || !\is_string($valNonce) || !\is_int($version) || !\is_string($algorithm)
            || !\is_string($checksum)
        ) {
            throw EnvelopeFormatException::malformedFields();
        }

        return [
            'encrypted_value' => $value,
            'encrypted_dek' => $dek,
            'dek_nonce' => $dekNonce,
            'value_nonce' => $valNonce,
            'value_checksum' => $checksum,
            'encryption_version' => $version,
            'encryption_algorithm' => $algorithm,
        ];
    }
}
