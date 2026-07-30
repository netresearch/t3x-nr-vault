<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Crypto;

use Netresearch\NrVault\Exception\EncryptionException;
use Netresearch\NrVault\Exception\EnvelopeFormatException;
use Netresearch\NrVault\Exception\MasterKeyException;
use SensitiveParameter;

/**
 * Envelope encryption for consumers that store a payload in ONE string (ADR-032).
 *
 * {@see EncryptionServiceInterface} mirrors this extension's own secret table:
 * ciphertext, wrapped DEK, two nonces and the version/algorithm markers are
 * separate arguments because they are separate columns. A consumer keeping an
 * encrypted blob in a single column has to invent its own framing to bridge
 * that, and every consumer inventing its own framing is how a format zoo starts.
 * This codec is that framing, once: one string in, one string out, with the
 * parsing and field validation on this side of the boundary.
 *
 * The sealed form is ``nrv1:`` + base64( JSON of {@see EncryptedData::toArray()} ).
 * It is self-identifying, so a column can hold sealed and not-yet-sealed values
 * during a migration and {@see isSealed()} tells them apart.
 *
 * Key management is unchanged and remains this extension's: a per-payload DEK
 * wrapped by the rotatable master key. Because the wrapped DEK lives in the
 * consumer's own table, rotating the master key does NOT reach it — a consumer
 * that seals payloads MUST also register a
 * {@see ForeignEnvelopeRotatorInterface} so its envelopes are re-wrapped with
 * the vault's own (ADR-033). Sealing without registering one produces data that
 * becomes unreadable at the next rotation.
 */
interface EnvelopeCodecInterface
{
    /** Version marker of the envelopes {@see seal()} produces. */
    public const MARKER = 'nrv1:';

    /**
     * Encrypt a payload into a single self-identifying string.
     *
     * @param string $plaintext The payload to protect
     * @param string $identifier Context label bound to the ciphertext as
     *                           additional authenticated data. Two payloads
     *                           sealed under different identifiers cannot be
     *                           swapped for one another — pass a stable,
     *                           per-purpose value (a column or use-case name),
     *                           not a per-row one, or nothing will decrypt after
     *                           a row moves.
     *
     * @throws EncryptionException If encryption fails
     * @throws MasterKeyException If the master key is missing or malformed. A
     *                            SIBLING of EncryptionException, not a subclass —
     *                            catching only EncryptionException lets a plain
     *                            misconfiguration escape as an uncaught fatal.
     */
    public function seal(#[SensitiveParameter] string $plaintext, string $identifier): string;

    /**
     * Decrypt a sealed string produced by {@see seal()}.
     *
     * The stored change-detection checksum is NOT verified here: integrity comes
     * from the AEAD tag, which `open()` always checks.
     *
     * @param string $identifier The SAME identifier the payload was sealed with
     *
     * @throws EnvelopeFormatException If the string is not a well-formed envelope
     * @throws EncryptionException If authentication fails or the algorithm marker
     *                             is unknown on this host
     * @throws MasterKeyException If the master key is missing or malformed (see
     *                            the note on {@see seal()})
     */
    public function open(string $sealed, string $identifier): string;

    /**
     * Whether a stored value is a sealed envelope, as opposed to a plain value
     * written before sealing was introduced.
     */
    public function isSealed(string $value): bool;

    /**
     * Re-wrap a sealed envelope's DEK from one master key to another, leaving the
     * payload ciphertext untouched.
     *
     * This is the primitive behind master-key rotation for consumer-owned
     * envelopes (ADR-033). It does not decrypt the payload, so a rotation never
     * materialises plaintext.
     *
     * @throws EnvelopeFormatException If the string is not a well-formed envelope
     * @throws EncryptionException If the DEK cannot be unwrapped with $oldMasterKey
     */
    public function rewrap(
        string $sealed,
        string $identifier,
        #[SensitiveParameter]
        string $oldMasterKey,
        #[SensitiveParameter]
        string $newMasterKey,
    ): string;
}
