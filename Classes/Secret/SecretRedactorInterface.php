<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Secret;

/**
 * Masks secret-shaped strings, and answers whether a name or a whole value looks
 * like a secret, from the shared catalogue (ADR-031).
 *
 * This is best-effort by nature: it recognises the shapes in
 * {@see SecretPatternLibrary} and nothing else. It is a defence-in-depth net for
 * secrets that have already escaped their proper home, NOT a substitute for
 * keeping them in the vault.
 */
interface SecretRedactorInterface
{
    /**
     * Replace every recognised secret occurrence in free text with a mask.
     *
     * Fail-safe: if the regex engine fails on a pathological input the text
     * processed so far is kept, so the method never returns an empty string in
     * place of the caller's content.
     *
     * @param bool $includeEmails Also mask e-mail addresses. Off by default: an
     *                            address is personal data rather than a secret,
     *                            and masking it in, say, a model prompt would
     *                            change the meaning of the text.
     */
    public function redact(string $text, bool $includeEmails = false): string;

    /**
     * Whether an identifier reads as secret-bearing within its namespace.
     */
    public function isSecretIdentifier(string $identifier, SecretIdentifierKind $kind): bool;

    /**
     * The shape name when the WHOLE value is a known secret format, else null.
     *
     * Leading and trailing whitespace is ignored.
     */
    public function identifyValue(string $value): ?string;
}
