<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Secret;

/**
 * Catalogue-driven implementation of {@see SecretRedactorInterface} (ADR-031).
 */
final readonly class SecretRedactor implements SecretRedactorInterface
{
    public function redact(string $text, bool $includeEmails = false): string
    {
        if ($text === '') {
            return '';
        }

        $redacted = $text;

        foreach (SecretPatternLibrary::all() as $pattern) {
            if ($pattern->inlinePattern === null) {
                continue;
            }

            $redacted = $this->apply($pattern->inlinePattern, $pattern->inlineReplacement, $redacted);
        }

        if ($includeEmails) {
            return $this->apply(SecretPatternLibrary::EMAIL_PATTERN, SecretPattern::MASK, $redacted);
        }

        return $redacted;
    }

    public function isSecretIdentifier(string $identifier, SecretIdentifierKind $kind): bool
    {
        foreach ($kind->hints() as $hint) {
            if (preg_match($hint, $identifier) === 1) {
                return true;
            }
        }

        return false;
    }

    public function identifyValue(string $value): ?string
    {
        $trimmed = trim($value);
        if ($trimmed === '') {
            return null;
        }

        foreach (SecretPatternLibrary::valueShapes() as $pattern) {
            if ($pattern->anchoredPattern === null) {
                continue;
            }

            if (preg_match($pattern->anchoredPattern, $trimmed) === 1) {
                return $pattern->name;
            }
        }

        return null;
    }

    /**
     * Apply one masking pattern, keeping the last good text if the regex engine
     * gives up.
     *
     * `preg_replace()` returns null on failure — a backtrack or recursion limit
     * hit on a huge payload, for instance. A bare (string) cast would turn that
     * null into '', silently wiping the caller's entire content; on a redaction
     * path that would look like a successful, very thorough redaction. Returning
     * the unchanged input instead means one pattern is skipped while the others
     * still apply.
     */
    private function apply(string $pattern, string $replacement, string $text): string
    {
        $result = preg_replace($pattern, $replacement, $text);

        return \is_string($result) ? $result : $text;
    }
}
