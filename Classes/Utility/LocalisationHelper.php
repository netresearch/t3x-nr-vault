<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Utility;

use TYPO3\CMS\Core\Localization\LanguageService;

/**
 * Helper around `LanguageService::sL()` with a SAFE fallback contract.
 *
 * Why this exists:
 *
 * `LanguageService::sL($key)` does NOT return an empty string when the
 * XLIFF translation is missing — it returns the input key verbatim
 * (`'LLL:EXT:foo/Resources/...:my_key'`). The widely-used idiom
 *
 *     $label = $lang->sL($key) ?: 'fallback';
 *
 * therefore NEVER triggers the fallback for a missing translation — the
 * user sees the raw `LLL:…` key in the UI, which looks like a bug.
 *
 * `translateOrFallback()` checks for the `LLL:` prefix and the empty
 * string before returning, so the fallback fires reliably when the key
 * is unresolved.
 */
final class LocalisationHelper
{
    /**
     * Resolve a `LLL:` key via the language service; return `$fallback`
     * if the key is missing (empty string OR returned unchanged).
     *
     * Plain (non-`LLL:`) inputs are returned as-is — matches the
     * existing `LanguageService::sL()` shape so this is a drop-in
     * replacement for the `sL($key) ?: $fallback` idiom.
     */
    public static function translateOrFallback(
        LanguageService $languageService,
        string $key,
        string $fallback,
    ): string {
        $translated = $languageService->sL($key);

        if ($translated === '' || str_starts_with($translated, 'LLL:')) {
            return $fallback;
        }

        return $translated;
    }
}
