<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Utility;

use Netresearch\NrVault\Tests\Unit\TestCase;
use Netresearch\NrVault\Utility\LocalisationHelper;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use TYPO3\CMS\Core\Localization\LanguageService;

/**
 * The whole point of the helper is the case `sL($key) ?: $fallback` gets wrong:
 * a missing translation comes back as the `LLL:` key itself, which is truthy, so
 * the idiomatic fallback never fires and the raw key reaches the UI. These tests
 * pin the three shapes `sL()` can return — a translation, the key verbatim, and
 * the empty string — plus the pass-through for plain strings that makes the
 * helper a drop-in replacement.
 */
#[CoversClass(LocalisationHelper::class)]
final class LocalisationHelperTest extends TestCase
{
    private const KEY = 'LLL:EXT:nr_vault/Resources/Private/Language/locallang.xlf:some_label';

    #[Test]
    public function returnsTheTranslationWhenTheKeyResolves(): void
    {
        self::assertSame(
            'Reveal secret',
            LocalisationHelper::translateOrFallback(
                $this->languageService(self::KEY, 'Reveal secret'),
                self::KEY,
                'fallback',
            ),
        );
    }

    /**
     * The regression this class exists for: `sL()` echoing the key back is a
     * missing translation, not a label.
     */
    #[Test]
    public function fallsBackWhenTheLanguageServiceEchoesTheKeyBack(): void
    {
        self::assertSame(
            'fallback',
            LocalisationHelper::translateOrFallback(
                $this->languageService(self::KEY, self::KEY),
                self::KEY,
                'fallback',
            ),
        );
    }

    #[Test]
    public function fallsBackOnAnEmptyTranslation(): void
    {
        self::assertSame(
            'fallback',
            LocalisationHelper::translateOrFallback(
                $this->languageService(self::KEY, ''),
                self::KEY,
                'fallback',
            ),
        );
    }

    /**
     * Any `LLL:` prefixed answer is unresolved, whichever key it names — a
     * chained XLIFF reference that itself fails to resolve must not leak either.
     */
    #[Test]
    public function fallsBackOnAnyUnresolvedLllAnswer(): void
    {
        self::assertSame(
            'fallback',
            LocalisationHelper::translateOrFallback(
                $this->languageService(self::KEY, 'LLL:EXT:other/Resources/Private/Language/db.xlf:label'),
                self::KEY,
                'fallback',
            ),
        );
    }

    /**
     * A plain input is handed to `sL()` unchanged, matching its own shape, so
     * call sites can pass a literal label without special-casing it.
     */
    #[Test]
    public function passesPlainNonLllInputThrough(): void
    {
        self::assertSame(
            'Already a label',
            LocalisationHelper::translateOrFallback(
                $this->languageService('Already a label', 'Already a label'),
                'Already a label',
                'fallback',
            ),
        );
    }

    #[Test]
    #[DataProvider('emptyFallbackProvider')]
    public function theFallbackIsReturnedVerbatimIncludingEmptyString(
        string $translated,
        string $fallback,
        string $expected,
    ): void {
        self::assertSame(
            $expected,
            LocalisationHelper::translateOrFallback(
                $this->languageService(self::KEY, $translated),
                self::KEY,
                $fallback,
            ),
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function emptyFallbackProvider(): iterable
    {
        yield 'empty fallback for an unresolved key' => ['', '', ''];
        yield 'unresolved key, whitespace fallback' => [self::KEY, ' ', ' '];
        yield 'resolved key wins over the fallback' => ['Label', 'fallback', 'Label'];
    }

    private function languageService(string $expectedKey, string $translated): LanguageService
    {
        $languageService = $this->createMock(LanguageService::class);
        $languageService->expects(self::once())
            ->method('sL')
            ->with($expectedKey)
            ->willReturn($translated);

        return $languageService;
    }
}
