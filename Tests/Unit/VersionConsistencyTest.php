<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;

/**
 * Guards the hand-maintained version surfaces against drift.
 *
 * TYPO3 v14.2 deprecates ext_emconf.php (#108345): an extension that still
 * ships it must declare `extra.typo3/cms.version` and
 * `extra.typo3/cms.Package.providesPackages` in composer.json, or classic mode
 * logs a deprecation. ext_emconf.php stays for TYPO3 v13 and TER, so the
 * version now lives in ext_emconf.php, composer.json and
 * Documentation/guides.xml, and every release commit bumps all three. The
 * release workflow takes the version from the tag and checks none of them.
 */
#[CoversNothing]
final class VersionConsistencyTest extends TestCase
{
    #[Test]
    public function composerJsonVersionMatchesExtEmconf(): void
    {
        self::assertSame(
            $this->extEmConfVersion(),
            $this->typo3ComposerExtra()['version'] ?? null,
            'composer.json extra.typo3/cms.version must match the ext_emconf.php version '
            . '(TYPO3 #108345) - bump both in the release commit.',
        );
    }

    #[Test]
    public function composerJsonDeclaresProvidesPackages(): void
    {
        $package = $this->typo3ComposerExtra()['Package'] ?? null;
        self::assertIsArray($package);
        self::assertArrayHasKey(
            'providesPackages',
            $package,
            'composer.json must declare extra.typo3/cms.Package.providesPackages, '
            . 'even as an empty object, or TYPO3 v14 logs the #108345 deprecation.',
        );
    }

    #[Test]
    public function guidesXmlVersionMatchesExtEmconf(): void
    {
        $version = $this->extEmConfVersion();
        $guides = (string) file_get_contents($this->repoRoot() . '/Documentation/guides.xml');

        self::assertStringContainsString(
            'release="' . $version . '"',
            $guides,
            'Documentation/guides.xml release attribute must match the ext_emconf.php version.',
        );
        self::assertStringContainsString(
            'version="' . implode('.', \array_slice(explode('.', $version), 0, 2)) . '"',
            $guides,
            'Documentation/guides.xml version attribute must be the major.minor of the ext_emconf.php version.',
        );
    }

    private function repoRoot(): string
    {
        return \dirname(__DIR__, 2);
    }

    private function extEmConfVersion(): string
    {
        $contents = file_get_contents($this->repoRoot() . '/ext_emconf.php');
        self::assertIsString($contents, 'ext_emconf.php must be readable');
        self::assertSame(
            1,
            preg_match("/'version'\\s*=>\\s*'([^']+)'/", $contents, $matches),
            'ext_emconf.php must declare a version',
        );

        return $matches[1];
    }

    /**
     * @return array<mixed>
     */
    private function typo3ComposerExtra(): array
    {
        $composer = json_decode((string) file_get_contents($this->repoRoot() . '/composer.json'), true);
        self::assertIsArray($composer);
        self::assertIsArray($composer['extra'] ?? null);
        self::assertIsArray($composer['extra']['typo3/cms'] ?? null);

        return $composer['extra']['typo3/cms'];
    }
}
