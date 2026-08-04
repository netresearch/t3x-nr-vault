<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

use Netresearch\NrVault\Tests\Unit\TestCase;
use TYPO3\TestingFramework\Core\Unit\UnitTestCase;

/*
 * Architecture check: new nr-vault unit tests must extend the project
 * `Netresearch\NrVault\Tests\Unit\TestCase` base class.
 *
 * This script performs a lightweight static scan (regex, no autoloader)
 * so it can run before the unit test suite — including in pre-commit
 * hooks and on fresh checkouts where `.Build/` may be empty.
 *
 * It maintains an allow-list of existing tests that still extend
 * `PHPUnit\Framework\TestCase` / `UnitTestCase` directly. The allow-list
 * is deliberately tech-debt: new entries are rejected. Existing tests
 * are migrated to the project base in a separate tracked PR (see
 * `Tests/AGENTS.md`).
 *
 * Exit codes:
 *   0 — all new/non-legacy tests extend the project base
 *   1 — at least one file violates the convention (or the allow-list
 *       is stale — unknown entry that no longer needs an exemption)
 */

$projectRoot = dirname(__DIR__, 2);
$unitDir = $projectRoot . '/Tests/Unit';

if (!is_dir($unitDir)) {
    fwrite(STDERR, "Unit test directory not found: {$unitDir}\n");
    exit(1);
}

/*
 * Tech-debt allow-list: files that still extend `TestCase` / `UnitTestCase`
 * directly. Relative paths from the project root; keep sorted.
 *
 * Rules:
 *   - NEW files MUST NOT be added here — extend the project TestCase instead.
 *   - Entries are REMOVED as tests migrate off the legacy bases.
 *   - The allow-list is regenerated automatically via:
 *       php Tests/scripts/check-test-base-class.php --update-allowlist
 */
$allowListFile = __DIR__ . '/test-base-class-allowlist.txt';
$allowList = [];
if (is_file($allowListFile)) {
    $lines = file($allowListFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }

        if (str_starts_with($line, '#')) {
            continue;
        }

        $allowList[$line] = true;
    }
}

$updateMode = in_array('--update-allowlist', $argv, true);

/** @var list<string> $violations */
$violations = [];
/** @var list<string> $staleAllowList */
$staleAllowList = [];
/** @var list<string> $legacyFiles */
$legacyFiles = [];

/** @var SplFileInfo $file */
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($unitDir, RecursiveDirectoryIterator::SKIP_DOTS)) as $file) {
    if (!$file->isFile()) {
        continue;
    }

    if ($file->getExtension() !== 'php') {
        continue;
    }

    // Skip the base class itself, traits, fixtures.
    $relative = ltrim(str_replace($projectRoot, '', $file->getPathname()), '/');
    if (str_ends_with($relative, 'Tests/Unit/TestCase.php')) {
        continue;
    }

    if (str_contains($relative, '/Traits/')) {
        continue;
    }

    if (str_contains($relative, '/Fixtures/')) {
        continue;
    }

    $contents = file_get_contents($file->getPathname());
    if ($contents === false) {
        continue;
    }

    // Only inspect classes named *Test that declare an `extends`.
    if (!preg_match('/class\s+\w+Test\s+extends\s+([\\\\\w]+)/', $contents, $matches)) {
        continue;
    }

    $parent = ltrim($matches[1], '\\');
    $isProjectBase = $parent === 'TestCase'
        || $parent === TestCase::class;

    $isLegacyBase = in_array($parent, ['UnitTestCase', UnitTestCase::class, 'TestCase', PHPUnit\Framework\TestCase::class], true);

    // Disambiguate: `TestCase` (unqualified) can mean either the project
    // base OR PHPUnit's — inspect `use` statements.
    if ($parent === 'TestCase') {
        if (preg_match('/use\s+PHPUnit\\\\Framework\\\\TestCase\s*;/', $contents)) {
            $isProjectBase = false;
            $isLegacyBase = true;
        } else {
            // No `use` statement importing PHPUnit's TestCase — assume project base.
            $isProjectBase = true;
            $isLegacyBase = false;
        }
    }

    if ($isProjectBase) {
        continue;
    }

    if (!$isLegacyBase) {
        // Extends something else entirely (e.g. an abstract helper) — not our concern.
        continue;
    }

    $legacyFiles[] = $relative;

    if (isset($allowList[$relative])) {
        unset($allowList[$relative]);

        continue;
    }

    $violations[] = $relative;
}

// Remaining allow-list entries point at files that either no longer exist or
// have already migrated — both cases mean the allow-list is stale.
$staleAllowList = array_keys($allowList);

if ($updateMode) {
    sort($legacyFiles);
    $header = <<<'TXT'
    # Tech-debt allow-list: nr-vault unit tests still extending PHPUnit's TestCase
    # or TYPO3's UnitTestCase directly (instead of the project base).
    #
    # Managed by: php Tests/scripts/check-test-base-class.php --update-allowlist
    # Rule:       New tests MUST extend Netresearch\NrVault\Tests\Unit\TestCase.

    TXT;
    file_put_contents($allowListFile, $header . implode("\n", $legacyFiles) . "\n");
    echo 'Updated allow-list: ' . count($legacyFiles) . " legacy tests.\n";
    exit(0);
}

$exitCode = 0;

if ($violations !== []) {
    sort($violations);
    fwrite(STDERR, "ERROR: the following unit tests must extend Netresearch\\NrVault\\Tests\\Unit\\TestCase:\n");
    foreach ($violations as $violation) {
        fwrite(STDERR, "  - {$violation}\n");
    }

    fwrite(STDERR, "\nHow to fix:\n");
    fwrite(STDERR, "  1. `extends UnitTestCase` -> `extends \\Netresearch\\NrVault\\Tests\\Unit\\TestCase`\n");
    fwrite(STDERR, "  2. Remove the now-unused `use TYPO3\\TestingFramework\\Core\\Unit\\UnitTestCase;`\n");
    $exitCode = 1;
}

if ($staleAllowList !== []) {
    sort($staleAllowList);
    fwrite(STDERR, "ERROR: stale allow-list entries (file migrated or deleted):\n");
    foreach ($staleAllowList as $entry) {
        fwrite(STDERR, "  - {$entry}\n");
    }

    fwrite(STDERR, "\nRegenerate with: php Tests/scripts/check-test-base-class.php --update-allowlist\n");
    $exitCode = 1;
}

if ($exitCode === 0) {
    echo 'OK: ' . count($legacyFiles) . " legacy tests allow-listed, no new violations.\n";
}

exit($exitCode);
