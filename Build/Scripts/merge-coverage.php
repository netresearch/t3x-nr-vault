<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * Merge the unit and functional coverage of the release evidence run.
 *
 * Both suites write PHPUnit's serialized coverage (`--coverage-php`) with
 * Xdebug path coverage enabled. The `merge` mode combines them with the merger
 * of phpunit/php-code-coverage — the library PHPUnit itself reports with,
 * already installed as a PHPUnit dependency, so no extra tool such as phpcov is
 * needed — and renders the two reports the evidence collector reads:
 *
 *   clover.xml         line and branch metrics (`conditionals`), overall and
 *                      per file
 *   coverage-text.txt  the summary text report, the only standard report that
 *                      carries the path metric
 *
 * ONE DENOMINATOR FOR BOTH SUITES
 * ===============================
 * Build/FunctionalTests.xml includes all of Classes/ except Exception/, while
 * Build/phpunit.xml additionally excludes the backend controllers, the module
 * access guard, the FormEngine element, interfaces and enums — the files it
 * documents as covered by E2E tests or free of executable code. Merging the two
 * as they are would put those files back into the denominator, and "merged"
 * would measure a different code base than "unit".
 *
 * The `config` mode therefore writes a copy of the functional configuration
 * whose <source> element is the unit configuration's. The functional suite runs
 * against that copy, both coverage files describe the same set of files, and the
 * merged number is the unit number plus what the functional suite executes —
 * nothing else. The copy sits next to the original so its relative paths
 * resolve the same way.
 *
 * Usage:
 *   php Build/Scripts/merge-coverage.php config <unit.xml> <functional.xml> <target.xml>
 *   php Build/Scripts/merge-coverage.php merge <unit.cov> <functional.cov> <output-dir>
 *
 * Exit codes: 0 done, 1 failed, 2 usage error.
 */

use SebastianBergmann\CodeCoverage\Report\Facade;
use SebastianBergmann\CodeCoverage\Serialization\Merger;

/** @var list<non-empty-string> $arguments */
$arguments = [];
$rawArguments = $_SERVER['argv'] ?? [];
foreach (is_array($rawArguments) ? array_slice($rawArguments, 1) : [] as $rawArgument) {
    if (is_string($rawArgument) && $rawArgument !== '') {
        $arguments[] = $rawArgument;
    }
}

$mode = $arguments[0] ?? '';
if (($mode === 'config' && count($arguments) !== 4) || ($mode === 'merge' && count($arguments) < 3)) {
    $mode = '';
}
if ($mode === '') {
    fwrite(STDERR, "Usage:\n"
        . "  php Build/Scripts/merge-coverage.php config <unit.xml> <functional.xml> <target.xml>\n"
        . "  php Build/Scripts/merge-coverage.php merge <output-dir> <shard.cov> [<shard.cov> …]\n");
    exit(2);
}

try {
    if ($mode === 'config') {
        [, $unitConfig, $functionalConfig, $target] = $arguments;
        foreach ([$unitConfig, $functionalConfig] as $path) {
            if (!is_file($path) || filesize($path) === 0) {
                fwrite(STDERR, "Missing or empty input file: {$path}\n");
                exit(2);
            }
        }
        writeFunctionalConfigWithUnitSource($unitConfig, $functionalConfig, $target);
        echo "Wrote {$target} with the <source> of {$unitConfig}.\n";

        exit(0);
    }

    $target = $arguments[1];
    $coverageFiles = array_slice($arguments, 2);
    foreach ($coverageFiles as $path) {
        if (!is_file($path) || filesize($path) === 0) {
            fwrite(STDERR, "Missing or empty coverage file: {$path}\n");
            exit(2);
        }
    }

    require dirname(__DIR__, 2) . '/.Build/vendor/autoload.php';

    if (!is_dir($target) && !mkdir($target, 0o775, true) && !is_dir($target)) {
        throw new RuntimeException("Cannot create {$target}", 1757851201);
    }

    echo 'Merging ' . count($coverageFiles) . " coverage file(s):\n  " . implode("\n  ", $coverageFiles) . "\n";

    $facade = Facade::fromSerializedData((new Merger())->merge($coverageFiles));
    $facade->renderClover($target . '/clover.xml');
    echo $facade->renderText($target . '/coverage-text.txt', null, false, true);
} catch (Throwable $e) {
    fwrite(STDERR, 'Coverage ' . $mode . ' failed: ' . $e::class . ': ' . $e->getMessage() . "\n");
    exit(1);
}

exit(0);

/**
 * @param non-empty-string $unitConfig
 * @param non-empty-string $functionalConfig
 * @param non-empty-string $target
 */
function writeFunctionalConfigWithUnitSource(string $unitConfig, string $functionalConfig, string $target): void
{
    $unit = loadConfig($unitConfig);
    $functional = loadConfig($functionalConfig);

    $unitSource = firstChildElement($unit, 'source', $unitConfig);
    $functionalSource = firstChildElement($functional, 'source', $functionalConfig);

    $replacement = $functional->importNode($unitSource, true);
    $parent = $functionalSource->parentNode;
    if ($parent === null) {
        throw new RuntimeException("{$functionalConfig}: <source> has no parent element", 1757851202);
    }
    $parent->replaceChild($replacement, $functionalSource);

    // The functional tests cover the backend controllers, which the unit
    // <source> excludes as "covered by E2E". Under the substituted source their
    // `#[CoversClass]` attributes name a class outside the coverage scope, and
    // PHPUnit reports each one as "Class … is not a valid target for code
    // coverage" — 26 of them, which failed the run with no test failing (CI run
    // 34853295501).
    //
    // That is a *PHPUnit* warning, gated by `failOnPhpunitWarning` (default
    // true), not by the `failOnWarning` the configuration sets — setting the
    // latter to false left the run failing. Only this one flag is relaxed, and
    // only on this copy: the functional suite's pass/fail verdict is produced by
    // the `checks` job from the original configuration, so no gate is weakened,
    // and a failing test still fails this run through the exit code.
    $root = $functional->documentElement;
    if ($root === null) {
        throw new RuntimeException("{$functionalConfig}: no root element", 1757851206);
    }
    $root->setAttribute('failOnPhpunitWarning', 'false');

    if ($functional->save($target) === false) {
        throw new RuntimeException("Cannot write {$target}", 1757851203);
    }
}

/**
 * @param non-empty-string $path
 */
function loadConfig(string $path): DOMDocument
{
    $document = new DOMDocument();
    $document->preserveWhiteSpace = true;
    if (!$document->load($path)) {
        throw new RuntimeException("{$path} is not a readable XML document", 1757851204);
    }

    return $document;
}

function firstChildElement(DOMDocument $document, string $name, string $path): DOMElement
{
    $root = $document->documentElement;
    if ($root !== null) {
        foreach ($root->childNodes as $child) {
            if ($child instanceof DOMElement && $child->tagName === $name) {
                return $child;
            }
        }
    }

    throw new RuntimeException("{$path} has no top-level <{$name}> element", 1757851205);
}
