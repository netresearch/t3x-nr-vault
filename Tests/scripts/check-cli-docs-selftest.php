<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * Fixture-driven self-check for check-cli-docs.php.
 *
 * A guard that never fails is indistinguishable from one that has nothing to
 * check, and that is exactly what happened here: the previous guard passed
 * while Documentation/Developer/Commands.rst documented three options that do
 * not exist. So each check gets a fixture that it MUST reject, plus a clean
 * fixture it must accept — the guard is only trusted once it has been seen
 * failing on demand.
 *
 * The guard is a standalone static scan with no autoloader (it runs in
 * pre-commit hooks and on fresh checkouts where .Build/ is empty), so it cannot
 * be reached from the PHPUnit suites in Tests/Unit. This file follows the
 * pattern already established by Build/Scripts/collect-evidence-selftest.php:
 * `require`d by `--self-test` and wired into `composer ci` as its own script.
 *
 * The fixtures below are synthetic — they describe a `vault:demo` command that
 * does not exist — so the self-check keeps working when the real commands
 * change, and a real-docs failure is never confused with a guard failure.
 */

/**
 * Runs the pass-2 checks of check-cli-docs.php against synthetic fixtures.
 *
 * parseDocumentedOptions(), validateDocumentedOptions() and
 * validateOptionCoverage() are declared by the guard that `require`s this file.
 */
function checkCliDocsSelfTest(): int
{
    // The authoritative signature the fixtures are checked against:
    //   --value=VALUE          (value, no short form)
    //   --file=VALUE, -f VALUE (value, short form -f)
    //   --force, -o            (flag, short form -o — deliberately NOT -f, so a
    //                           copy-paste shortcut is a detectable mistake)
    $commands = [
        'vault:demo' => [
            'options' => [
                'value' => ['short' => null, 'value' => true],
                'file' => ['short' => 'f', 'value' => true],
                'force' => ['short' => 'o', 'value' => false],
            ],
            'args' => 1,
        ],
    ];

    $globalOptions = ['help', 'quiet', 'verbose', 'no-interaction'];

    // Every fixture is a complete, correct Options list with ONE mutation, so a
    // failure names the mutation rather than the fixture's other noise.
    $section = static fn (string $terms): string => "vault:demo\n==========\n\nOptions\n-------\n\n" . $terms;

    $correct = "--value=SECRET\n   The value.\n\n--file=PATH, -f PATH\n   A file.\n\n--force, -o\n   Skip the prompt.\n";

    /** @var list<array{label: string, rst: string, expect: ?string}> $cases */
    $cases = [
        [
            'label' => 'clean list passes',
            'rst' => $section($correct),
            'expect' => null,
        ],
        [
            'label' => 'invented option is caught',
            'rst' => $section($correct . "\n--expires=DATE\n   Not a real option.\n"),
            'expect' => "documents '--expires', which the command does not declare",
        ],
        [
            'label' => 'wrong short form is caught',
            'rst' => $section(str_replace('--force, -o', '--force, -f', $correct)),
            'expect' => "documents '--force, -f'; the real signature is '--force, -o'",
        ],
        [
            'label' => 'malformed term is caught',
            'rst' => $section(str_replace('-f PATH', '-f =PATH', $correct)),
            'expect' => 'has a malformed option term',
        ],
        [
            'label' => 'global option is rejected, not whitelisted',
            'rst' => $section($correct . "\n--quiet, -q\n   Suppress output.\n"),
            'expect' => "documents the global option '--quiet' as its own",
        ],
        [
            'label' => 'omitted real option is caught',
            'rst' => $section(str_replace("--file=PATH, -f PATH\n   A file.\n\n", '', $correct)),
            'expect' => "does not document '--file=VALUE, -f VALUE'",
        ],
        [
            'label' => 'value option written as a flag is caught',
            'rst' => $section(str_replace('--value=SECRET', '--value', $correct)),
            'expect' => "documents '--value'; the real signature is '--value=VALUE'",
        ],
        [
            'label' => 'flag written as a value option is caught',
            'rst' => $section(str_replace('--force, -o', '--force=BOOL, -o BOOL', $correct)),
            'expect' => "documents '--force=BOOL, -o BOOL'; the real signature is '--force, -o'",
        ],
        [
            'label' => 'short placeholder disagreeing with the long one is caught',
            'rst' => $section(str_replace('-f PATH', '-f FILE', $correct)),
            'expect' => "the real signature is '--file=PATH, -f PATH'",
        ],
        [
            'label' => 'duplicate entry is caught',
            'rst' => $section($correct . "\n--force, -o\n   Again.\n"),
            'expect' => "documents '--force' twice",
        ],
        [
            // A task-oriented page (Documentation/Usage/Index.rst) walks the
            // same commands with examples only. It must not be forced to
            // duplicate the reference — coverage is checked repo-wide instead.
            'label' => 'command section without an Options list is skipped, not flagged',
            'rst' => "vault:demo\n==========\n\nSome prose, no Options list.\n",
            'expect' => null,
        ],
        [
            'label' => 'section for a command that does not exist is caught',
            'rst' => "vault:ghost\n===========\n\nOptions\n-------\n\n--force\n   Nope.\n",
            'expect' => "documents unknown command 'vault:ghost'",
        ],
        [
            // The guard must not read a neighbouring definition list as options:
            // vault:doctor documents its control catalogue exactly like this.
            'label' => 'definition list outside the Options section is ignored',
            'rst' => $section($correct)
                . "\nControl catalogue\n-----------------\n\n--not-an-option\n   Prose, not an option.\n",
            'expect' => null,
        ],
    ];

    $failures = 0;

    foreach ($cases as $case) {
        $result = validateDocumentedOptions(
            $commands,
            parseDocumentedOptions($case['rst']),
            $globalOptions,
            'fixture.rst',
        );
        $violations = $result['violations'];

        $expected = $case['expect'];
        if ($expected === null) {
            if ($violations === []) {
                echo "  PASS  {$case['label']}\n";

                continue;
            }
            ++$failures;
            echo "  FAIL  {$case['label']}: expected no violation, got:\n";
            foreach ($violations as $violation) {
                echo "          {$violation}\n";
            }

            continue;
        }

        $matched = null;
        foreach ($violations as $violation) {
            if (str_contains($violation, $expected)) {
                $matched = $violation;

                break;
            }
        }

        if ($matched !== null) {
            echo "  PASS  {$case['label']}\n          {$matched}\n";

            continue;
        }

        ++$failures;
        echo "  FAIL  {$case['label']}: no violation contained \"{$expected}\"; got:\n";
        foreach ($violations === [] ? ['(none)'] : $violations as $violation) {
            echo "          {$violation}\n";
        }
    }

    // Repo-wide coverage: the rule that stops "delete the Options list" from
    // being a way to silence the per-list checks.
    /** @var list<array{label: string, covered: list<string>, commands: array<string, array{options: array<string, array{short: ?string, value: bool}>, args: int}>, expect: ?string}> $coverageCases */
    $coverageCases = [
        [
            'label' => 'a documented command satisfies coverage',
            'covered' => ['vault:demo'],
            'commands' => $commands,
            'expect' => null,
        ],
        [
            'label' => 'a command documented nowhere is caught',
            'covered' => [],
            'commands' => $commands,
            'expect' => "no Options list documents 'vault:demo'",
        ],
        [
            'label' => 'a command without options needs no Options list',
            'covered' => [],
            'commands' => ['vault:bare' => ['options' => [], 'args' => 0]],
            'expect' => null,
        ],
    ];

    foreach ($coverageCases as $case) {
        $violations = validateOptionCoverage($case['commands'], $case['covered']);
        $expected = $case['expect'];

        if ($expected === null && $violations === []) {
            echo "  PASS  {$case['label']}\n";

            continue;
        }
        if ($expected !== null && $violations !== [] && str_contains($violations[0], $expected)) {
            echo "  PASS  {$case['label']}\n          {$violations[0]}\n";

            continue;
        }

        ++$failures;
        echo "  FAIL  {$case['label']}: expected " . ($expected ?? '(no violation)') . ", got:\n";
        foreach ($violations === [] ? ['(none)'] : $violations as $violation) {
            echo "          {$violation}\n";
        }
    }

    $total = count($cases) + count($coverageCases);
    if ($failures > 0) {
        fwrite(STDERR, "\nERROR: {$failures} of {$total} CLI-docs guard self-check(s) failed.\n");
        fwrite(STDERR, "The guard no longer catches the drift it exists to catch.\n");

        return 1;
    }

    echo "\nOK: all {$total} CLI-docs guard self-check(s) behaved as specified.\n";

    return 0;
}
