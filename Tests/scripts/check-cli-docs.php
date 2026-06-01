<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * Documentation drift guard for the `vault:*` CLI.
 *
 * Every `vendor/bin/typo3 vault:<cmd> ...` example in README.md and the
 * Developer/Commands.rst reference is checked against the authoritative
 * command definitions in Classes/Command/*Command.php:
 *
 *   - the command name must exist (`#[AsCommand(name: 'vault:...')]`)
 *   - every `--option` used must be a real option of THAT command
 *     (or a known global Symfony/TYPO3 option)
 *   - the number of positional arguments must not exceed the command's
 *     declared `addArgument()` count
 *
 * Like check-test-base-class.php this is a lightweight static scan (regex,
 * no autoloader) so it runs before the test suite, in pre-commit hooks, and
 * on fresh checkouts where `.Build/` may be empty.
 *
 * Exit codes:
 *   0 — every documented example matches a real command signature
 *   1 — at least one example references an unknown command/option or passes
 *       too many positional arguments
 */

$projectRoot = dirname(__DIR__, 2);
$commandDir = $projectRoot . '/Classes/Command';

if (!is_dir($commandDir)) {
    fwrite(STDERR, "Command directory not found: {$commandDir}\n");
    exit(1);
}

/*
 * Options Symfony's Application and TYPO3's CommandApplication add to every
 * command. Examples may legitimately use these even though no command class
 * declares them.
 */
$globalOptions = [
    'help', 'quiet', 'verbose', 'version', 'ansi', 'no-ansi',
    'no-interaction', 'env', 'no-debug',
];

/**
 * @return array{0: array<string, array{options: array<string,true>, args: int}>, 1: list<string>}
 */
$parseCommands = static function (string $commandDir): array {
    /** @var array<string, array{options: array<string,true>, args: int}> $commands */
    $commands = [];
    /** @var list<string> $errors */
    $errors = [];

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($commandDir, RecursiveDirectoryIterator::SKIP_DOTS)) as $file) {
        if (!$file->isFile()) {
            continue;
        }
        if ($file->getExtension() !== 'php') {
            continue;
        }
        $contents = file_get_contents($file->getPathname());
        if ($contents === false) {
            continue;
        }

        // Only command classes carry an #[AsCommand(...)] attribute. Accept
        // both the named-argument form #[AsCommand(name: 'vault:x')] and the
        // positional form #[AsCommand('vault:x')].
        if (!preg_match('/#\[AsCommand\(\s*(?:name:\s*)?[\'"]([^\'"]+)[\'"]/', $contents, $nameMatch)) {
            continue;
        }
        $name = $nameMatch[1];

        // Option names: first string literal argument of each addOption() call.
        /** @var array<string,true> $options */
        $options = [];
        if (preg_match_all('/->addOption\(\s*[\'"]([a-zA-Z0-9][a-zA-Z0-9-]*)[\'"]/', $contents, $optMatches)) {
            foreach ($optMatches[1] as $opt) {
                $options[$opt] = true;
            }
        }

        // Positional argument count: number of addArgument() calls.
        $argCount = preg_match_all('/->addArgument\(/', $contents);

        $commands[$name] = ['options' => $options, 'args' => (int) $argCount];
    }

    if ($commands === []) {
        $errors[] = "No #[AsCommand] classes parsed from {$commandDir}";
    }

    return [$commands, $errors];
};

/**
 * Extract `vendor/bin/typo3 vault:* ...` example invocations from a doc file.
 * Returns a list of [lineNumber, rawCommandLine].
 *
 * @return list<array{int, string}>
 */
$extractExamples = static function (string $path): array {
    /** @var list<array{int, string}> $examples */
    $examples = [];
    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return $examples;
    }

    $count = count($lines);
    for ($i = 0; $i < $count; ++$i) {
        $line = $lines[$i];
        // Match a vault:* invocation anywhere on the line (code blocks, prose).
        if (!preg_match('/(?:vendor\/bin\/typo3|bin\/typo3|typo3)\s+(vault:[a-z-]+)(.*)$/', $line, $m)) {
            continue;
        }

        $startLine = $i + 1;
        $rest = $m[2];

        // Join shell line continuations: a trailing backslash means the
        // options continue on the next line(s). Without this the guard would
        // only validate the first line and miss drift on continuation lines.
        while (rtrim($rest) !== '' && str_ends_with(rtrim($rest), '\\') && $i + 1 < $count) {
            $rest = rtrim($rest);
            $rest = substr($rest, 0, -1); // drop trailing backslash
            ++$i;
            $rest .= ' ' . trim($lines[$i]);
        }

        $examples[] = [$startLine, trim($m[1] . ' ' . $rest)];
    }

    return $examples;
};

/**
 * Parse a single example command line into [command, options[], positionalCount].
 * Strips trailing shell noise (redirects, pipes, line continuations, comments).
 *
 * @return array{string, list<string>, int}
 */
$parseExample = static function (string $cmdLine): array {
    // Cut shell trailers: redirects, pipes, backgrounding, comments, continuations.
    $cmdLine = preg_replace('/\s*(?:[|>&#].*|\\\\)$/', '', $cmdLine) ?? $cmdLine;

    // Tokenize respecting single/double quotes so a quoted value containing a
    // space stays in ONE token — including when the quote follows `=`
    // (e.g. --reason="Scheduled rotation") or stands alone ("foo bar").
    // A token is a run of non-space/non-quote chars, each optionally followed
    // by a quoted span, repeated (so --reason="a b" is one token).
    preg_match_all('/(?:[^\s"\']+(?:"[^"]*"|\'[^\']*\')?|"[^"]*"|\'[^\']*\')+/', trim($cmdLine), $tokMatch);
    $tokens = $tokMatch[0] ?? [];
    $command = array_shift($tokens) ?? '';

    /** @var list<string> $options */
    $options = [];
    $positional = 0;

    foreach ($tokens as $tok) {
        if ($tok === '') {
            continue;
        }
        if (str_starts_with($tok, '--')) {
            // Strip a value: --opt=value  OR  bare --opt.
            $opt = substr($tok, 2);
            $eq = strpos($opt, '=');
            if ($eq !== false) {
                $opt = substr($opt, 0, $eq);
            }
            if ($opt !== '') {
                $options[] = $opt;
            }

            continue;
        }
        if (str_starts_with($tok, '-') && strlen($tok) > 1) {
            // Short option (e.g. -r, -f) — not validated against long names here.
            continue;
        }
        // Synopsis grammar, not a real argument: [options], <identifier>,
        // [<arg>], [--], {a|b}. These describe the signature, they don't pass a value.
        if (preg_match('/^[\[<{].*[\]>}]$/', $tok)) {
            continue;
        }
        if ($tok === '[--]') {
            continue;
        }
        if ($tok === '--') {
            continue;
        }
        // A positional argument (placeholder or literal value).
        ++$positional;
    }

    return [$command, $options, $positional];
};

[$commands, $parseErrors] = $parseCommands($commandDir);
$violations = $parseErrors;

// Scan README plus every doc under Documentation/ so a vault:* example
// anywhere in the docs is validated — not just the two reference files.
/** @var array<string,string> $docFiles label => absolute path */
$docFiles = [];
if (is_file($projectRoot . '/README.md')) {
    $docFiles['README.md'] = $projectRoot . '/README.md';
}
$docDir = $projectRoot . '/Documentation';
if (is_dir($docDir)) {
    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($docDir, RecursiveDirectoryIterator::SKIP_DOTS)) as $file) {
        if (!$file->isFile()) {
            continue;
        }
        if (!in_array($file->getExtension(), ['rst', 'md'], true)) {
            continue;
        }
        $label = ltrim(str_replace($projectRoot, '', $file->getPathname()), '/');
        $docFiles[$label] = $file->getPathname();
    }
    ksort($docFiles);
}

$checked = 0;
foreach ($docFiles as $label => $path) {
    if (!is_file($path)) {
        continue;
    }

    foreach ($extractExamples($path) as [$lineNo, $cmdLine]) {
        [$command, $options, $positional] = $parseExample($cmdLine);

        if (!isset($commands[$command])) {
            $violations[] = "{$label}:{$lineNo}: unknown command '{$command}'";

            continue;
        }
        ++$checked;

        $def = $commands[$command];
        foreach ($options as $opt) {
            if (isset($def['options'][$opt])) {
                continue;
            }
            if (in_array($opt, $globalOptions, true)) {
                continue;
            }
            $known = array_keys($def['options']);
            sort($known);
            $hint = $known === [] ? '(command has no options)' : '(have: --' . implode(', --', $known) . ')';
            $violations[] = "{$label}:{$lineNo}: '{$command}' has no option '--{$opt}' {$hint}";
        }

        if ($positional > $def['args']) {
            $violations[] = "{$label}:{$lineNo}: '{$command}' takes {$def['args']} positional argument(s), example passes {$positional}";
        }
    }
}

if ($violations !== []) {
    sort($violations);
    fwrite(STDERR, "ERROR: CLI documentation drift detected:\n");
    foreach ($violations as $v) {
        fwrite(STDERR, "  - {$v}\n");
    }
    fwrite(STDERR, "\nFix the documented example(s) to match the command signature in\n");
    fwrite(STDERR, "Classes/Command/*Command.php, or update the command definition.\n");
    exit(1);
}

echo 'OK: ' . $checked . ' documented vault:* example(s) match their command signatures (' . count($commands) . " commands).\n";
exit(0);
