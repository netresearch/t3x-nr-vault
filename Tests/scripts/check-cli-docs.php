<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * Documentation drift guard for the `vault:*` CLI.
 *
 * Two independent passes over README.md and everything under Documentation/,
 * both checked against the authoritative command definitions in
 * Classes/Command/*Command.php.
 *
 * Pass 1 — shell examples. Every `vendor/bin/typo3 vault:<cmd> ...` invocation:
 *
 *   - the command name must exist (`#[AsCommand(name: 'vault:...')]`)
 *   - every `--option` used must be a real option of THAT command
 *     (or a known global Symfony/TYPO3 option)
 *   - the number of positional arguments must not exceed the command's
 *     declared `addArgument()` count
 *
 * Pass 2 — the per-command `Options` definition lists in the RST reference.
 * Examples alone are not enough: the reference once documented
 * `vault:store --description/--context/--expires` and `vault:retrieve -q`,
 * none of which exist, while omitting `--stdin`, `--file` and `--limit` —
 * and pass 1 stayed green throughout, because no example used the invented
 * options. Each documented term is therefore compared against the real
 * `addOption()` call:
 *
 *   - the long option must exist on that command
 *   - the short form must be the real shortcut (present, absent, identical)
 *   - a value-taking option must be written `--name=VALUE`, a flag must not
 *   - the term must be well-shaped: `--name=VALUE, -x VALUE` exactly
 *     (a `-x =VALUE` typo previously stood in nine places)
 *   - every real option must be documented, and no option twice
 *   - Symfony's global options are REJECTED here (see $globalOptions)
 *
 * Both passes are hard failures: an invented option is actively harmful (it is
 * copied into a deployment script and fails, or silently does something else),
 * and an omitted one is what sends a reader to guess. Neither is a warning,
 * because a warning nobody gates on is how the drift lasted this long.
 *
 * Like check-test-base-class.php this is a lightweight static scan (regex,
 * no autoloader) so it runs before the test suite, in pre-commit hooks, and
 * on fresh checkouts where `.Build/` may be empty. `--self-test` proves the
 * pass-2 checks actually fail when they should; see check-cli-docs-selftest.php.
 *
 * Exit codes:
 *   0 — the documented examples and option lists match the real signatures
 *   1 — at least one documented example or option contradicts the command
 *       definitions (or, with --self-test, a check failed to catch its case)
 */

$projectRoot = dirname(__DIR__, 2);
$commandDir = $projectRoot . '/Classes/Command';

if (!is_dir($commandDir)) {
    fwrite(STDERR, "Command directory not found: {$commandDir}\n");
    exit(1);
}

/*
 * Options Symfony's Application and TYPO3's CommandApplication add to every
 * command.
 *
 * In a shell EXAMPLE these are legitimate: `vault:audit --no-interaction` is a
 * real thing to run. In a per-command Options LIST they are not, and pass 2
 * rejects them outright — no whitelist, no opt-out marker. Claiming a global in
 * a command's own option list asserts the command owns it and gives it
 * command-specific semantics, which is precisely how `-q` came to be
 * documented as the `vault:retrieve` scripting flag: it is Symfony's global
 * quiet switch, it suppresses the value, and the documented pipeline captured
 * an empty string. An opt-out marker would only be a slower route back to that.
 *
 * A command that genuinely declares an option of the same name is unaffected:
 * pass 2 resolves each documented term against the command's own definitions
 * first, so `vault:init --env` (a real VALUE_NONE option) never reaches this
 * list.
 */
$globalOptions = [
    'help', 'quiet', 'verbose', 'version', 'ansi', 'no-ansi',
    'no-interaction', 'env', 'no-debug',
];

/**
 * The PHP files below $commandDir, in the iterator's order.
 *
 * @return list<string>
 */
function commandClassFiles(string $commandDir): array
{
    /** @var list<string> $paths */
    $paths = [];

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($commandDir, RecursiveDirectoryIterator::SKIP_DOTS)) as $file) {
        if (!$file->isFile()) {
            continue;
        }
        if ($file->getExtension() !== 'php') {
            continue;
        }
        $paths[] = $file->getPathname();
    }

    return $paths;
}

/**
 * Parse the `addOption(name, shortcut, mode, ...)` calls of one command class.
 *
 * All three are captured, so the documented short form and value placeholder
 * can be verified too — not just the option name.
 *
 * @return array<string, array{short: ?string, value: bool}>
 */
function parseCommandOptions(string $contents): array
{
    /** @var array<string, array{short: ?string, value: bool}> $options */
    $options = [];

    preg_match_all(
        '/->addOption\(\s*[\'"]([a-zA-Z0-9][a-zA-Z0-9-]*)[\'"]\s*,'
        . '\s*(?:null|[\'"]([a-zA-Z0-9])[\'"])\s*,'
        . '\s*((?:\s*InputOption::[A-Z_]+\s*\|?)+)/',
        $contents,
        $optMatches,
        PREG_SET_ORDER,
    );
    foreach ($optMatches as $match) {
        $options[$match[1]] = [
            'short' => $match[2] === '' ? null : $match[2],
            'value' => str_contains($match[3], 'VALUE_REQUIRED')
                || str_contains($match[3], 'VALUE_OPTIONAL'),
        ];
    }

    return $options;
}

/**
 * Parse every command class into name => {options, positional argument count}.
 *
 * Each option carries its real short form and whether it takes a value, so the
 * documented term can be compared against the full signature rather than the
 * name alone.
 *
 * @return array{0: array<string, array{options: array<string, array{short: ?string, value: bool}>, args: int}>, 1: list<string>}
 */
function parseCommandDefinitions(string $commandDir): array
{
    /** @var array<string, array{options: array<string, array{short: ?string, value: bool}>, args: int}> $commands */
    $commands = [];
    /** @var list<string> $errors */
    $errors = [];

    foreach (commandClassFiles($commandDir) as $path) {
        $contents = file_get_contents($path);
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

        $options = parseCommandOptions($contents);

        // An addOption() call the regex could not read would silently drop out
        // of the model — the option would then read as invented in the docs AND
        // escape the completeness check. Fail loudly instead of guarding half
        // the surface.
        $declared = preg_match_all('/->addOption\(/', $contents);
        if ($declared !== count($options)) {
            $errors[] = sprintf(
                '%s: parsed %d of %d addOption() call(s) — the guard cannot see the full signature of %s',
                basename($path),
                count($options),
                (int) $declared,
                $name,
            );
        }

        // Positional argument count: number of addArgument() calls.
        $argCount = preg_match_all('/->addArgument\(/', $contents);

        $commands[$name] = ['options' => $options, 'args' => (int) $argCount];
    }

    if ($commands === []) {
        $errors[] = "No #[AsCommand] classes parsed from {$commandDir}";
    }

    return [$commands, $errors];
}

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

/**
 * True when $title/$underline form an RST section header: a non-empty title
 * whose next line is a run of punctuation at least as long as the title.
 */
function isRstSectionHeader(string $title, string $underline): bool
{
    return $title !== ''
        && preg_match('/^([=\-~^"\'`#*+]){2,}$/', $underline) === 1
        && strlen($underline) >= strlen($title);
}

/**
 * Extract the per-command `Options` definition lists from an RST reference page.
 *
 * A command section is a `vault:<name>` title with an underline; the option
 * terms are the unindented `--…` lines inside its `Options` subsection. Scoping
 * to that subsection matters: `vault:doctor` also carries a "Control catalogue"
 * definition list whose terms are not options at all.
 *
 * Returns the command sections found (name => title line) alongside their terms,
 * so a section that documents no options can be told apart from a command that
 * has no section in this file.
 *
 * Declared as a named function rather than a closure, like the helpers in
 * Build/Scripts/collect-evidence.php: PHPStan does not apply a docblock to a
 * closure assigned to a variable, so the array shapes these three helpers pass
 * around would degrade to `mixed` and take the guard's own type safety with them.
 *
 * @return array{sections: array<string,int>, options: array<string, list<array{int, string}>>}
 */
function parseDocumentedOptions(string $rst): array
{
    /** @var array<string,int> $sections */
    $sections = [];
    /** @var array<string, list<array{int, string}>> $options */
    $options = [];

    $lines = preg_split('/\R/', $rst);
    if ($lines === false) {
        return ['sections' => $sections, 'options' => $options];
    }

    $command = null;
    $inOptions = false;
    $count = count($lines);

    // An explicit cursor rather than a `for` counter: a header consumes TWO
    // lines (title + underline), and advancing a loop counter from inside the
    // body is exactly the kind of hidden control flow this guard should not have.
    $cursor = 0;
    while ($cursor < $count) {
        $line = $lines[$cursor];
        $lineNo = $cursor + 1;
        $title = trim($line);

        if (isRstSectionHeader($title, $lines[$cursor + 1] ?? '')) {
            if (preg_match('/^(vault:[a-z][a-z0-9-]*)$/', $title, $sectionMatch) === 1) {
                $command = $sectionMatch[1];
                $sections[$command] = $lineNo;
                $inOptions = false;
            } else {
                $inOptions = $title === 'Options';
            }
            $cursor += 2;

            continue;
        }

        ++$cursor;

        if (!$inOptions) {
            continue;
        }
        if ($command === null) {
            continue;
        }
        if (preg_match('/^--\S/', $line) !== 1) {
            continue;
        }

        $options[$command][] = [$lineNo, rtrim($line)];
    }

    return ['sections' => $sections, 'options' => $options];
}

/**
 * Render the canonical term for a real option, reusing the placeholder the
 * author chose (`PATH`, `TEXT`, `N`, …) so the expectation shown in a failure
 * is the line the author should have written, not a generic one.
 */
function renderOptionTerm(string $name, ?string $short, bool $takesValue, string $placeholder): string
{
    $term = '--' . $name . ($takesValue ? '=' . $placeholder : '');
    if ($short !== null) {
        $term .= ', -' . $short . ($takesValue ? ' ' . $placeholder : '');
    }

    return $term;
}

/**
 * Split one documented term into its four parts, or null when it is malformed.
 *
 * Shape rule: `--name[=PLACEHOLDER][, -x [PLACEHOLDER]]` and nothing else. The
 * placeholder may itself contain '=' (--metadata=KEY=VALUE) but may not start
 * with one, which is what makes the `-x =VALUE` typo fail.
 *
 * @return array{name: string, placeholder: string, short: ?string, shortPlaceholder: string}|null
 */
function parseOptionTerm(string $term): ?array
{
    $shape = preg_match(
        '/^--([a-z0-9][a-z0-9-]*)(?:=([^\s,=][^\s,]*))?(?:, -([a-zA-Z0-9])(?: ([^\s,=][^\s,]*))?)?$/',
        $term,
        $parts,
    );
    if ($shape !== 1) {
        return null;
    }

    $short = $parts[3] ?? '';

    return [
        'name' => $parts[1],
        'placeholder' => $parts[2] ?? '',
        'short' => $short === '' ? null : $short,
        'shortPlaceholder' => $parts[4] ?? '',
    ];
}

/**
 * Rule: a documented long option must be declared by THAT command.
 *
 * A Symfony global gets its own message, because "remove the entry" is the fix,
 * whereas "the command does not declare it" would read as an invitation to add
 * the option to the command.
 *
 * @param array<string, array{short: ?string, value: bool}> $real
 * @param list<string> $globalOptions
 */
function violationForUndeclaredOption(string $where, string $name, array $real, array $globalOptions): ?string
{
    if (isset($real[$name])) {
        return null;
    }

    if (in_array($name, $globalOptions, true)) {
        return "{$where} documents the global option '--{$name}' as its own"
            . ' — Symfony adds it to every command, so a per-command entry claims'
            . ' semantics it does not have (this is how -q was documented as a'
            . ' scripting flag; it suppresses the output). Remove the entry.';
    }

    $known = array_keys($real);
    sort($known);

    return "{$where} documents '--{$name}', which the command does not declare"
        . ' (real options: --' . implode(', --', $known) . ')';
}

/**
 * Rule: the documented term must render exactly like the real signature.
 *
 * Comparing the whole rendered term rather than each property one at a time:
 * one comparison catches the wrong shortcut, a missing or invented shortcut, a
 * value marker on a flag, a missing one on a value-taking option, and a short
 * placeholder that disagrees with the long one — and it always names the exact
 * line to write.
 *
 * @param array{name: string, placeholder: string, short: ?string, shortPlaceholder: string} $parsed
 * @param array{short: ?string, value: bool} $real
 */
function violationForSignatureMismatch(string $where, string $term, array $parsed, array $real): ?string
{
    $placeholder = $parsed['placeholder'] === '' ? 'VALUE' : $parsed['placeholder'];

    $expected = renderOptionTerm($parsed['name'], $real['short'], $real['value'], $placeholder);
    $canonical = renderOptionTerm($parsed['name'], $parsed['short'], $parsed['placeholder'] !== '', $placeholder);

    $selfConsistent = $canonical === $term
        && ($parsed['short'] === null || $parsed['shortPlaceholder'] === $parsed['placeholder']);

    if ($selfConsistent && $canonical === $expected) {
        return null;
    }

    return "{$where} documents '{$term}'; the real signature is '{$expected}'";
}

/**
 * Rule: every option the command declares must appear in the list.
 *
 * @param array<string, array{short: ?string, value: bool}> $real
 * @param array<string,int> $seen documented long name => line
 *
 * @return list<string>
 */
function violationsForUndocumentedOptions(
    string $label,
    int $sectionLine,
    string $command,
    array $real,
    array $seen,
): array {
    /** @var list<string> $violations */
    $violations = [];

    foreach (array_diff(array_keys($real), array_keys($seen)) as $name) {
        $violations[] = sprintf(
            "%s:%d: '%s' does not document '%s'",
            $label,
            $sectionLine,
            $command,
            renderOptionTerm($name, $real[$name]['short'], $real[$name]['value'], 'VALUE'),
        );
    }

    return $violations;
}

/**
 * Run every per-term rule over ONE command's Options list, then the
 * completeness rule over the list as a whole.
 *
 * @param array<string, array{short: ?string, value: bool}> $real
 * @param list<array{int, string}> $terms
 * @param list<string> $globalOptions
 *
 * @return array{violations: list<string>, checked: int}
 */
function validateCommandOptionList(
    string $label,
    string $command,
    int $sectionLine,
    array $real,
    array $terms,
    array $globalOptions,
): array {
    /** @var list<string> $violations */
    $violations = [];
    /** @var array<string,int> $seen documented long name => line */
    $seen = [];

    foreach ($terms as [$lineNo, $term]) {
        $where = "{$label}:{$lineNo}: '{$command}'";

        $parsed = parseOptionTerm($term);
        if ($parsed === null) {
            $violations[] = "{$where} has a malformed option term '{$term}'"
                . " (expected '--name=VALUE, -x VALUE', '--name=VALUE' or '--name')";

            continue;
        }

        $name = $parsed['name'];

        $undeclared = violationForUndeclaredOption($where, $name, $real, $globalOptions);
        if ($undeclared !== null) {
            $violations[] = $undeclared;

            continue;
        }

        if (isset($seen[$name])) {
            $violations[] = "{$where} documents '--{$name}' twice (also on line {$seen[$name]})";
        }
        $seen[$name] = $lineNo;

        $mismatch = violationForSignatureMismatch($where, $term, $parsed, $real[$name]);
        if ($mismatch !== null) {
            $violations[] = $mismatch;
        }
    }

    return [
        'violations' => [
            ...$violations,
            ...violationsForUndocumentedOptions($label, $sectionLine, $command, $real, $seen),
        ],
        'checked' => count($terms),
    ];
}

/**
 * Check the documented option lists of one file against the real definitions.
 *
 * A command section without an `Options` subsection is skipped rather than
 * flagged: Documentation/Usage/Index.rst walks through the same commands
 * task-first, with examples and no option lists, and forcing it to duplicate
 * the reference would be worse documentation. The list has to exist SOMEWHERE
 * though — the commands whose list was validated here are reported back so
 * validateOptionCoverage() can require exactly that, which also closes the
 * "delete the section instead of fixing it" escape.
 *
 * @param array<string, array{options: array<string, array{short: ?string, value: bool}>, args: int}> $commands
 * @param array{sections: array<string,int>, options: array<string, list<array{int, string}>>} $documented
 * @param list<string> $globalOptions
 *
 * @return array{violations: list<string>, checked: int, covered: list<string>}
 */
function validateDocumentedOptions(
    array $commands,
    array $documented,
    array $globalOptions,
    string $label,
): array {
    /** @var list<string> $violations */
    $violations = [];
    /** @var list<string> $covered */
    $covered = [];
    $checked = 0;

    foreach ($documented['sections'] as $command => $sectionLine) {
        if (!isset($commands[$command])) {
            $violations[] = "{$label}:{$sectionLine}: documents unknown command '{$command}'";

            continue;
        }

        $terms = $documented['options'][$command] ?? [];
        if ($terms === []) {
            continue;
        }
        $covered[] = $command;

        $result = validateCommandOptionList(
            $label,
            $command,
            $sectionLine,
            $commands[$command]['options'],
            $terms,
            $globalOptions,
        );
        $violations = [...$violations, ...$result['violations']];
        $checked += $result['checked'];
    }

    return ['violations' => $violations, 'checked' => $checked, 'covered' => $covered];
}

/**
 * Every command that declares options must have its Options list on some page.
 *
 * Without this, the per-list checks are opt-in: a command whose documentation
 * disagrees with its signature could be brought back into line by deleting the
 * Options list rather than correcting it, and a newly added command could ship
 * with no option reference at all.
 *
 * @param array<string, array{options: array<string, array{short: ?string, value: bool}>, args: int}> $commands
 * @param list<string> $covered
 *
 * @return list<string>
 */
function validateOptionCoverage(array $commands, array $covered): array
{
    /** @var list<string> $violations */
    $violations = [];

    foreach ($commands as $command => $definition) {
        if ($definition['options'] === []) {
            continue;
        }
        if (in_array($command, $covered, true)) {
            continue;
        }
        $violations[] = sprintf(
            "no Options list documents '%s', which declares %d option(s): --%s",
            $command,
            count($definition['options']),
            implode(', --', array_keys($definition['options'])),
        );
    }

    return $violations;
}

// $argv is only populated when register_argc_argv is on; read it via $_SERVER
// so the guard also behaves under an unusual CLI ini.
$arguments = $_SERVER['argv'] ?? [];
if (is_array($arguments) && in_array('--self-test', $arguments, true)) {
    require_once __DIR__ . '/check-cli-docs-selftest.php';

    exit(checkCliDocsSelfTest());
}

[$commands, $parseErrors] = parseCommandDefinitions($commandDir);
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
$checkedOptions = 0;
/** @var list<string> $covered commands whose Options list was validated */
$covered = [];
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

    // Pass 2 — the per-command Options definition lists. RST only: the command
    // sections are keyed on a `vault:<name>` title with an underline, which is
    // the reference-page shape. A file without such a section contributes
    // nothing and is silently skipped.
    if (str_ends_with($path, '.rst')) {
        $rst = file_get_contents($path);
        if ($rst !== false) {
            $result = validateDocumentedOptions(
                $commands,
                parseDocumentedOptions($rst),
                $globalOptions,
                $label,
            );
            $violations = [...$violations, ...$result['violations']];
            $covered = [...$covered, ...$result['covered']];
            $checkedOptions += $result['checked'];
        }
    }
}

$violations = [...$violations, ...validateOptionCoverage($commands, $covered)];

if ($violations !== []) {
    sort($violations);
    fwrite(STDERR, "ERROR: CLI documentation drift detected:\n");
    foreach ($violations as $v) {
        fwrite(STDERR, "  - {$v}\n");
    }
    fwrite(STDERR, "\nFix the documented example(s) and Options list(s) to match the command\n");
    fwrite(STDERR, "signature in Classes/Command/*Command.php, or update the command definition.\n");
    exit(1);
}

echo 'OK: ' . $checked . ' documented vault:* example(s) and ' . $checkedOptions
    . ' documented option(s) match their command signatures (' . count($commands) . " commands).\n";
exit(0);
