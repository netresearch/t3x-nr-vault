<?php

/*
 * Copyright (c) 2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

namespace Netresearch\NrVault\Tests\Unit\Api\Support;

/**
 * Classifies the difference between two rendered API surfaces.
 *
 * A snapshot assertion that only reports "different" makes a new value
 * object look exactly like a deleted method, so every diff gets read with
 * the same shrug. This splits the difference into buckets and answers the
 * only question the author actually has: may I regenerate the file, or do I
 * have to decide something?
 *
 * - **added** — a class, method, property, constant or enum case that was
 *   not there before. Additive; existing callers keep compiling.
 * - **removed** — gone. Every caller that used it breaks.
 * - **changed** — same member, different signature. Includes a widened
 *   constructor, which a plain line diff would report as one unrelated
 *   removal plus one unrelated addition.
 * - **breaks implementers** — a method added to an extension point, an
 *   interface marked `#[ExtensionPoint]`. Harmless to every caller, and a
 *   fatal error for every existing implementation: PHP refuses to load a
 *   class that does not implement each method of its interface.
 *
 * The same holds for a changed method on an extension point, optional
 * parameter or not, which is why the breaking verdict explains both sides.
 * The mark itself is read from the rendered declaration line
 * (`FQCN (interface, extension point)`), so the diff needs nothing but the
 * two renderings. Gaining the mark is a new promise and additive; losing it
 * withdraws one and lands in `changed`.
 *
 * Members are matched by NAME, not by rendered line, so a signature change
 * lands in `changed` instead of showing up as an unrelated removal plus an
 * unrelated addition.
 *
 * Ported from nr-llm's `Tests/Unit/Api/Support/ApiSurfaceDiff.php`
 * (issue #306); the "what to do" guidance and the implementer side differ.
 */
final readonly class ApiSurfaceDiff
{
    /**
     * Appended by ApiSurfaceRenderer to the kind of an interface that carries
     * `#[ExtensionPoint]`.
     */
    public const EXTENSION_POINT_MARKER = 'extension point';

    /**
     * How many entries a bucket prints before it is truncated. A surface-wide
     * rename produces hundreds; the first few say the same thing.
     */
    private const MAX_LISTED = 40;

    /**
     * The synthetic member key of the block header, so a `class` that became
     * an `interface` is a change like any other.
     */
    private const DECLARATION_KEY = '(declaration)';

    /**
     * @param list<string> $added
     * @param list<string> $removed
     * @param list<array{entry: string, was: string, now: string}> $changed
     * @param list<string> $implementerBreaks methods added to an existing extension point
     */
    private function __construct(
        public array $added,
        public array $removed,
        public array $changed,
        public array $implementerBreaks,
    ) {}

    public static function between(string $expected, string $actual): self
    {
        $before = self::parse($expected);
        $after = self::parse($actual);

        $added = [];
        $removed = [];
        $changed = [];
        $implementerBreaks = [];

        foreach ($after as $fqcn => $members) {
            if (!isset($before[$fqcn])) {
                $added[] = $members[self::DECLARATION_KEY] ?? $fqcn;

                continue;
            }

            $wasExtensionPoint = self::isExtensionPoint($before[$fqcn][self::DECLARATION_KEY] ?? '');

            foreach ($members as $key => $line) {
                if (!isset($before[$fqcn][$key])) {
                    if ($wasExtensionPoint && str_starts_with($line, 'method ')) {
                        $implementerBreaks[] = $fqcn . ' :: ' . $line;
                    } else {
                        $added[] = $fqcn . ' :: ' . $line;
                    }

                    continue;
                }

                $was = $before[$fqcn][$key];
                if ($was === $line) {
                    continue;
                }

                if ($key === self::DECLARATION_KEY && self::onlyGainedTheMark($was, $line)) {
                    $added[] = $line;

                    continue;
                }

                $changed[] = [
                    'entry' => $fqcn . ' :: ' . $key,
                    'was' => $was,
                    'now' => $line,
                ];
            }
        }

        foreach ($before as $fqcn => $members) {
            if (!isset($after[$fqcn])) {
                $removed[] = $members[self::DECLARATION_KEY] ?? $fqcn;

                continue;
            }

            foreach ($members as $key => $line) {
                if (!isset($after[$fqcn][$key])) {
                    $removed[] = $fqcn . ' :: ' . $line;
                }
            }
        }

        sort($added);
        sort($removed);
        sort($implementerBreaks);
        usort($changed, static fn (array $a, array $b): int => strcmp($a['entry'], $b['entry']));

        return new self($added, $removed, $changed, $implementerBreaks);
    }

    public function isEmpty(): bool
    {
        return $this->added === [] && $this->removed === [] && $this->changed === [] && $this->implementerBreaks === [];
    }

    /**
     * True when nothing was removed, nothing changed shape and no extension
     * point gained a method — the case an author may resolve by regenerating
     * the snapshot.
     */
    public function isAdditiveOnly(): bool
    {
        return !$this->isEmpty() && $this->removed === [] && $this->changed === [] && $this->implementerBreaks === [];
    }

    /**
     * `identical`, `additive` or `breaking` — the word the failure message
     * leads with.
     */
    public function verdict(): string
    {
        return match (true) {
            $this->isEmpty() => 'identical',
            $this->isAdditiveOnly() => 'additive',
            default => 'breaking',
        };
    }

    /**
     * The failure message body: what happened, and what the author must do
     * about it.
     */
    public function describe(): string
    {
        if ($this->isEmpty()) {
            return 'The rendered public surface matches api-surface.txt.';
        }

        $counts = \sprintf(
            '%d added, %d removed, %d changed, %d breaking implementers',
            \count($this->added),
            \count($this->removed),
            \count($this->changed),
            \count($this->implementerBreaks),
        );

        $sections = [];

        if ($this->isAdditiveOnly()) {
            $sections[] = strtoupper($this->verdict()) . ' — ' . $counts . '. Nothing was removed, '
                . 'no existing signature changed and no extension point gained a method, so neither '
                . 'a caller nor an implementation breaks.';
            $sections[] = 'What to do: regenerate the snapshot (delete Tests/Unit/Api/api-surface.txt, '
                . 'run the unit suite twice) and note the addition under "### Added" in CHANGELOG.md.';
        } else {
            $sections[] = strtoupper($this->verdict()) . ' — ' . $counts . '. A removed line breaks '
                . 'every caller that used it. A changed one may or may not break a caller: an added '
                . 'OPTIONAL parameter breaks no call, an added required one breaks every call. Read the '
                . 'was/now pair below — the rendering marks an optional parameter with " = …". On an '
                . 'extension point (a declaration marked "' . self::EXTENSION_POINT_MARKER . '") the '
                . 'implementation side decides instead: every added or changed method breaks every '
                . 'existing implementation, optional parameter or not, because PHP refuses to load a '
                . 'class whose methods no longer match its interface.';
            $sections[] = 'What to do: this is a decision, not a regeneration. AGENTS.md puts '
                . 'changing public API signatures of *Interface.php under "Ask First" — agree the '
                . 'change before it lands. Then record it under a BREAKING heading in CHANGELOG.md '
                . 'and regenerate the snapshot. A widening that only adds optional parameters to a '
                . 'method nobody implements is additive for callers: note it under "### Added" and '
                . 'regenerate. For an extension point, ship the new capability as a separate '
                . 'interface an implementation may additionally implement and a caller detects with '
                . 'instanceof (the CancellableHttpClientInterface precedent), or hold it for a major '
                . 'release. A constructor of a service you only ever obtain from the DI container is '
                . 'not a caller contract, but it is still recorded here so a widened one cannot land '
                . 'unread.';
        }

        if ($this->implementerBreaks !== []) {
            $sections[] = $this->bucket('breaks implementers', '!', $this->implementerBreaks);
        }

        if ($this->removed !== []) {
            $sections[] = $this->bucket('removed', '-', $this->removed);
        }

        if ($this->changed !== []) {
            $lines = [];
            foreach ($this->changed as $entry) {
                $lines[] = $entry['entry'] . "\n        was: " . $entry['was'] . "\n        now: " . $entry['now'];
            }

            $sections[] = $this->bucket('changed', '~', $lines);
        }

        if ($this->added !== []) {
            $sections[] = $this->bucket('added', '+', $this->added);
        }

        return implode("\n\n", $sections);
    }

    /**
     * @param list<string> $entries
     */
    private function bucket(string $title, string $marker, array $entries): string
    {
        $shown = \array_slice($entries, 0, self::MAX_LISTED);
        $formatted = array_map(static fn (string $entry): string => '  ' . $marker . ' ' . $entry, $shown);

        if (\count($entries) > self::MAX_LISTED) {
            $formatted[] = \sprintf('  … and %d more', \count($entries) - self::MAX_LISTED);
        }

        return $title . ':' . "\n" . implode("\n", $formatted);
    }

    /**
     * `Foo\Bar (interface, extension point)` → true.
     */
    private static function isExtensionPoint(string $header): bool
    {
        return str_ends_with($header, ', ' . self::EXTENSION_POINT_MARKER . ')');
    }

    /**
     * `Foo\Bar (interface)` → `Foo\Bar (interface, extension point)` and
     * nothing else.
     */
    private static function onlyGainedTheMark(string $was, string $now): bool
    {
        return !self::isExtensionPoint($was)
            && str_ends_with($was, ')')
            && $now === substr($was, 0, -1) . ', ' . self::EXTENSION_POINT_MARKER . ')';
    }

    /**
     * @return array<string, array<string, string>> FQCN => member key => rendered line
     */
    private static function parse(string $text): array
    {
        $classes = [];

        foreach (explode("\n\n", trim($text)) as $block) {
            $lines = array_values(array_filter(
                array_map(rtrim(...), explode("\n", $block)),
                static fn (string $line): bool => trim($line) !== '',
            ));

            if ($lines === []) {
                continue;
            }

            $header = trim($lines[0]);
            $fqcn = self::classNameOf($header);

            $members = [self::DECLARATION_KEY => $header];
            foreach (\array_slice($lines, 1) as $line) {
                $member = trim($line);
                $members[self::memberKey($member)] = $member;
            }

            $classes[$fqcn] = $members;
        }

        return $classes;
    }

    /**
     * `Foo\Bar (class)` → `Foo\Bar`; `Foo\Bar (interface, extension point)`
     * → `Foo\Bar`.
     */
    private static function classNameOf(string $header): string
    {
        return preg_match('/^(\S+) \([a-z, ]+\)$/', $header, $matches) === 1 ? $matches[1] : $header;
    }

    /**
     * The name a member is matched by across the two renderings.
     *
     * Modifiers are deliberately dropped from the key: a method that became
     * `static`, or a property that lost `readonly`, must land in `changed`
     * rather than read as one removal and one unrelated addition.
     */
    private static function memberKey(string $line): string
    {
        if (str_starts_with($line, 'constructor(')) {
            return 'constructor';
        }

        if (preg_match('/^(method|property) (?:static |readonly )?(\w+)/', $line, $matches) === 1) {
            return $matches[1] . ' ' . $matches[2];
        }

        if (preg_match('/^(const|case) (\w+)/', $line, $matches) === 1) {
            return $matches[1] . ' ' . $matches[2];
        }

        return $line;
    }
}
