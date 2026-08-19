<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * Release evidence bundle collector.
 *
 * Assembles whatever verification artifacts exist at release time into a
 * single directory (`.Build/evidence/` by default) containing:
 *
 *   evidence-manifest.json   machine-readable manifest (stable schema)
 *   EVIDENCE.md              human-readable render of the same data
 *   artifacts/               verbatim copies of every input that was found
 *
 * The collector never *produces* evidence — it only reads what the test,
 * coverage, mutation, audit and doctor steps left behind. A producer that
 * did not run is recorded with status "absent" and does NOT fail the run:
 * the bundle is meant to describe a release honestly, including its gaps.
 * Only an artifact that is present but unparseable is an error, because
 * that means the bundle would misrepresent a check that actually ran.
 *
 * Supply-chain artifacts (SBOMs, Cosign bundles, checksums, build-provenance
 * attestation) are produced by the org-reusable release workflow and live on
 * the GitHub Release, not in this bundle. The manifest references them by
 * their documented asset names; it does not regenerate or re-sign them.
 *
 * Like Tests/scripts/check-cli-docs.php this is a dependency-free script
 * (no autoloader, no composer packages) so it runs on a bare checkout.
 *
 * Exit codes:
 *   0 — bundle written (regardless of individual check statuses)
 *   1 — an artifact was present but malformed, or the bundle could not be
 *       written, or --self-test found a regression
 *   2 — usage error (unknown option, unresolvable build timestamp)
 */

const SCHEMA_VERSION = 1;

/**
 * Security-relevant source directories that get their own coverage line in
 * the manifest. Mirrors the source scope of the security mutation ratchet
 * (infection-security.json5), the codecov security components, the
 * security-critical path table in CONTRIBUTING.md and the `Classes/`
 * entries in CODEOWNERS.
 */
const SECURITY_DIRS = ['Classes/Crypto', 'Classes/Security', 'Classes/Audit', 'Classes/Http'];

/**
 * Infection config for the security-scoped mutation run. Absent on releases
 * that predate the security ratchet, which makes that check "absent".
 */
const SECURITY_MUTATION_CONFIG = 'infection-security.json5';

/**
 * Test suites the collector looks for, in report order. Each maps to an input
 * key `junit-<suite>`; a suite that left no log is simply not reported.
 */
const TEST_SUITES = ['unit', 'fuzz', 'functional'];

/**
 * Overall line-coverage bar. Sourced from the `patch` target in codecov.yml
 * so the bundle does not invent a second, conflicting policy.
 */
const MIN_LINE_COVERAGE = 80.0;

/**
 * Bar for the security directories in SECURITY_DIRS. Deliberately stricter
 * than MIN_LINE_COVERAGE — crypto/audit/access-control code is the part an
 * auditor cares about. Override with --min-security-coverage.
 */
const MIN_SECURITY_COVERAGE = 90.0;

/** Lowest PHPStan level still recorded as "pass". */
const MIN_PHPSTAN_LEVEL = 9;

/**
 * Thrown when an artifact exists but cannot be interpreted. Distinct from an
 * absent artifact, which is a normal, non-fatal outcome.
 */
final class MalformedArtifactException extends RuntimeException {}

// ---------------------------------------------------------------------------
// Small typed helpers
// ---------------------------------------------------------------------------

/**
 * Read a file or throw. Used for artifacts we already know exist.
 */
function readFileOrFail(string $path): string
{
    if (!is_file($path) || !is_readable($path)) {
        throw new MalformedArtifactException("cannot read {$path}", 3708722807);
    }
    $contents = file_get_contents($path);
    if ($contents === false) {
        throw new MalformedArtifactException("cannot read {$path}", 9714683605);
    }

    return $contents;
}

/**
 * Decode a JSON artifact into an array, treating anything else as malformed.
 *
 * @return array<string, mixed>
 */
function decodeJsonArtifact(string $path): array
{
    try {
        $decoded = json_decode(readFileOrFail($path), true, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        throw new MalformedArtifactException("{$path} is not valid JSON: " . $e->getMessage(), 0, $e);
    }

    if (!is_array($decoded)) {
        throw new MalformedArtifactException("{$path} does not contain a JSON object", 5811083281);
    }

    /** @var array<string, mixed> $decoded */
    return $decoded;
}

/**
 * Parse an XML artifact, converting libxml failures into a malformed error.
 */
function loadXmlArtifact(string $path): SimpleXMLElement
{
    $previous = libxml_use_internal_errors(true);

    try {
        $xml = simplexml_load_string(readFileOrFail($path));
        if (!$xml instanceof SimpleXMLElement) {
            $first = libxml_get_last_error();
            $detail = $first === false ? 'unparseable XML' : trim($first->message);

            throw new MalformedArtifactException("{$path}: {$detail}", 3133594368);
        }

        return $xml;
    } finally {
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
    }
}

/**
 * Read an integer XML attribute, or null when it is absent/non-numeric.
 */
function xmlInt(SimpleXMLElement $element, string $attribute): ?int
{
    $raw = $element[$attribute];
    if ($raw === null) {
        return null;
    }
    $value = (string) $raw;

    return $value === '' || !is_numeric($value) ? null : (int) $value;
}

/**
 * Percentage of $covered out of $total, or null when there is nothing to
 * measure (an empty denominator is "no data", never 0 % or 100 %).
 */
function percentage(int $covered, int $total): ?float
{
    return $total === 0 ? null : round($covered / $total * 100, 2);
}

function formatPercentage(?float $value): string
{
    return $value === null ? 'n/a' : number_format($value, 2, '.', '') . '%';
}

/**
 * @param non-empty-string $pattern
 */
function matchFirst(string $pattern, string $subject): ?string
{
    return preg_match($pattern, $subject, $m) === 1 ? $m[1] : null;
}

/**
 * Build one entry of the manifest `checks` array.
 *
 * @param 'pass'|'warn'|'fail'|'absent' $status
 *
 * @return array{id: string, status: string, summary: string, source: string}
 */
function check(string $id, string $status, string $summary, string $source): array
{
    return ['id' => $id, 'status' => $status, 'summary' => $summary, 'source' => $source];
}

/**
 * @param 'pass'|'warn'|'fail' $onPass
 *
 * @return 'pass'|'warn'|'fail'
 */
function thresholdStatus(?float $actual, float $minimum, string $onPass = 'pass'): string
{
    if ($actual === null) {
        return 'warn';
    }

    return $actual >= $minimum ? $onPass : 'fail';
}

// ---------------------------------------------------------------------------
// Producers — each returns exactly one check entry
// ---------------------------------------------------------------------------

/**
 * Extension version from ext_emconf.php. Parsed rather than included: the
 * file expects $_EXTKEY to be defined by TYPO3's extension loader.
 */
function readExtensionVersion(string $root): ?string
{
    $emconf = $root . '/ext_emconf.php';
    if (!is_file($emconf)) {
        return null;
    }

    return matchFirst("/'version'\s*=>\s*'([^']+)'/", readFileOrFail($emconf));
}

/**
 * @return array{id: string, status: string, summary: string, source: string}
 */
function checkReleaseIdentity(?string $tag, string $commit, ?string $version): array
{
    $source = 'ext_emconf.php + git';

    if ($version === null) {
        return check('release-identity', 'fail', 'ext_emconf.php has no parseable version', $source);
    }

    $shortCommit = substr($commit, 0, 12);

    if ($tag === null || $tag === '') {
        return check(
            'release-identity',
            'warn',
            "version {$version} at commit {$shortCommit} — no release tag supplied (not a tagged build)",
            $source,
        );
    }

    $tagVersion = ltrim($tag, 'vV');
    if ($tagVersion !== $version) {
        return check(
            'release-identity',
            'fail',
            "tag {$tag} does not match ext_emconf version {$version}",
            $source,
        );
    }

    return check(
        'release-identity',
        'pass',
        "tag {$tag} matches ext_emconf version {$version} at commit {$shortCommit}",
        $source,
    );
}

/**
 * Aggregate Clover statement/branch metrics, overall and per source prefix.
 *
 * @param list<string> $prefixes
 *
 * @return array{
 *     line: float|null,
 *     branch: float|null,
 *     statements: int,
 *     covered: int,
 *     perPrefix: array<string, float|null>
 * }
 */
function parseClover(string $path, array $prefixes): array
{
    $xml = loadXmlArtifact($path);

    $projectMetrics = $xml->xpath('/coverage/project/metrics');
    if ($projectMetrics === null || $projectMetrics === []) {
        throw new MalformedArtifactException("{$path}: no /coverage/project/metrics element", 4640153950);
    }
    $metrics = $projectMetrics[0];

    $statements = xmlInt($metrics, 'statements');
    $covered = xmlInt($metrics, 'coveredstatements');
    if ($statements === null || $covered === null) {
        throw new MalformedArtifactException("{$path}: project metrics lack statement counts", 6498936204);
    }

    $conditionals = xmlInt($metrics, 'conditionals') ?? 0;
    $coveredConditionals = xmlInt($metrics, 'coveredconditionals') ?? 0;

    /** @var array<string, int> $prefixStatements */
    $prefixStatements = [];
    /** @var array<string, int> $prefixCovered */
    $prefixCovered = [];
    foreach ($prefixes as $prefix) {
        $prefixStatements[$prefix] = 0;
        $prefixCovered[$prefix] = 0;
    }

    $files = $xml->xpath('//file');
    foreach ($files ?? [] as $file) {
        $name = (string) ($file['name'] ?? '');
        if ($name === '') {
            continue;
        }
        $normalized = str_replace('\\', '/', $name);
        $fileMetrics = $file->metrics;
        if (!$fileMetrics instanceof SimpleXMLElement) {
            continue;
        }
        $fileStatements = xmlInt($fileMetrics, 'statements');
        $fileCovered = xmlInt($fileMetrics, 'coveredstatements');
        if ($fileStatements === null) {
            continue;
        }
        if ($fileCovered === null) {
            continue;
        }

        foreach ($prefixes as $prefix) {
            if (!str_contains($normalized, '/' . $prefix . '/')) {
                continue;
            }
            $prefixStatements[$prefix] += $fileStatements;
            $prefixCovered[$prefix] += $fileCovered;
        }
    }

    /** @var array<string, float|null> $perPrefix */
    $perPrefix = [];
    foreach ($prefixStatements as $prefix => $total) {
        $perPrefix[$prefix] = percentage($prefixCovered[$prefix], $total);
    }

    return [
        'line' => percentage($covered, $statements),
        'branch' => percentage($coveredConditionals, $conditionals),
        'statements' => $statements,
        'covered' => $covered,
        'perPrefix' => $perPrefix,
    ];
}

/**
 * Totals from one PHPUnit JUnit log.
 *
 * @return array{tests: int, failures: int, errors: int, skipped: int}
 */
function parseJunit(string $path): array
{
    $xml = loadXmlArtifact($path);
    // PHPUnit emits a root <testsuites> wrapping one <testsuite> per suite;
    // the aggregate counters live on the outermost element that has them.
    $root = $xml->getName() === 'testsuites' ? ($xml->testsuite[0] ?? $xml) : $xml;

    $tests = xmlInt($xml, 'tests') ?? xmlInt($root, 'tests');
    if ($tests === null) {
        throw new MalformedArtifactException("{$path}: no test counters on the root element", 1388064956);
    }

    return [
        'tests' => $tests,
        'failures' => xmlInt($xml, 'failures') ?? xmlInt($root, 'failures') ?? 0,
        'errors' => xmlInt($xml, 'errors') ?? xmlInt($root, 'errors') ?? 0,
        'skipped' => xmlInt($xml, 'skipped') ?? xmlInt($root, 'skipped') ?? 0,
    ];
}

/**
 * The JUnit logs that were found, keyed by suite name in TEST_SUITES order.
 *
 * @param array<string, string|null> $inputs
 *
 * @return array<string, string>
 */
function junitSuites(array $inputs): array
{
    $suites = [];
    foreach (TEST_SUITES as $suite) {
        $path = $inputs['junit-' . $suite] ?? null;
        if ($path !== null) {
            $suites[$suite] = $path;
        }
    }

    return $suites;
}

/**
 * Aggregate every suite that left a JUnit log. Per-suite counts stay in the
 * summary so a reader can tell *which* suite broke, and a suite that did not
 * run is simply absent from the list rather than silently counted as passing.
 *
 * @param array<string, string> $suites suite name => JUnit path
 *
 * @return array{id: string, status: string, summary: string, source: string}
 */
function checkTestResults(array $suites): array
{
    $source = 'PHPUnit JUnit logs';

    if ($suites === []) {
        return check('tests', 'absent', 'no JUnit log produced by this build', $source);
    }

    $parts = [];
    $failed = false;
    $totalTests = 0;
    foreach ($suites as $suite => $path) {
        $totals = parseJunit($path);
        $totalTests += $totals['tests'];
        $broken = $totals['failures'] + $totals['errors'];
        if ($broken > 0) {
            $failed = true;
        }
        $detail = "{$suite} {$totals['tests']}";
        if ($broken > 0) {
            $detail .= " ({$totals['failures']} failures, {$totals['errors']} errors)";
        }
        if ($totals['skipped'] > 0) {
            $detail .= " ({$totals['skipped']} skipped)";
        }
        $parts[] = $detail;
    }

    $summary = "{$totalTests} tests across " . count($suites) . ' suite(s) — ' . implode(', ', $parts);

    return check('tests', $failed ? 'fail' : 'pass', $summary, $source);
}

/**
 * @param array{line: float|null, branch: float|null, statements: int, covered: int, perPrefix: array<string, float|null>}|null $coverage
 *
 * @return array{id: string, status: string, summary: string, source: string}
 */
function checkCoverage(?array $coverage): array
{
    $source = 'clover.xml';

    if ($coverage === null) {
        return check('coverage-line', 'absent', 'no coverage report produced by this build', $source);
    }

    $summary = sprintf(
        'line %s (%d/%d statements), branch %s — bar %s',
        formatPercentage($coverage['line']),
        $coverage['covered'],
        $coverage['statements'],
        formatPercentage($coverage['branch']),
        formatPercentage(MIN_LINE_COVERAGE),
    );

    return check('coverage-line', thresholdStatus($coverage['line'], MIN_LINE_COVERAGE), $summary, $source);
}

/**
 * @param array{line: float|null, branch: float|null, statements: int, covered: int, perPrefix: array<string, float|null>}|null $coverage
 *
 * @return array{id: string, status: string, summary: string, source: string}
 */
function checkSecurityCoverage(?array $coverage, float $minimum): array
{
    $source = 'clover.xml';

    if ($coverage === null) {
        return check('coverage-security-dirs', 'absent', 'no coverage report produced by this build', $source);
    }

    $parts = [];
    $status = 'pass';
    foreach ($coverage['perPrefix'] as $prefix => $percent) {
        $parts[] = $prefix . ' ' . formatPercentage($percent);
        if ($percent === null) {
            // Directory contributed no measured files — not a failure, but the
            // bundle must not claim the bar was met either.
            $status = $status === 'fail' ? 'fail' : 'warn';

            continue;
        }
        if ($percent < $minimum) {
            $status = 'fail';
        }
    }

    $summary = implode(', ', $parts) . ' — bar ' . formatPercentage($minimum);

    return check('coverage-security-dirs', $status, $summary, $source);
}

/**
 * Infection thresholds are authoritative in infection.json5. That file is
 * JSON5 (comments, trailing commas) so it is scanned, not decoded.
 *
 * @return array{minMsi: float|null, minCoveredMsi: float|null}
 */
function readMutationThresholds(string $root, string $configName = 'infection.json5'): array
{
    $config = $root . '/' . $configName;
    if (!is_file($config)) {
        return ['minMsi' => null, 'minCoveredMsi' => null];
    }
    $contents = readFileOrFail($config);
    $minMsi = matchFirst('/"minMsi"\s*:\s*([0-9.]+)/', $contents);
    $minCovered = matchFirst('/"minCoveredMsi"\s*:\s*([0-9.]+)/', $contents);

    return [
        'minMsi' => $minMsi === null ? null : (float) $minMsi,
        'minCoveredMsi' => $minCovered === null ? null : (float) $minCovered,
    ];
}

/**
 * One mutation-score check. Called once for the whole codebase and once for the
 * security-scoped run, which is why the id, scope label and config name are
 * parameters rather than constants.
 *
 * @param array{minMsi: float|null, minCoveredMsi: float|null} $thresholds
 *
 * @return array{id: string, status: string, summary: string, source: string}
 */
function checkMutation(
    ?string $infectionJson,
    array $thresholds,
    string $id = 'mutation-msi',
    string $scope = 'whole codebase',
    string $configName = 'infection.json5',
): array {
    // When the report is absent there is no filename to name, so fall back to
    // the report this scope *would* have produced (infection.json5 logs to
    // infection.json, infection-security.json5 to infection-security.json).
    $source = $infectionJson === null
        ? str_replace('.json5', '.json', $configName)
        : basename($infectionJson);

    if ($infectionJson === null) {
        // Deliberately does not claim why it is missing. On a tagged release
        // the release-evidence workflow does run Infection, so an absent report
        // there means the mutation job failed or was skipped — a real signal,
        // not an expected gap. Name the producers and let the reader judge.
        return check(
            $id,
            'absent',
            "no mutation report for the {$scope} in this build — produced by the mutation job in release-evidence.yml, or locally via `make test-mutation`",
            $source,
        );
    }

    $report = decodeJsonArtifact($infectionJson);
    $stats = $report['stats'] ?? null;
    if (!is_array($stats) || !isset($stats['msi']) || !is_numeric($stats['msi'])) {
        throw new MalformedArtifactException("{$infectionJson}: missing .stats.msi", 9904897261);
    }

    $msi = (float) $stats['msi'];
    $coveredMsi = isset($stats['coveredCodeMsi']) && is_numeric($stats['coveredCodeMsi'])
        ? (float) $stats['coveredCodeMsi']
        : null;

    $summary = $scope . ': MSI ' . formatPercentage($msi)
        . ', covered-code MSI ' . formatPercentage($coveredMsi);

    $minMsi = $thresholds['minMsi'];
    if ($minMsi === null) {
        return check($id, 'warn', $summary . " — no threshold found in {$configName}", $source);
    }

    $summary .= ' — bar ' . formatPercentage($minMsi);
    $status = $msi >= $minMsi ? 'pass' : 'fail';

    $minCovered = $thresholds['minCoveredMsi'];
    if ($minCovered !== null && $coveredMsi !== null && $coveredMsi < $minCovered) {
        $status = 'fail';
        $summary .= ' / covered bar ' . formatPercentage($minCovered);
    }

    return check($id, $status, $summary, $source);
}

/**
 * @return array{id: string, status: string, summary: string, source: string}
 */
function checkStaticAnalysis(string $root): array
{
    $source = 'phpstan.neon';
    $config = $root . '/phpstan.neon';

    if (!is_file($config)) {
        return check('static-analysis', 'absent', 'no phpstan.neon in this checkout', $source);
    }

    $level = matchFirst('/^\s*level:\s*(\S+)/m', readFileOrFail($config));
    if ($level === null) {
        throw new MalformedArtifactException("{$config}: no `level:` setting found", 3519928559);
    }

    $numeric = $level === 'max' ? 10 : (is_numeric($level) ? (int) $level : null);
    if ($numeric === null) {
        throw new MalformedArtifactException("{$config}: unrecognised level `{$level}`", 4284766832);
    }

    return check(
        'static-analysis',
        $numeric >= MIN_PHPSTAN_LEVEL ? 'pass' : 'warn',
        "PHPStan level {$level} (bar " . MIN_PHPSTAN_LEVEL . ') over Classes + Tests',
        $source,
    );
}

/**
 * @return array{id: string, status: string, summary: string, source: string}
 */
function checkDependencyAudit(?string $auditJson): array
{
    $source = 'composer audit --format=json';

    if ($auditJson === null) {
        return check('dependency-audit', 'absent', 'no composer audit report in this build', $source);
    }

    $report = decodeJsonArtifact($auditJson);
    $advisories = $report['advisories'] ?? [];
    $abandoned = $report['abandoned'] ?? [];
    if (!is_array($advisories) || !is_array($abandoned)) {
        throw new MalformedArtifactException("{$auditJson}: unexpected advisories/abandoned shape", 5665648318);
    }

    $advisoryCount = 0;
    foreach ($advisories as $perPackage) {
        $advisoryCount += is_array($perPackage) ? count($perPackage) : 1;
    }
    $abandonedCount = count($abandoned);

    $summary = "{$advisoryCount} advisories, {$abandonedCount} abandoned packages";

    if ($advisoryCount > 0) {
        return check('dependency-audit', 'fail', $summary . ' — ' . implode(', ', array_keys($advisories)), $source);
    }
    if ($abandonedCount > 0) {
        return check('dependency-audit', 'warn', $summary . ' — ' . implode(', ', array_keys($abandoned)), $source);
    }

    return check('dependency-audit', 'pass', $summary, $source);
}

/**
 * True when this checkout registers the `vault:doctor` command. Scanned the
 * same way check-cli-docs.php scans command definitions, so it works without
 * a booted TYPO3 or a populated .Build/.
 */
function hasDoctorCommand(string $root): bool
{
    $commandDir = $root . '/Classes/Command';
    if (!is_dir($commandDir)) {
        return false;
    }

    $files = glob($commandDir . '/*.php');
    foreach ($files === false ? [] : $files as $file) {
        if (!is_readable($file)) {
            continue;
        }
        $contents = file_get_contents($file);
        if ($contents === false) {
            continue;
        }
        if (preg_match('/#\[AsCommand\(\s*(?:name:\s*)?[\'"]vault:doctor[\'"]/', $contents) === 1) {
            return true;
        }
    }

    return false;
}

/**
 * @return array{id: string, status: string, summary: string, source: string}
 */
function checkDoctor(string $root, ?string $doctorJson): array
{
    $source = 'vault:doctor --format=json';

    if (!hasDoctorCommand($root)) {
        // A report cannot describe a command this version does not ship, so it
        // is ignored — but say so rather than dropping it silently, because the
        // only ways to get here are a stale drop-zone or a foreign artifact.
        if ($doctorJson !== null) {
            return check(
                'vault-doctor',
                'warn',
                'a doctor report was supplied but vault:doctor is not in this version — ignored as stale or foreign',
                $source,
            );
        }

        return check(
            'vault-doctor',
            'absent',
            'vault:doctor is not available in this version of the extension',
            $source,
        );
    }

    if ($doctorJson === null) {
        return check(
            'vault-doctor',
            'warn',
            'vault:doctor exists but produced no report in this build',
            $source,
        );
    }

    $report = decodeJsonArtifact($doctorJson);

    // A crash or an unusable --profile value emits {"error": ..., "exitCode": ...}
    // and no severity at all. That must never read as a pass: the check did not
    // run, so its result is unknown, and unknown is not clean.
    if (isset($report['error'])) {
        $detail = is_string($report['error']) ? $report['error'] : 'unspecified error';

        return check('vault-doctor', 'fail', "vault:doctor did not complete: {$detail}", $source);
    }

    // Verified against DoctorReport::toArray() on feature/vault-doctor: the
    // report carries `highestSeverity` (worst-wins) and `exitCode`, NOT a
    // `status` key. The string map is kept as a fallback in case the shape
    // grows one, and `exitCode` as a fallback in case severity is dropped.
    $severityMap = ['pass' => 'pass', 'warning' => 'warn', 'critical' => 'fail'];
    $stringMap = [
        'ok' => 'pass', 'pass' => 'pass', 'healthy' => 'pass',
        'warn' => 'warn', 'warning' => 'warn', 'degraded' => 'warn',
        'fail' => 'fail', 'error' => 'fail', 'critical' => 'fail',
    ];
    $exitMap = [0 => 'pass', 1 => 'warn', 2 => 'fail'];

    $severity = $report['highestSeverity'] ?? null;
    $severity = is_string($severity) ? strtolower($severity) : null;

    $status = null;
    $reported = null;
    if ($severity !== null && isset($severityMap[$severity])) {
        $status = $severityMap[$severity];
        $reported = $severity;
    } else {
        $raw = $report['status'] ?? $report['overallStatus'] ?? null;
        $raw = is_string($raw) ? strtolower($raw) : null;
        if ($raw !== null && isset($stringMap[$raw])) {
            $status = $stringMap[$raw];
            $reported = $raw;
        } elseif (isset($report['exitCode']) && is_int($report['exitCode']) && isset($exitMap[$report['exitCode']])) {
            $status = $exitMap[$report['exitCode']];
            $reported = 'exit code ' . $report['exitCode'];
        }
    }

    if ($status === null) {
        return check(
            'vault-doctor',
            'warn',
            'doctor report present but carries no recognised severity, status or exit code',
            $source,
        );
    }

    $summary = "doctor reports {$reported}";

    // `profile` is the profile the run was evaluated against, which may be an
    // override (--profile=hardened on a standard install answers a hypothetical).
    // Recording both keeps the evidence unambiguous.
    $profile = $report['profile'] ?? null;
    $configured = $report['configuredProfile'] ?? null;
    if (is_string($profile) && $profile !== '') {
        $summary .= " for profile {$profile}";
        if (is_string($configured) && $configured !== '' && $configured !== $profile) {
            $summary .= " (configured: {$configured})";
        }
    }

    $counts = $report['summary'] ?? null;
    if (is_array($counts) && isset($counts['total']) && is_int($counts['total'])) {
        $summary .= " across {$counts['total']} controls";
        if (isset($counts['warning'], $counts['critical']) && is_int($counts['warning']) && is_int($counts['critical'])) {
            $summary .= " ({$counts['critical']} critical, {$counts['warning']} warning)";
        }
    } else {
        $findings = $report['findings'] ?? $report['checks'] ?? null;
        if (is_array($findings)) {
            $summary .= ' across ' . count($findings) . ' probes';
        }
    }

    // VaultDoctorService contains a crashing check by turning it into a
    // `check.crashed` CRITICAL finding, so an unreachable database looks
    // identical to a genuinely bad posture unless the ids are inspected. Those
    // areas were never evaluated: that is incomplete evidence, not a finding.
    $crashed = crashedDoctorChecks($report);
    if ($crashed !== []) {
        $areas = implode(', ', $crashed);
        $summary .= ' — INCOMPLETE: ' . count($crashed) . " check(s) could not run ({$areas}); "
            . 'those controls are unevaluated, not satisfied';

        // Only soften to "inconclusive" when every critical IS a crash. A real
        // critical alongside a crash must still fail, or the crash would mask it.
        if ($status === 'fail' && !hasNonCrashCritical($report)) {
            $status = 'warn';
        }
    }

    return check('vault-doctor', $status, $summary, $source);
}

/**
 * Names of the readiness checks that crashed, taken from `details.check` on
 * every `check.crashed` finding.
 *
 * @param array<string, mixed> $report
 *
 * @return list<string>
 */
function crashedDoctorChecks(array $report): array
{
    $names = [];
    foreach (doctorFindings($report) as $finding) {
        if (($finding['id'] ?? null) !== 'check.crashed') {
            continue;
        }
        $details = $finding['details'] ?? null;
        $name = is_array($details) && isset($details['check']) && is_string($details['check'])
            ? $details['check']
            : 'unnamed check';
        $names[] = $name;
    }

    return $names;
}

/**
 * True when at least one critical finding is a real control failure rather than
 * a crashed check.
 *
 * @param array<string, mixed> $report
 */
function hasNonCrashCritical(array $report): bool
{
    foreach (doctorFindings($report) as $finding) {
        $severity = $finding['severity'] ?? null;
        if (!is_string($severity)) {
            continue;
        }
        if (strtolower($severity) !== 'critical') {
            continue;
        }
        if (($finding['id'] ?? null) !== 'check.crashed') {
            return true;
        }
    }

    return false;
}

/**
 * The report's findings, normalised to a list of arrays.
 *
 * @param array<string, mixed> $report
 *
 * @return list<array<string, mixed>>
 */
function doctorFindings(array $report): array
{
    $raw = $report['findings'] ?? null;
    if (!is_array($raw)) {
        return [];
    }

    $findings = [];
    foreach ($raw as $finding) {
        if (is_array($finding)) {
            /** @var array<string, mixed> $finding */
            $findings[] = $finding;
        }
    }

    return $findings;
}

// ---------------------------------------------------------------------------
// Manifest assembly
// ---------------------------------------------------------------------------

/**
 * Release assets produced by the org-reusable release workflow
 * (netresearch/typo3-ci-workflows release-typo3-extension.yml). Referenced by
 * URL only — this bundle neither regenerates nor re-signs them.
 *
 * @return list<array{name: string, url: string}>
 */
function releaseAssetPointers(string $repo, string $prefix, ?string $tag, ?string $version): array
{
    if ($tag === null || $tag === '' || $version === null) {
        return [];
    }

    $base = "https://github.com/{$repo}/releases/download/{$tag}/";
    $stem = "{$prefix}-{$version}";

    $assets = [
        "{$stem}.zip",
        "{$stem}.tar.gz",
        "{$stem}.sbom.spdx.json",
        "{$stem}.sbom.cdx.json",
        'checksums.txt',
        "{$stem}.zip.sigstore.json",
        "{$stem}.tar.gz.sigstore.json",
    ];

    $pointers = [];
    foreach ($assets as $asset) {
        $pointers[] = ['name' => $asset, 'url' => $base . $asset];
    }

    // Build-provenance lives in GitHub's attestation store, not as a file asset.
    $pointers[] = [
        'name' => 'build-provenance attestation',
        'url' => "https://github.com/{$repo}/attestations",
    ];

    return $pointers;
}

/**
 * @param array{
 *     root: string,
 *     tag: string|null,
 *     commit: string,
 *     builtAt: string,
 *     repo: string,
 *     archivePrefix: string,
 *     extensionKey: string,
 *     minSecurityCoverage: float,
 *     inputs: array<string, string|null>,
 *     bundled: list<array{name: string, path: string, sha256: string}>
 * } $context
 *
 * @return array{
 *     schemaVersion: int,
 *     extension: string,
 *     version: string|null,
 *     commit: string,
 *     builtAt: string,
 *     checks: list<array{id: string, status: string, summary: string, source: string}>,
 *     artifacts: list<array<string, string>>
 * }
 */
function buildManifest(array $context): array
{
    $root = $context['root'];
    $inputs = $context['inputs'];
    $version = readExtensionVersion($root);

    $clover = $inputs['clover'] ?? null;
    $coverage = $clover === null ? null : parseClover($clover, SECURITY_DIRS);

    $checks = [
        checkReleaseIdentity($context['tag'], $context['commit'], $version),
        checkTestResults(junitSuites($inputs)),
        checkCoverage($coverage),
        checkSecurityCoverage($coverage, $context['minSecurityCoverage']),
        checkMutation($inputs['infection'] ?? null, readMutationThresholds($root)),
        checkMutation(
            $inputs['infectionSecurity'] ?? null,
            readMutationThresholds($root, SECURITY_MUTATION_CONFIG),
            'mutation-msi-security',
            'security-critical scope (' . implode(', ', SECURITY_DIRS) . ')',
            SECURITY_MUTATION_CONFIG,
        ),
        checkStaticAnalysis($root),
        checkDependencyAudit($inputs['audit'] ?? null),
        checkDoctor($root, $inputs['doctor'] ?? null),
    ];

    /** @var list<array<string, string>> $artifacts */
    $artifacts = [];
    foreach ($context['bundled'] as $entry) {
        $artifacts[] = $entry;
    }
    foreach (releaseAssetPointers($context['repo'], $context['archivePrefix'], $context['tag'], $version) as $pointer) {
        $artifacts[] = $pointer;
    }

    return [
        'schemaVersion' => SCHEMA_VERSION,
        'extension' => $context['extensionKey'],
        'version' => $version,
        'commit' => $context['commit'],
        'builtAt' => $context['builtAt'],
        'checks' => $checks,
        'artifacts' => $artifacts,
    ];
}

/**
 * Render the manifest as the human-readable EVIDENCE.md.
 *
 * @param array{
 *     schemaVersion: int,
 *     extension: string,
 *     version: string|null,
 *     commit: string,
 *     builtAt: string,
 *     checks: list<array{id: string, status: string, summary: string, source: string}>,
 *     artifacts: list<array<string, string>>
 * } $manifest
 */
function renderMarkdown(array $manifest): string
{
    $labels = ['pass' => 'PASS', 'warn' => 'WARN', 'fail' => 'FAIL', 'absent' => 'ABSENT'];

    /** @var array<string, int> $tally */
    $tally = ['pass' => 0, 'warn' => 0, 'fail' => 0, 'absent' => 0];
    foreach ($manifest['checks'] as $entry) {
        $tally[$entry['status']] = ($tally[$entry['status']] ?? 0) + 1;
    }

    $lines = [];
    $lines[] = '# Release evidence — ' . $manifest['extension'] . ' ' . ($manifest['version'] ?? 'unknown version');
    $lines[] = '';
    $lines[] = 'Generated by `Build/Scripts/collect-evidence.php` from the verification';
    $lines[] = 'artifacts present at release time. Checks marked ABSENT had no producer in';
    $lines[] = 'this build — that is recorded, not hidden.';
    $lines[] = '';
    $lines[] = '| | |';
    $lines[] = '|---|---|';
    $lines[] = '| Extension | `' . $manifest['extension'] . '` |';
    $lines[] = '| Version | ' . ($manifest['version'] ?? 'unknown') . ' |';
    $lines[] = '| Commit | `' . $manifest['commit'] . '` |';
    $lines[] = '| Built at | ' . $manifest['builtAt'] . ' |';
    $lines[] = '| Schema | ' . $manifest['schemaVersion'] . ' |';
    $lines[] = '';
    $lines[] = sprintf(
        'Result: %d pass, %d warn, %d fail, %d absent.',
        $tally['pass'],
        $tally['warn'],
        $tally['fail'],
        $tally['absent'],
    );
    $lines[] = '';
    $lines[] = '## Checks';
    $lines[] = '';
    $lines[] = '| Check | Status | Summary | Source |';
    $lines[] = '|---|---|---|---|';
    foreach ($manifest['checks'] as $entry) {
        $lines[] = sprintf(
            '| `%s` | %s | %s | `%s` |',
            $entry['id'],
            $labels[$entry['status']] ?? strtoupper($entry['status']),
            $entry['summary'],
            $entry['source'],
        );
    }

    $lines[] = '';
    $lines[] = '## Artifacts';
    $lines[] = '';
    $lines[] = 'Files under `artifacts/` are verbatim copies of the inputs this bundle was';
    $lines[] = 'built from. Entries with a URL are produced and signed by the release';
    $lines[] = 'workflow and live on the GitHub Release; this bundle references them, it';
    $lines[] = 'does not reproduce them.';
    $lines[] = '';

    $bundled = [];
    $referenced = [];
    foreach ($manifest['artifacts'] as $artifact) {
        if (isset($artifact['path'])) {
            $bundled[] = $artifact;
        } else {
            $referenced[] = $artifact;
        }
    }

    if ($bundled === []) {
        $lines[] = '_No input artifacts were present in this build._';
        $lines[] = '';
    } else {
        $lines[] = '| Bundled file | SHA-256 |';
        $lines[] = '|---|---|';
        foreach ($bundled as $artifact) {
            $lines[] = '| `' . $artifact['path'] . '` | `' . ($artifact['sha256'] ?? '') . '` |';
        }
        $lines[] = '';
    }

    if ($referenced !== []) {
        $lines[] = '| Release asset | Location |';
        $lines[] = '|---|---|';
        foreach ($referenced as $artifact) {
            $lines[] = '| ' . $artifact['name'] . ' | <' . ($artifact['url'] ?? '') . '> |';
        }
        $lines[] = '';
    }

    $lines[] = '## Verifying the supply-chain artifacts';
    $lines[] = '';
    $lines[] = '```bash';
    $lines[] = '# Cosign keyless signature (bundle format)';
    $lines[] = 'cosign verify-blob --bundle <asset>.sigstore.json \\';
    $lines[] = '  --certificate-oidc-issuer https://token.actions.githubusercontent.com \\';
    $lines[] = '  --certificate-identity-regexp \'^https://github.com/netresearch/\' <asset>';
    $lines[] = '';
    $lines[] = '# Checksums';
    $lines[] = 'sha256sum -c checksums.txt';
    $lines[] = '';
    $lines[] = '# Build provenance';
    $lines[] = 'gh attestation verify <asset> --repo netresearch/t3x-nr-vault';
    $lines[] = '```';
    $lines[] = '';

    return implode("\n", $lines);
}

// ---------------------------------------------------------------------------
// Bundle writing
// ---------------------------------------------------------------------------

function ensureDirectory(string $path): void
{
    if (is_dir($path)) {
        return;
    }
    if (!mkdir($path, 0o775, true) && !is_dir($path)) {
        throw new MalformedArtifactException("cannot create directory {$path}", 4597115234);
    }
}

/**
 * Copy every present input into <output>/artifacts/ and return manifest
 * entries with a bundle-relative path and a SHA-256 of the copy.
 *
 * @param array<string, string|null> $inputs
 *
 * @return list<array{name: string, path: string, sha256: string}>
 */
function bundleInputs(array $inputs, string $outputDir): array
{
    $names = [
        'clover' => 'clover.xml',
        'infection' => 'infection.json',
        'infectionSecurity' => 'infection-security.json',
        'infectionSummary' => 'infection-summary.log',
        'audit' => 'composer-audit.json',
        'doctor' => 'vault-doctor.json',
    ];
    foreach (TEST_SUITES as $suite) {
        $names['junit-' . $suite] = 'junit-' . $suite . '.xml';
    }

    $present = array_filter($inputs, static fn (?string $path): bool => $path !== null);
    if ($present === []) {
        return [];
    }

    $artifactDir = $outputDir . '/artifacts';
    ensureDirectory($artifactDir);

    $entries = [];
    foreach ($present as $key => $path) {
        $target = $names[$key] ?? basename((string) $path);
        if (!copy((string) $path, $artifactDir . '/' . $target)) {
            throw new MalformedArtifactException("cannot copy {$path} into {$artifactDir}", 8611380534);
        }
        $hash = hash_file('sha256', $artifactDir . '/' . $target);
        if ($hash === false) {
            throw new MalformedArtifactException("cannot hash {$artifactDir}/{$target}", 2244921220);
        }
        $entries[] = ['name' => $target, 'path' => 'artifacts/' . $target, 'sha256' => $hash];
    }

    return $entries;
}

function writeFileOrFail(string $path, string $contents): void
{
    if (file_put_contents($path, $contents) === false) {
        throw new MalformedArtifactException("cannot write {$path}", 6329280501);
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/**
 * @param list<string> $argv
 *
 * @return array<string, string>
 */
function parseArguments(array $argv): array
{
    $known = [
        'output-dir', 'parts', 'tag', 'commit', 'built-at', 'repo', 'archive-prefix', 'extension-key',
        'clover', 'junit', 'junit-unit', 'junit-fuzz', 'junit-functional',
        'infection', 'infection-security', 'infection-summary', 'audit', 'doctor',
        'min-security-coverage',
    ];

    /** @var array<string, string> $options */
    $options = [];
    foreach (array_slice($argv, 1) as $argument) {
        if ($argument === '--self-test') {
            $options['self-test'] = '1';

            continue;
        }
        if ($argument === '--help' || $argument === '-h') {
            $options['help'] = '1';

            continue;
        }
        if (preg_match('/^--([a-z-]+)=(.*)$/', $argument, $m) !== 1) {
            fwrite(STDERR, "Unknown or malformed argument: {$argument}\n");
            exit(2);
        }
        if (!in_array($m[1], $known, true)) {
            fwrite(STDERR, "Unknown option: --{$m[1]}\n");
            exit(2);
        }
        $options[$m[1]] = $m[2];
    }

    return $options;
}

function usage(): string
{
    return <<<'TXT'
    collect-evidence.php — assemble a release evidence bundle.

    Usage:
      Build/Scripts/collect-evidence.php [options]
      Build/Scripts/collect-evidence.php --self-test

    Options:
      --output-dir=DIR            bundle destination (default .Build/evidence)
      --parts=DIR                 drop-zone of CI-produced reports, checked
                                  before the in-tree defaults. Expected names:
                                    junit-unit.xml, junit-fuzz.xml,
                                    junit-functional.xml, clover.xml,
                                    infection.json, infection-security.json,
                                    infection-summary.log,
                                    composer-audit.json, doctor.json
      --tag=TAG                   release tag (default $GITHUB_REF_NAME)
      --commit=SHA                commit SHA (default $GITHUB_SHA, else git HEAD)
      --built-at=RFC3339          build timestamp (default $BUILD_TIMESTAMP,
                                  else the HEAD committer date — never wall clock)
      --repo=OWNER/NAME           repo slug for release-asset URLs
                                  (default $GITHUB_REPOSITORY)
      --archive-prefix=PREFIX     release archive prefix (default nr-vault)
      --extension-key=KEY         extension key (default nr_vault)
      --clover=FILE               default .Build/coverage/clover.xml
      --junit=FILE                unit-suite log, alias of --junit-unit
                                  (default .Build/logs/junit.xml)
      --junit-fuzz=FILE           default .Build/logs/junit-fuzz.xml
      --junit-functional=FILE     default .Build/logs/junit-functional.xml
      --infection=FILE            default .Build/infection/infection.json
      --infection-security=FILE   security-scoped Infection report (default
                                  .Build/infection-security/infection.json)
      --infection-summary=FILE    default .Build/infection/summary.log
      --audit=FILE                composer audit --format=json output
                                  (default .Build/evidence-inputs/composer-audit.json)
      --doctor=FILE               vault:doctor --format=json output
                                  (default .Build/evidence-inputs/doctor.json)
      --min-security-coverage=N   bar for the security dirs (default 90)
      --self-test                 run fixture self-checks, write nothing
      -h, --help                  this text

    A producer that did not run is recorded as "absent" and the exit code stays
    0. Only a present-but-malformed artifact is an error.
    TXT;
}

/**
 * Resolve an optional artifact path. Precedence: explicit `--flag`, then the
 * `--parts` drop-zone, then the default in-tree location, then null (absent).
 * An explicitly requested file that does not exist is a usage error, not a
 * silent absence — a typo must not masquerade as a missing producer.
 *
 * The drop-zone exists because the CI jobs that produce evidence run in
 * separate runners: each uploads its reports into one flat directory, and the
 * bundling job points `--parts` at the merged download.
 *
 * @param array<string, string> $options
 */
function resolveInput(array $options, string $option, string $default, ?string $partsName = null): ?string
{
    if (isset($options[$option])) {
        $path = $options[$option];
        if ($path === '') {
            return null;
        }
        if (!is_file($path)) {
            fwrite(STDERR, "--{$option} points at a missing file: {$path}\n");
            exit(2);
        }

        return usableArtifact($path) ? $path : null;
    }

    if (isset($options['parts']) && $partsName !== null) {
        $candidate = rtrim($options['parts'], '/') . '/' . $partsName;
        if (is_file($candidate) && usableArtifact($candidate)) {
            return $candidate;
        }
    }

    return is_file($default) && usableArtifact($default) ? $default : null;
}

/**
 * An empty artifact means the producer died before writing anything — a shell
 * redirect creates the file before the command runs, so a hard crash leaves a
 * zero-byte file behind. That is an ABSENT producer, not a corrupt artifact:
 * treating it as malformed would abort the whole bundle and throw away all the
 * other evidence over one step that failed to start.
 *
 * A truncated but non-empty artifact stays malformed — there the producer did
 * write something, and silently ignoring it would misreport a check that ran.
 */
function usableArtifact(string $path): bool
{
    $size = filesize($path);
    if ($size === false || $size === 0) {
        return false;
    }
    // Cheap whitespace-only guard: a few bytes of newline is still "nothing".
    if ($size <= 8) {
        $head = file_get_contents($path, false, null, 0, 8);

        return $head !== false && trim($head) !== '';
    }

    return true;
}

function gitOutput(string $root, string $command): ?string
{
    $escapedRoot = escapeshellarg($root);
    $output = shell_exec("git -C {$escapedRoot} {$command} 2>/dev/null");
    if (!is_string($output)) {
        return null;
    }
    $trimmed = trim($output);

    return $trimmed === '' ? null : $trimmed;
}

/**
 * Never uses the wall clock: a bundle rebuilt from the same commit with the
 * same inputs must be byte-identical.
 *
 * @param array<string, string> $options
 */
function resolveBuiltAt(array $options, string $root): string
{
    $explicit = $options['built-at'] ?? getenv('BUILD_TIMESTAMP');
    if (is_string($explicit) && $explicit !== '') {
        return $explicit;
    }

    $committed = gitOutput($root, 'log -1 --format=%cI');
    if ($committed !== null) {
        return $committed;
    }

    fwrite(STDERR, "Cannot determine build timestamp: pass --built-at= or set BUILD_TIMESTAMP.\n");
    exit(2);
}

/**
 * @param array<string, string> $options
 */
function run(array $options, string $root): int
{
    $outputDir = $options['output-dir'] ?? $root . '/.Build/evidence';
    $commit = $options['commit']
        ?? (is_string($env = getenv('GITHUB_SHA')) && $env !== '' ? $env : null)
        ?? gitOutput($root, 'rev-parse HEAD')
        ?? 'unknown';

    $tag = $options['tag'] ?? (is_string($ref = getenv('GITHUB_REF_NAME')) && $ref !== '' ? $ref : null);
    if ($tag !== null && !str_starts_with($tag, 'v')) {
        // GITHUB_REF_NAME is a branch name outside tag events — not a release tag.
        $tag = isset($options['tag']) ? $tag : null;
    }

    $repo = $options['repo']
        ?? (is_string($slug = getenv('GITHUB_REPOSITORY')) && $slug !== '' ? $slug : null)
        ?? 'netresearch/t3x-nr-vault';

    if (isset($options['parts']) && !is_dir($options['parts'])) {
        fwrite(STDERR, "--parts points at a missing directory: {$options['parts']}\n");
        exit(2);
    }

    // `--junit` is the alias for the unit suite, whose log is `junit.xml` by
    // convention (that is what `--log-junit` writes by default).
    if (isset($options['junit']) && !isset($options['junit-unit'])) {
        $options['junit-unit'] = $options['junit'];
    }

    $inputs = [
        'junit-unit' => resolveInput($options, 'junit-unit', $root . '/.Build/logs/junit.xml', 'junit-unit.xml'),
        'junit-fuzz' => resolveInput($options, 'junit-fuzz', $root . '/.Build/logs/junit-fuzz.xml', 'junit-fuzz.xml'),
        'junit-functional' => resolveInput(
            $options,
            'junit-functional',
            $root . '/.Build/logs/junit-functional.xml',
            'junit-functional.xml',
        ),
        'clover' => resolveInput($options, 'clover', $root . '/.Build/coverage/clover.xml', 'clover.xml'),
        'infection' => resolveInput($options, 'infection', $root . '/.Build/infection/infection.json', 'infection.json'),
        'infectionSecurity' => resolveInput(
            $options,
            'infection-security',
            $root . '/.Build/infection-security/infection.json',
            'infection-security.json',
        ),
        'infectionSummary' => resolveInput(
            $options,
            'infection-summary',
            $root . '/.Build/infection/summary.log',
            'infection-summary.log',
        ),
        'audit' => resolveInput(
            $options,
            'audit',
            $root . '/.Build/evidence-inputs/composer-audit.json',
            'composer-audit.json',
        ),
        'doctor' => resolveInput($options, 'doctor', $root . '/.Build/evidence-inputs/doctor.json', 'doctor.json'),
    ];

    $minSecurity = isset($options['min-security-coverage']) && is_numeric($options['min-security-coverage'])
        ? (float) $options['min-security-coverage']
        : MIN_SECURITY_COVERAGE;

    ensureDirectory($outputDir);

    $manifest = buildManifest([
        'root' => $root,
        'tag' => $tag,
        'commit' => $commit,
        'builtAt' => resolveBuiltAt($options, $root),
        'repo' => $repo,
        'archivePrefix' => $options['archive-prefix'] ?? 'nr-vault',
        'extensionKey' => $options['extension-key'] ?? 'nr_vault',
        'minSecurityCoverage' => $minSecurity,
        'inputs' => $inputs,
        'bundled' => bundleInputs($inputs, $outputDir),
    ]);

    $json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    writeFileOrFail($outputDir . '/evidence-manifest.json', $json . "\n");
    writeFileOrFail($outputDir . '/EVIDENCE.md', renderMarkdown($manifest));

    $counts = [];
    foreach ($manifest['checks'] as $entry) {
        $counts[$entry['status']] = ($counts[$entry['status']] ?? 0) + 1;
    }
    ksort($counts);
    $summary = [];
    foreach ($counts as $status => $count) {
        $summary[] = "{$count} {$status}";
    }

    echo "Evidence bundle written to {$outputDir}/ (" . implode(', ', $summary) . ").\n";

    return 0;
}

$projectRoot = dirname(__DIR__, 2);

// $argv is only populated when register_argc_argv is on; read it via $_SERVER
// so the script also behaves under an unusual CLI ini.
$rawArguments = $_SERVER['argv'] ?? [];
/** @var list<string> $arguments */
$arguments = [];
if (is_array($rawArguments)) {
    foreach ($rawArguments as $rawArgument) {
        if (is_string($rawArgument)) {
            $arguments[] = $rawArgument;
        }
    }
}

$options = parseArguments($arguments);

if (isset($options['help'])) {
    echo usage() . "\n";
    exit(0);
}

if (isset($options['self-test'])) {
    require __DIR__ . '/collect-evidence-selftest.php';
    exit(selfTest($projectRoot));
}

try {
    exit(run($options, $projectRoot));
} catch (MalformedArtifactException $e) {
    fwrite(STDERR, 'ERROR: ' . $e->getMessage() . "\n");
    fwrite(STDERR, "An artifact was present but could not be interpreted; the bundle would\n");
    fwrite(STDERR, "misrepresent a check that actually ran. Fix or remove the artifact.\n");
    exit(1);
}
