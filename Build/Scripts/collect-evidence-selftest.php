<?php

/*
 * Copyright (c) 2025-2026 Netresearch DTT GmbH
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

declare(strict_types=1);

/*
 * Fixture-driven self-check for collect-evidence.php.
 *
 * The collector is build-time tooling under Build/ and therefore outside the
 * shipped autoload, so it cannot be covered by the PHPUnit suites in Tests/.
 * This file is `require`d by `collect-evidence.php --self-test` and wired into
 * `composer ci` as `ci:test:evidence`, which keeps the manifest schema and the
 * graceful-degradation contract under CI enforcement anyway.
 *
 * It asserts, against synthetic fixture roots:
 *   - the manifest shape (required keys, check enum, unique ids)
 *   - every producer degrades to status "absent" when its artifact is missing
 *   - every producer reports pass/fail correctly when its artifact is present
 *   - a present-but-malformed artifact raises MalformedArtifactException
 *   - the render mentions every check
 *   - two runs over identical inputs produce byte-identical manifests
 */

/**
 * Accumulator for self-check failures. A typed static holder rather than a
 * global, so PHPStan can see the shape.
 */
final class SelfTestFailures
{
    /** @var list<string> */
    private static array $messages = [];

    public static function add(string $message): void
    {
        self::$messages[] = $message;
    }

    /**
     * @return list<string>
     */
    public static function all(): array
    {
        return self::$messages;
    }
}

function selfTestAssert(bool $condition, string $message): void
{
    if (!$condition) {
        SelfTestFailures::add($message);
    }
}

function selfTestEquals(mixed $expected, mixed $actual, string $message): void
{
    selfTestAssert(
        $expected === $actual,
        $message . ' (expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . ')',
    );
}

function selfTestTempDir(string $suffix): string
{
    $path = sys_get_temp_dir() . '/nr-vault-evidence-' . $suffix . '-' . bin2hex(random_bytes(6));
    ensureDirectory($path);

    return $path;
}

function selfTestRemove(string $path): void
{
    if (!is_dir($path)) {
        if (is_file($path)) {
            unlink($path);
        }

        return;
    }
    $entries = scandir($path);
    foreach ($entries === false ? [] : $entries as $entry) {
        if ($entry === '.') {
            continue;
        }
        if ($entry === '..') {
            continue;
        }
        selfTestRemove($path . '/' . $entry);
    }
    rmdir($path);
}

function selfTestWrite(string $path, string $contents): string
{
    ensureDirectory(dirname($path));
    writeFileOrFail($path, $contents);

    return $path;
}

/**
 * A minimal checkout that the root-reading producers (version, PHPStan level,
 * mutation thresholds, doctor detection) can be pointed at.
 */
function selfTestFixtureRoot(bool $withDoctorCommand): string
{
    $root = selfTestTempDir('root');

    selfTestWrite($root . '/ext_emconf.php', <<<'PHP'
    <?php
    $EM_CONF[$_EXTKEY] = [
        'title' => 'Fixture',
        'version' => '9.9.9',
    ];
    PHP);

    selfTestWrite($root . '/phpstan.neon', "parameters:\n    level: 10\n    paths:\n        - Classes\n");
    selfTestWrite($root . '/infection.json5', "{\n    // comment\n    \"minMsi\": 72,\n    \"minCoveredMsi\": 72\n}\n");
    // The security-scoped ratchet is deliberately stricter than the global one.
    selfTestWrite($root . '/' . SECURITY_MUTATION_CONFIG, "{\n    \"minMsi\": 85,\n    \"minCoveredMsi\": 90\n}\n");
    ensureDirectory($root . '/Classes/Command');
    selfTestWrite($root . '/Classes/Command/VaultListCommand.php', "<?php\n#[AsCommand(name: 'vault:list')]\nclass A {}\n");

    if ($withDoctorCommand) {
        selfTestWrite(
            $root . '/Classes/Command/VaultDoctorCommand.php',
            "<?php\n#[AsCommand(name: 'vault:doctor', description: 'x')]\nclass B {}\n",
        );
    }

    return $root;
}

/**
 * Clover report with known totals: 95/100 statements overall, and each
 * security directory above the 90 % bar.
 */
function selfTestCloverHealthy(string $dir): string
{
    return selfTestWrite($dir . '/clover.xml', <<<'XML'
    <?xml version="1.0" encoding="UTF-8"?>
    <coverage generated="1">
      <project timestamp="1">
        <file name="/src/Classes/Crypto/EncryptionService.php">
          <metrics statements="40" coveredstatements="38" conditionals="10" coveredconditionals="9"/>
        </file>
        <file name="/src/Classes/Security/AccessControlService.php">
          <metrics statements="30" coveredstatements="29" conditionals="6" coveredconditionals="5"/>
        </file>
        <file name="/src/Classes/Audit/AuditLogService.php">
          <metrics statements="20" coveredstatements="19" conditionals="4" coveredconditionals="4"/>
        </file>
        <file name="/src/Classes/Service/VaultService.php">
          <metrics statements="10" coveredstatements="9" conditionals="2" coveredconditionals="1"/>
        </file>
        <metrics statements="100" coveredstatements="95" conditionals="22" coveredconditionals="19"/>
      </project>
    </coverage>
    XML);
}

/**
 * Same shape, but Classes/Crypto sits below the security bar.
 */
function selfTestCloverWeakCrypto(string $dir): string
{
    return selfTestWrite($dir . '/clover.xml', <<<'XML'
    <?xml version="1.0" encoding="UTF-8"?>
    <coverage generated="1">
      <project timestamp="1">
        <file name="/src/Classes/Crypto/EncryptionService.php">
          <metrics statements="40" coveredstatements="20" conditionals="10" coveredconditionals="4"/>
        </file>
        <metrics statements="100" coveredstatements="40" conditionals="22" coveredconditionals="8"/>
      </project>
    </coverage>
    XML);
}

/**
 * @param array<string, string|null> $inputs
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
function selfTestManifest(string $root, array $inputs, ?string $tag = 'v9.9.9', ?string $outputDir = null): array
{
    return buildManifest([
        'root' => $root,
        'tag' => $tag,
        'commit' => 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
        'builtAt' => '2026-07-31T12:00:00+00:00',
        'repo' => 'netresearch/t3x-nr-vault',
        'archivePrefix' => 'nr-vault',
        'extensionKey' => 'nr_vault',
        'minSecurityCoverage' => MIN_SECURITY_COVERAGE,
        'inputs' => $inputs,
        'bundled' => $outputDir === null ? [] : bundleInputs($inputs, $outputDir),
    ]);
}

/**
 * @param list<array{id: string, status: string, summary: string, source: string}> $checks
 *
 * @return array<string, array{id: string, status: string, summary: string, source: string}>
 */
function selfTestById(array $checks): array
{
    $byId = [];
    foreach ($checks as $entry) {
        $byId[$entry['id']] = $entry;
    }

    return $byId;
}

/**
 * @return list<string>
 */
function selfTestExpectedCheckIds(): array
{
    return [
        'release-identity',
        'tests',
        'coverage-line',
        'coverage-security-dirs',
        'mutation-msi',
        'mutation-msi-security',
        'static-analysis',
        'dependency-audit',
        'vault-doctor',
    ];
}

function selfTest(string $projectRoot): int
{
    /** @var list<string> $temporary */
    $temporary = [];

    try {
        // --- 1. Every optional producer absent -----------------------------
        $bareRoot = selfTestFixtureRoot(false);
        $temporary[] = $bareRoot;
        $emptyInputs = [
            'junit-unit' => null, 'junit-fuzz' => null, 'junit-functional' => null,
            'clover' => null, 'infection' => null, 'infectionSecurity' => null,
            'infectionSummary' => null, 'audit' => null, 'doctor' => null,
        ];
        $absent = selfTestManifest($bareRoot, $emptyInputs);

        foreach (['schemaVersion', 'extension', 'version', 'commit', 'builtAt', 'checks', 'artifacts'] as $key) {
            selfTestAssert(array_key_exists($key, $absent), "manifest is missing required key `{$key}`");
        }
        selfTestEquals(SCHEMA_VERSION, $absent['schemaVersion'], 'schemaVersion');
        selfTestEquals('nr_vault', $absent['extension'], 'extension key');
        selfTestEquals('9.9.9', $absent['version'], 'version parsed from ext_emconf.php');

        $ids = array_column($absent['checks'], 'id');
        selfTestEquals(selfTestExpectedCheckIds(), $ids, 'check ids and their order');
        selfTestEquals(count($ids), count(array_unique($ids)), 'check ids are unique');

        foreach ($absent['checks'] as $entry) {
            selfTestAssert(
                in_array($entry['status'], ['pass', 'warn', 'fail', 'absent'], true),
                "check `{$entry['id']}` has status outside the enum: {$entry['status']}",
            );
            selfTestAssert($entry['summary'] !== '', "check `{$entry['id']}` has an empty summary");
            selfTestAssert($entry['source'] !== '', "check `{$entry['id']}` has an empty source");
        }

        $byId = selfTestById($absent['checks']);
        foreach (['tests', 'coverage-line', 'coverage-security-dirs', 'mutation-msi', 'mutation-msi-security', 'dependency-audit'] as $id) {
            selfTestEquals('absent', $byId[$id]['status'], "`{$id}` degrades to absent without its artifact");
        }
        selfTestEquals(
            'absent',
            $byId['vault-doctor']['status'],
            'vault-doctor is absent when the command is not in this version',
        );
        selfTestAssert(
            str_contains($byId['vault-doctor']['summary'], 'not available in this version'),
            'the absent doctor check says why it is absent',
        );
        selfTestEquals(
            'infection-security.json',
            $byId['mutation-msi-security']['source'],
            'an absent security-scoped mutation check names its own report, not the global one',
        );
        selfTestEquals(
            'infection.json',
            $byId['mutation-msi']['source'],
            'an absent whole-codebase mutation check names the global report',
        );
        selfTestEquals('pass', $byId['static-analysis']['status'], 'static-analysis reads the level from phpstan.neon');
        selfTestEquals('pass', $byId['release-identity']['status'], 'release-identity accepts a matching tag');

        // Release-asset pointers are present even with no local artifacts.
        selfTestAssert($absent['artifacts'] !== [], 'release asset pointers are always referenced');
        foreach ($absent['artifacts'] as $artifact) {
            selfTestAssert(
                isset($artifact['url']) && str_starts_with($artifact['url'], 'https://'),
                'referenced artifacts carry an https URL',
            );
        }
        $assetNames = array_column($absent['artifacts'], 'name');
        foreach (['nr-vault-9.9.9.zip', 'nr-vault-9.9.9.sbom.spdx.json', 'checksums.txt'] as $expected) {
            selfTestAssert(in_array($expected, $assetNames, true), "release asset `{$expected}` is referenced");
        }

        // --- 2. Every producer present and healthy -------------------------
        $doctorRoot = selfTestFixtureRoot(true);
        $temporary[] = $doctorRoot;
        $fixtures = selfTestTempDir('inputs');
        $temporary[] = $fixtures;

        $healthy = [
            'junit-unit' => selfTestWrite(
                $fixtures . '/junit-unit.xml',
                '<?xml version="1.0"?><testsuites tests="120" assertions="400" errors="0" failures="0" skipped="2"/>',
            ),
            'junit-fuzz' => selfTestWrite(
                $fixtures . '/junit-fuzz.xml',
                '<?xml version="1.0"?><testsuites tests="30" errors="0" failures="0" skipped="0"/>',
            ),
            'junit-functional' => selfTestWrite(
                $fixtures . '/junit-functional.xml',
                '<?xml version="1.0"?><testsuites tests="45" errors="0" failures="0" skipped="0"/>',
            ),
            'clover' => selfTestCloverHealthy($fixtures),
            'infection' => selfTestWrite(
                $fixtures . '/infection.json',
                '{"stats":{"msi":80.5,"coveredCodeMsi":85.25,"totalMutantsCount":900}}',
            ),
            'infectionSecurity' => selfTestWrite(
                $fixtures . '/infection-security.json',
                '{"stats":{"msi":91.5,"coveredCodeMsi":94.25,"totalMutantsCount":210}}',
            ),
            'infectionSummary' => selfTestWrite($fixtures . '/summary.log', "Mutation Score Indicator (MSI): 80%\n"),
            'audit' => selfTestWrite($fixtures . '/composer-audit.json', '{"advisories":{},"abandoned":{}}'),
            'doctor' => selfTestWrite($fixtures . '/doctor.json', '{"status":"ok","checks":[1,2,3,4]}'),
        ];

        $output = selfTestTempDir('bundle');
        $temporary[] = $output;
        $good = selfTestManifest($doctorRoot, $healthy, 'v9.9.9', $output);
        $goodById = selfTestById($good['checks']);

        foreach (selfTestExpectedCheckIds() as $id) {
            selfTestEquals('pass', $goodById[$id]['status'], "`{$id}` passes with a healthy artifact");
        }
        selfTestAssert(
            str_contains($goodById['coverage-line']['summary'], '95.00%'),
            'overall line coverage is computed from the clover project metrics',
        );
        selfTestAssert(
            str_contains($goodById['coverage-security-dirs']['summary'], 'Classes/Crypto 95.00%'),
            'per-directory coverage is aggregated from the clover file metrics',
        );
        selfTestAssert(
            str_contains($goodById['mutation-msi']['summary'], '80.50%')
                && str_contains($goodById['mutation-msi']['summary'], '72.00%'),
            'mutation check reports MSI against the infection.json5 threshold',
        );
        selfTestAssert(
            str_contains($goodById['mutation-msi-security']['summary'], '91.50%')
                && str_contains($goodById['mutation-msi-security']['summary'], '85.00%'),
            'security-scoped mutation reports MSI against the stricter security ratchet',
        );
        selfTestAssert(
            str_contains($goodById['mutation-msi-security']['summary'], 'Classes/Crypto'),
            'the security-scoped mutation check names the directories it covers',
        );
        selfTestAssert(
            str_contains($goodById['vault-doctor']['summary'], '4 probes'),
            'doctor check counts the probes it found',
        );

        // All three suites are aggregated, with per-suite counts preserved.
        foreach (['unit 120', 'fuzz 30', 'functional 45'] as $fragment) {
            selfTestAssert(
                str_contains($goodById['tests']['summary'], $fragment),
                "the tests check reports `{$fragment}`",
            );
        }
        selfTestAssert(
            str_contains($goodById['tests']['summary'], '195 tests across 3 suite(s)'),
            'the tests check totals every suite it found',
        );

        // Every present input is copied into the bundle and hashed.
        $bundled = array_values(array_filter(
            $good['artifacts'],
            static fn (array $a): bool => isset($a['path']),
        ));
        selfTestEquals(count($healthy), count($bundled), 'every present input is bundled');
        foreach ($bundled as $artifact) {
            selfTestAssert(
                isset($artifact['sha256']) && preg_match('/^[0-9a-f]{64}$/', $artifact['sha256']) === 1,
                'bundled artifact `' . $artifact['name'] . '` carries a SHA-256',
            );
            selfTestAssert(
                is_file($output . '/' . $artifact['path']),
                'bundled artifact `' . $artifact['name'] . '` exists on disk',
            );
        }

        // --- 3. Present artifacts that report problems ---------------------
        $bad = selfTestTempDir('failing');
        $temporary[] = $bad;
        $failing = [
            // Only the fuzz suite broke: the aggregate must still fail, and the
            // healthy unit suite must not mask it.
            'junit-unit' => selfTestWrite(
                $bad . '/junit-unit.xml',
                '<?xml version="1.0"?><testsuites tests="120" errors="0" failures="0" skipped="0"/>',
            ),
            'junit-fuzz' => selfTestWrite(
                $bad . '/junit-fuzz.xml',
                '<?xml version="1.0"?><testsuites tests="30" errors="1" failures="2" skipped="0"/>',
            ),
            'junit-functional' => null,
            'clover' => selfTestCloverWeakCrypto($bad),
            'infection' => selfTestWrite($bad . '/infection.json', '{"stats":{"msi":50.0,"coveredCodeMsi":55.0}}'),
            'infectionSecurity' => selfTestWrite(
                $bad . '/infection-security.json',
                '{"stats":{"msi":60.0,"coveredCodeMsi":65.0}}',
            ),
            'infectionSummary' => null,
            'audit' => selfTestWrite(
                $bad . '/composer-audit.json',
                '{"advisories":{"acme/lib":[{"advisoryId":"PKSA-1"}]},"abandoned":{}}',
            ),
            'doctor' => selfTestWrite($bad . '/doctor.json', '{"status":"critical","checks":[1]}'),
        ];
        $failed = selfTestById(selfTestManifest($doctorRoot, $failing)['checks']);
        foreach (['tests', 'coverage-line', 'coverage-security-dirs', 'mutation-msi', 'mutation-msi-security', 'dependency-audit', 'vault-doctor'] as $id) {
            selfTestEquals('fail', $failed[$id]['status'], "`{$id}` fails when its artifact reports a problem");
        }
        selfTestAssert(
            str_contains($failed['tests']['summary'], 'fuzz 30 (2 failures, 1 errors)'),
            'the aggregate tests check names the suite that broke',
        );
        selfTestAssert(
            !str_contains($failed['tests']['summary'], 'functional'),
            'a suite that did not run is not listed as passing',
        );

        // A tag that disagrees with ext_emconf.php is a release-blocking mismatch.
        $mismatch = selfTestById(selfTestManifest($bareRoot, $emptyInputs, 'v1.2.3')['checks']);
        selfTestEquals('fail', $mismatch['release-identity']['status'], 'tag/version mismatch fails');

        // An untagged (local) run is a warning, not a failure.
        $untagged = selfTestById(selfTestManifest($bareRoot, $emptyInputs, null)['checks']);
        selfTestEquals('warn', $untagged['release-identity']['status'], 'an untagged build warns');

        // A doctor build with the command but no report warns rather than lying.
        $noReport = selfTestById(selfTestManifest($doctorRoot, $emptyInputs)['checks']);
        selfTestEquals(
            'warn',
            $noReport['vault-doctor']['status'],
            'doctor available but not run is a warning, not absent',
        );

        // The inverse contradiction: a report for a command this version does
        // not ship must be reported as ignored, never silently accepted.
        $foreignInputs = $emptyInputs;
        $foreignInputs['doctor'] = $healthy['doctor'];
        $foreign = selfTestById(selfTestManifest($bareRoot, $foreignInputs)['checks']);
        selfTestEquals(
            'warn',
            $foreign['vault-doctor']['status'],
            'a doctor report without the command in this version warns rather than being dropped',
        );
        selfTestAssert(
            str_contains($foreign['vault-doctor']['summary'], 'stale or foreign'),
            'the ignored-report warning says why it was ignored',
        );

        // --- 4. Present but malformed is an error --------------------------
        $malformed = selfTestTempDir('malformed');
        $temporary[] = $malformed;

        $cases = [
            'audit' => selfTestWrite($malformed . '/composer-audit.json', '{"advisories": '),
            'clover' => selfTestWrite($malformed . '/clover.xml', '<coverage><project></project>'),
            'infection' => selfTestWrite($malformed . '/infection.json', '{"stats":{}}'),
            'junit-unit' => selfTestWrite($malformed . '/junit-unit.xml', '<?xml version="1.0"?><testsuites/>'),
            'infectionSecurity' => selfTestWrite($malformed . '/infection-security.json', '{"stats":{}}'),
        ];
        foreach ($cases as $key => $path) {
            $inputs = $emptyInputs;
            $inputs[$key] = $path;
            $threw = false;

            try {
                selfTestManifest($doctorRoot, $inputs);
            } catch (MalformedArtifactException) {
                $threw = true;
            }
            selfTestAssert($threw, "a malformed `{$key}` artifact raises MalformedArtifactException");
        }

        // --- 4b. The --parts drop-zone resolves CI-produced reports ---------
        // The producing jobs run on separate runners and merge their uploads
        // into one flat directory; --parts must find them there.
        $parts = selfTestTempDir('parts');
        $temporary[] = $parts;
        foreach (
            [
                'junit-unit.xml' => '<?xml version="1.0"?><testsuites tests="7" errors="0" failures="0"/>',
                'junit-functional.xml' => '<?xml version="1.0"?><testsuites tests="3" errors="0" failures="0"/>',
                'composer-audit.json' => '{"advisories":{},"abandoned":{}}',
                'doctor.json' => '{"status":"ok","checks":[1]}',
            ] as $name => $body
        ) {
            selfTestWrite($parts . '/' . $name, $body);
        }

        $partsOptions = ['parts' => $parts];
        selfTestEquals(
            $parts . '/junit-unit.xml',
            resolveInput($partsOptions, 'junit-unit', '/nonexistent/junit.xml', 'junit-unit.xml'),
            '--parts resolves the unit JUnit log',
        );
        selfTestEquals(
            $parts . '/doctor.json',
            resolveInput($partsOptions, 'doctor', '/nonexistent/doctor.json', 'doctor.json'),
            '--parts resolves the doctor report',
        );
        selfTestEquals(
            null,
            resolveInput($partsOptions, 'junit-fuzz', '/nonexistent/junit-fuzz.xml', 'junit-fuzz.xml'),
            'a report absent from --parts stays absent rather than erroring',
        );
        // An explicit flag still outranks the drop-zone.
        $override = selfTestWrite($parts . '/elsewhere.xml', '<?xml version="1.0"?><testsuites tests="1"/>');
        selfTestEquals(
            $override,
            resolveInput(['parts' => $parts, 'junit-unit' => $override], 'junit-unit', '/nonexistent', 'junit-unit.xml'),
            'an explicit --junit-unit outranks the --parts drop-zone',
        );

        // --- 5. Render mentions every check --------------------------------
        $markdown = renderMarkdown($good);
        foreach (selfTestExpectedCheckIds() as $id) {
            selfTestAssert(str_contains($markdown, '`' . $id . '`'), "EVIDENCE.md lists check `{$id}`");
        }
        selfTestAssert(str_contains($markdown, 'PASS'), 'EVIDENCE.md renders status labels');
        selfTestAssert(str_contains($markdown, '9.9.9'), 'EVIDENCE.md carries the version');
        selfTestAssert(
            str_contains($markdown, 'gh attestation verify'),
            'EVIDENCE.md tells an auditor how to verify provenance',
        );
        $absentMarkdown = renderMarkdown($absent);
        selfTestAssert(str_contains($absentMarkdown, 'ABSENT'), 'EVIDENCE.md renders ABSENT for missing producers');
        selfTestAssert(
            str_contains($absentMarkdown, 'No input artifacts were present'),
            'EVIDENCE.md says so when nothing was bundled',
        );

        // --- 6. Reproducibility --------------------------------------------
        $first = json_encode(selfTestManifest($doctorRoot, $healthy), JSON_THROW_ON_ERROR);
        $second = json_encode(selfTestManifest($doctorRoot, $healthy), JSON_THROW_ON_ERROR);
        selfTestEquals($first, $second, 'identical inputs produce an identical manifest');

        // --- 7. The real checkout is readable ------------------------------
        selfTestAssert(
            readExtensionVersion($projectRoot) !== null,
            'the real ext_emconf.php exposes a parseable version',
        );
        selfTestEquals(
            'pass',
            selfTestById([checkStaticAnalysis($projectRoot)])['static-analysis']['status'],
            'the real phpstan.neon level clears the bar',
        );
    } finally {
        foreach ($temporary as $path) {
            selfTestRemove($path);
        }
    }

    $failures = SelfTestFailures::all();
    if ($failures !== []) {
        fwrite(STDERR, 'FAIL: ' . count($failures) . " evidence self-check(s) failed:\n");
        foreach ($failures as $failure) {
            fwrite(STDERR, '  - ' . $failure . "\n");
        }

        return 1;
    }

    echo "OK: evidence collector self-checks passed (manifest schema, graceful degradation, malformed-artifact handling, render, reproducibility).\n";

    return 0;
}
