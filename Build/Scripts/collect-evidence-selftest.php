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
            // nosemgrep: php.lang.security.unlink-use.unlink-use - self-test-owned temp fixture path built by this script, never user input.
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
 * A `vault:doctor` payload whose `summary` block is internally consistent with
 * its `findings` list, because the real report carries one finding per evaluated
 * control — passing ones included — and `totalControls()` is `count($findings)`.
 *
 * A crashed check does NOT add a finding: `VaultDoctorService::runContained()`
 * returns a single-element list on catch, so it REPLACES the N controls that
 * check would have emitted. The evaluated total therefore drops, which is why a
 * fixture that keeps the healthy total while adding crash findings is impossible.
 *
 * @param list<array<string, mixed>> $problems non-pass findings
 *
 * @return array<string, mixed>
 */
function selfTestDoctorPayload(int $passCount, array $problems, string $profile = 'hardened'): array
{
    $findings = [];
    for ($i = 0; $i < $passCount; ++$i) {
        $findings[] = ['id' => 'control.pass_' . $i, 'severity' => 'pass', 'details' => []];
    }
    foreach ($problems as $problem) {
        $findings[] = $problem;
    }

    $bySeverity = ['pass' => $passCount, 'warning' => 0, 'critical' => 0];
    foreach ($problems as $problem) {
        $severity = is_string($problem['severity'] ?? null) ? $problem['severity'] : 'pass';
        $bySeverity[$severity] = ($bySeverity[$severity] ?? 0) + 1;
    }

    $highest = $bySeverity['critical'] > 0 ? 'critical' : ($bySeverity['warning'] > 0 ? 'warning' : 'pass');
    $exit = ['pass' => 0, 'warning' => 1, 'critical' => 2][$highest];

    return [
        'profile' => $profile,
        'configuredProfile' => $profile,
        'profileOverridden' => false,
        'auditReady' => $highest === 'pass',
        'highestSeverity' => $highest,
        'exitCode' => $exit,
        'summary' => [
            'total' => count($findings),
            'pass' => $bySeverity['pass'],
            'warning' => $bySeverity['warning'],
            'critical' => $bySeverity['critical'],
        ],
        'findings' => $findings,
    ];
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
            // Real DoctorReport::toArray() shape, verified against
            // feature/vault-doctor: highestSeverity + exitCode, no `status` key.
            // 22 controls is the healthy total for the functional deployment
            // shape (file provider, CLI access off, standard profile).
            'doctor' => selfTestWrite(
                $fixtures . '/doctor.json',
                json_encode(selfTestDoctorPayload(22, []), JSON_THROW_ON_ERROR),
            ),
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
            str_contains($goodById['vault-doctor']['summary'], '22 controls'),
            'doctor check counts the controls from summary.total',
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
            'doctor' => selfTestWrite(
                $bad . '/doctor.json',
                json_encode(selfTestDoctorPayload(19, [
                    ['id' => 'environment.backend_lock_ssl', 'severity' => 'warning', 'details' => []],
                    ['id' => 'profile.admin_override', 'severity' => 'critical', 'details' => []],
                    ['id' => 'provider.key_permissions', 'severity' => 'critical', 'details' => []],
                ], 'standard'), JSON_THROW_ON_ERROR),
            ),
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

        // --- 3b. The real vault:doctor JSON shapes -------------------------
        // Contract verified against DoctorReport::toArray() and the command's
        // renderCrash()/renderInvalidProfile() paths on feature/vault-doctor.
        $doctorFixtures = selfTestTempDir('doctor');
        $temporary[] = $doctorFixtures;

        $doctorCase = static function (string $name, string $json) use ($doctorRoot, $emptyInputs, $doctorFixtures): array {
            $inputs = $emptyInputs;
            $inputs['doctor'] = selfTestWrite($doctorFixtures . '/' . $name . '.json', $json);

            return selfTestById(selfTestManifest($doctorRoot, $inputs)['checks'])['vault-doctor'];
        };

        // A crash or an unusable --profile emits {"error":…,"exitCode":…} with no
        // severity. It must fail, never pass: the check never actually ran.
        $crashed = $doctorCase('crash', '{"error":"Something exploded","exitCode":2}');
        selfTestEquals('fail', $crashed['status'], 'a crashed doctor run fails rather than passing');
        selfTestAssert(
            str_contains($crashed['summary'], 'did not complete'),
            'the crashed-doctor summary says the run did not complete',
        );
        $invalidProfile = $doctorCase('invalid', '{"error":"Unknown profile \\"nope\\"","exitCode":1}');
        selfTestEquals('fail', $invalidProfile['status'], 'an unusable --profile value fails');

        // Severity drives the status; worst-wins is the command's own concern.
        selfTestEquals(
            'warn',
            $doctorCase('warning', '{"highestSeverity":"warning","exitCode":1}')['status'],
            'highestSeverity=warning maps to warn',
        );
        selfTestEquals(
            'fail',
            $doctorCase('critical', '{"highestSeverity":"critical","exitCode":2}')['status'],
            'highestSeverity=critical maps to fail',
        );

        // exitCode alone is enough if the severity key is ever dropped.
        selfTestEquals(
            'pass',
            $doctorCase('exitonly', '{"exitCode":0}')['status'],
            'exitCode alone is a usable fallback',
        );

        // An override is recorded, so evidence cannot imply the live profile.
        $overridden = $doctorCase(
            'override',
            '{"profile":"hardened","configuredProfile":"standard","profileOverridden":true,'
                . '"highestSeverity":"warning","exitCode":1,'
                . '"summary":{"total":24,"pass":18,"warning":6,"critical":0},"findings":[]}',
        );
        selfTestAssert(
            str_contains($overridden['summary'], 'profile hardened')
                && str_contains($overridden['summary'], 'configured: standard'),
            'a --profile override records both the evaluated and configured profile',
        );
        selfTestAssert(
            str_contains($overridden['summary'], '0 critical, 6 warning'),
            'the doctor summary carries the finding counts',
        );

        // A shape carrying none of the three signals is inconclusive, not clean.
        selfTestEquals(
            'warn',
            $doctorCase('unknown', '{"profile":"hardened"}')['status'],
            'an unrecognised doctor shape warns rather than passing',
        );

        // check.crashed is a CRITICAL finding raised by per-check containment
        // (e.g. an unreachable database), so exit 2 with crashes is
        // indistinguishable from bad posture unless the ids are read.
        // Realistic arithmetic: 22 healthy controls, minus audit's 6 and
        // secret_hygiene's 3, plus one check.crashed each = 15 evaluated. Plus a
        // typical standard-profile warning so the warn path is exercised.
        $crashOnly = $doctorCase('crashonly', json_encode(selfTestDoctorPayload(12, [
            ['id' => 'environment.backend_lock_ssl', 'severity' => 'warning', 'details' => []],
            ['id' => 'check.crashed', 'severity' => 'critical', 'details' => ['check' => 'audit']],
            ['id' => 'check.crashed', 'severity' => 'critical', 'details' => ['check' => 'secret_hygiene']],
        ]), JSON_THROW_ON_ERROR));
        selfTestAssert(
            str_contains($crashOnly['summary'], '15 controls'),
            'the evaluated control total drops when checks crash, and the bundle reports the drop',
        );
        selfTestEquals(
            'warn',
            $crashOnly['status'],
            'criticals that are only crashed checks mean incomplete evidence, not bad posture',
        );
        selfTestAssert(
            str_contains($crashOnly['summary'], 'INCOMPLETE')
                && str_contains($crashOnly['summary'], 'audit')
                && str_contains($crashOnly['summary'], 'secret_hygiene'),
            'the incomplete-evidence summary names the checks that could not run',
        );
        selfTestAssert(
            str_contains($crashOnly['summary'], 'unevaluated, not satisfied'),
            'the incomplete-evidence summary refuses to imply the controls passed',
        );

        // A real critical alongside a crash must still FAIL — the crash must
        // never mask an actual control failure.
        $crashPlusReal = $doctorCase('crashplusreal', json_encode(selfTestDoctorPayload(14, [
            ['id' => 'check.crashed', 'severity' => 'critical', 'details' => ['check' => 'audit']],
            ['id' => 'profile.admin_override', 'severity' => 'critical', 'details' => []],
        ]), JSON_THROW_ON_ERROR));
        selfTestEquals(
            'fail',
            $crashPlusReal['status'],
            'a real critical alongside a crashed check still fails',
        );
        selfTestAssert(
            str_contains($crashPlusReal['summary'], 'INCOMPLETE'),
            'the crash is still disclosed even when a real critical dominates the status',
        );

        // A crash next to warnings is disclosed without inventing a failure.
        // A crashed check is itself critical, so highestSeverity is critical even
        // when every *real* problem is only a warning. The status must still land
        // on warn — incomplete evidence, not a failed control.
        $crashWithWarnings = $doctorCase('crashwarn', json_encode(selfTestDoctorPayload(15, [
            ['id' => 'cli.access', 'severity' => 'warning', 'details' => []],
            ['id' => 'check.crashed', 'severity' => 'critical', 'details' => ['check' => 'audit']],
        ]), JSON_THROW_ON_ERROR));
        selfTestEquals('warn', $crashWithWarnings['status'], 'a crash alongside warnings stays a warning');
        selfTestAssert(
            str_contains($crashWithWarnings['summary'], 'INCOMPLETE'),
            'a crash is disclosed even when severity is only warning',
        );

        // A clean run must not gain a spurious incompleteness note.
        selfTestAssert(
            !str_contains($goodById['vault-doctor']['summary'], 'INCOMPLETE'),
            'a healthy doctor run carries no incomplete-evidence note',
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
                'doctor.json' => '{"highestSeverity":"pass","exitCode":0}',
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

        // --- 4c. An empty artifact is an absent producer, not a corrupt one --
        // A shell redirect creates the file before the command runs, so a
        // producer that crashes at startup leaves a zero-byte file. Aborting the
        // bundle over that would discard every other piece of evidence.
        $emptyDir = selfTestTempDir('empty');
        $temporary[] = $emptyDir;
        $emptyNames = [
            'junit-unit.xml', 'junit-fuzz.xml', 'junit-functional.xml', 'clover.xml',
            'infection.json', 'infection-security.json', 'composer-audit.json', 'doctor.json',
        ];
        foreach ($emptyNames as $name) {
            selfTestWrite($emptyDir . '/' . $name, '');
        }
        selfTestWrite($emptyDir . '/whitespace.json', "\n  \n");

        foreach (
            [
                'junit-unit' => 'junit-unit.xml',
                'clover' => 'clover.xml',
                'infection' => 'infection.json',
                'infection-security' => 'infection-security.json',
                'audit' => 'composer-audit.json',
                'doctor' => 'doctor.json',
            ] as $option => $name
        ) {
            selfTestEquals(
                null,
                resolveInput(['parts' => $emptyDir], $option, '/nonexistent', $name),
                "an empty `{$name}` in --parts resolves to absent, not malformed",
            );
        }
        selfTestEquals(
            null,
            resolveInput(['doctor' => $emptyDir . '/whitespace.json'], 'doctor', '/nonexistent', 'doctor.json'),
            'a whitespace-only artifact resolves to absent',
        );

        // The whole bundle must still be produced, with the dead producer absent.
        $emptyBundle = selfTestTempDir('emptybundle');
        $temporary[] = $emptyBundle;
        $survivingInputs = $emptyInputs;
        $survivingInputs['clover'] = $healthy['clover'];
        $survivingInputs['doctor'] = resolveInput(['parts' => $emptyDir], 'doctor', '/nonexistent', 'doctor.json');
        $survived = selfTestById(selfTestManifest($doctorRoot, $survivingInputs, 'v9.9.9', $emptyBundle)['checks']);
        selfTestEquals(
            'pass',
            $survived['coverage-line']['status'],
            'evidence from healthy producers survives a producer that wrote nothing',
        );
        selfTestEquals(
            'warn',
            $survived['vault-doctor']['status'],
            'a doctor that wrote nothing is recorded as unrun, not as a corrupt artifact',
        );

        // A truncated but NON-empty artifact is still malformed — the producer
        // did write something, so ignoring it would misreport a check that ran.
        $truncated = selfTestWrite($emptyDir . '/truncated.json', '{"stats":');
        $threwTruncated = false;

        try {
            $truncatedInputs = $emptyInputs;
            $truncatedInputs['infection'] = $truncated;
            selfTestManifest($doctorRoot, $truncatedInputs);
        } catch (MalformedArtifactException) {
            $threwTruncated = true;
        }
        selfTestAssert($threwTruncated, 'a truncated non-empty artifact is still an error');

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
