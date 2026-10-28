<?php

declare (strict_types=1);
// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: Netresearch DTT GmbH
use SebastianBergmann\CodeCoverage\Data\ProcessedBranchCoverageData;
use SebastianBergmann\CodeCoverage\Data\ProcessedFunctionCoverageData;
use SebastianBergmann\CodeCoverage\Data\ProcessedPathCoverageData;
use SebastianBergmann\CodeCoverage\Serialization\Unserializer;

require '.Build/vendor/autoload.php';

function oracleRequire(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function oracleMap(array $value): object
{
    ksort($value, SORT_STRING);
    return (object) $value;
}

function oracleHits(mixed $hits, array $ids, array $tests): object
{
    oracleRequire(is_array($hits), 'Malformed hit map');
    $result = [];
    foreach ($hits as $index => $count) {
        oracleRequire(
            is_int($index) && isset($ids[$index], $tests[$ids[$index]]) && is_int($count) && $count > 0,
            'Unknown hit index or invalid count'
        );
        $result[$ids[$index]] = $count;
    }
    return oracleMap($result);
}

try {
    oracleRequire(
        $argc === 2 && is_file($argv[1]) && filesize($argv[1]) > 0,
        'Expected one nonempty coverage part'
    );
    oracleRequire(
        PHP_VERSION === '8.5.12' && Composer\InstalledVersions::getPrettyVersion(
            'phpunit/php-code-coverage'
        ) === '14.4.1',
        'Decoder runtime changed'
    );
    $value = new Unserializer()->unserialize($argv[1]);
    $build = $value['buildInformation'];
    oracleRequire(
        $build['timestamp'] !== '' && $build['runtime']['name'] === 'PHP' && $build['runtime']['version'] === '8.5.12' && $build['phpCodeCoverage'] === [
            'version' => '14.4.1',
            'serializationFormat' => 4,
            'driverInformation' => ['name' => 'Xdebug', 'version' => '3.5.3'],
        ],
        'Coverage build changed'
    );
    oracleRequire($value['basePath'] !== '', 'Missing source base path');
    $data = $value['codeCoverage'];
    $ids = $data->testIds();
    $tests = $value['testResults'];
    foreach ($tests as $id => $test) {
        oracleRequire(
            is_string($id) && preg_match(
                '/^Netresearch\\\\NrVault\\\\Tests\\\\Unit\\\\Audit\\\\[A-Za-z_][A-Za-z0-9_\\\\]*::[A-Za-z_][A-Za-z0-9_]*(?:#.*)?$/D',
                $id
            ) === 1 && is_array($test) && isset($test['size'], $test['status'], $test['time']) && is_string($test['size']) && $test['size'] !== '' && $test['status'] === 'success' && (is_float($test['time']) || is_int($test['time'])) && is_finite((float) $test['time']) && $test['time'] >= 0,
            'Malformed or unsuccessful canonical Audit test'
        );
    }
    oracleRequire(
        $tests !== [] && count($ids) === count(array_unique($ids)),
        'Missing tests or ambiguous test indexes'
    );
    foreach ($ids as $index => $id) {
        oracleRequire(
            is_int($index) && $index >= 0 && is_string($id) && isset($tests[$id]),
            'Unknown canonical test index'
        );
    }
    $lines = [];
    foreach ($data->lineCoverage() as $file => $coverage) {
        oracleRequire(
            is_string($file) && preg_match('~^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[^\\\\]+\.php$~D', $file) === 1 && is_array($coverage),
            'Malformed relative source path'
        );
        foreach ($coverage as $line => $hits) {
            oracleRequire(is_int($line) && $line > 0, 'Malformed source line');
            $coverage[$line] = $hits === null ? null : oracleHits($hits, $ids, $tests);
        }
        $lines[$file] = oracleMap($coverage);
    }
    $functions = [];
    $branches = $paths = $hitBranches = $hitPaths = 0;
    foreach ($data->functionCoverage() as $file => $coverage) {
        oracleRequire(
            isset($lines[$file]) && is_array($coverage),
            'Function source outside line scope'
        );
        $fileFunctions = [];
        foreach ($coverage as $name => $function) {
            oracleRequire(
                is_string($name) && $name !== '' && $function instanceof ProcessedFunctionCoverageData,
                'Malformed function'
            );
            $branchData = $pathData = [];
            foreach ($function->branches as $id => $branch) {
                oracleRequire(
                    is_int($id) && $id >= 0 && $branch instanceof ProcessedBranchCoverageData,
                    'Malformed branch'
                );
                foreach (['out', 'out_hit'] as $field) {
                    oracleRequire(
                        array_is_list($branch->{$field}),
                        'Malformed branch edge list'
                    );
                    foreach ($branch->{$field} as $edge) {
                        oracleRequire(
                            is_int($edge) && $edge >= 0,
                            'Malformed branch edge value'
                        );
                    }
                }
                $raw = get_object_vars($branch);
                $raw['hit'] = oracleHits($branch->hit, $ids, $tests);
                $branchData[$id] = oracleMap($raw);
                ++$branches;
                $hitBranches += (int) ($branch->hit !== []);
            }
            foreach ($function->paths as $id => $path) {
                oracleRequire(
                    is_int($id) && $id >= 0 && $path instanceof ProcessedPathCoverageData,
                    'Malformed path'
                );
                oracleRequire(
                    array_is_list($path->path),
                    'Malformed branch path'
                );
                foreach ($path->path as $branchId) {
                    oracleRequire(
                        is_int($branchId) && isset($function->branches[$branchId]),
                        'Unknown branch in path'
                    );
                }
                $raw = get_object_vars($path);
                $raw['hit'] = oracleHits($path->hit, $ids, $tests);
                $pathData[$id] = oracleMap($raw);
                ++$paths;
                $hitPaths += (int) ($path->hit !== []);
            }
            $fileFunctions[$name] = [
                'branches' => oracleMap($branchData),
                'paths' => oracleMap($pathData),
            ];
        }
        $functions[$file] = oracleMap($fileFunctions);
    }
    $files = array_keys($lines);
    sort($files, SORT_STRING);
    echo json_encode(
        [
            'schemaVersion' => 1,
            'part_sha256' => hash_file('sha256', $argv[1]),
            'build' => $build,
            'basePath' => $value['basePath'],
            'files' => $files,
            'tests' => oracleMap($tests),
            'lineCoverage' => oracleMap($lines),
            'functionCoverage' => oracleMap($functions),
            'branches' => $branches,
            'paths' => $paths,
            'hitBranches' => $hitBranches,
            'hitPaths' => $hitPaths,
            'collectsHitCounts' => $data->collectsHitCounts(),
        ],
        JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
    ) . "\n";
} catch (Throwable $error) {
    fwrite(
        STDERR,
        json_encode(
            ['accepted' => false, 'error' => $error->getMessage()],
            JSON_THROW_ON_ERROR
        ) . "\n"
    );
    exit(1);
}
