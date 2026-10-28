#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Temporary full-Audit identity and path-coverage oracle; never publishes."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

TARGET = "1bf5c2075a2ba8ed1eff91ce82e87718c448771c"
COUNT = 626
IDENTITIES = "49fd78c2c1503a6ed3ee2b2d5d8a4fb52fb60a427fd00912eec1a7d248f2c0f3"
DEPENDENCIES = "ffbd447cbb5b0f4d3a25755ace47c10f65e161c109bfae0977f5a12d1d59e681"
SOURCE_FILES = "cdbb0855e7a1e676788130dd026c3cfa8f168cfb26b511f17241f3e58151ff01"
NAMESPACE = "{https://xml.phpunit.de/testSuite}"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fingerprint(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


def inventory(path, count=COUNT, digest=IDENTITIES):
    root = ET.parse(path).getroot()
    require(root.tag == NAMESPACE + "testSuite", "Unknown inventory XML schema")
    ids = [node.get("id") for node in root.findall("./" + NAMESPACE + "tests/" +
                                                  NAMESPACE + "testClass/" + NAMESPACE + "testMethod")]
    require(all(isinstance(value, str) and value for value in ids), "Missing inventory identity")
    require(len(ids) == count and len(set(ids)) == count and fingerprint(sorted(ids)) == digest,
            "Complete Audit inventory identity/count changed")
    return set(ids)


def junit(path, expected):
    root = ET.parse(path).getroot()
    require(root.tag == "testsuites", "Unknown JUnit XML schema")
    suites = root.findall("testsuite")
    require(len(suites) == 1, "JUnit root suite is ambiguous")
    suite = suites[0]
    require(int(suite.attrib["tests"]) == len(expected) and
            all(int(suite.attrib[key]) == 0 for key in ("errors", "failures", "skipped")),
            "JUnit has missing cases, errors, failures or skips")
    cases = root.findall(".//testcase")
    ids = []
    for case in cases:
        require(not any(case.find(tag) is not None for tag in ("error", "failure", "skipped")),
                "JUnit contains an unsuccessful case")
        name = case.attrib["name"]
        match = re.fullmatch(r'(.+) with data set "(.*)"', name) or re.fullmatch(r"(.+) with data set #([0-9]+)", name)
        ids.append(case.attrib["class"] + "::" + (match[1] + "#" + match[2] if match else name))
    require(len(ids) == len(expected) and len(set(ids)) == len(expected) and set(ids) == expected,
            "JUnit testcase identities differ from the complete inventory")
    return {"cases": len(ids), "assertions": int(suite.attrib["assertions"]), "skipped": 0}


def dependencies(data, digest=DEPENDENCIES):
    versions = sorted(({"name": row["name"], "version": row["version"]} for row in data["installed"]),
                      key=lambda row: row["name"])
    require(len({row["name"] for row in versions}) == len(versions) and fingerprint(versions) == digest,
            "Dependencies differ from native crash diagnostic")


def coverage(data, expected, source_count=193, source_digest=SOURCE_FILES):
    build = data["build"]
    require(build["runtime"]["version"] == "8.5.12" and
            build["phpCodeCoverage"]["version"] == "14.4.1" and
            build["phpCodeCoverage"]["serializationFormat"] == 4 and
            build["phpCodeCoverage"]["driverInformation"] == {"name": "Xdebug", "version": "3.5.3"},
            "Coverage runtime, driver or format changed")
    files = data["files"]
    require(len(files) == source_count and len(set(files)) == source_count and
            fingerprint(sorted(files)) == source_digest, "Coverage source-file scope changed")
    require(set(data["tests"]) == expected and len(data["tests"]) == len(expected) and
            all(value["status"] == "success" for value in data["tests"].values()),
            "Coverage test identities or success records are incomplete")
    require(all(type(data[key]) is int and data[key] > 0
                for key in ("branches", "paths", "hitBranches", "hitPaths")),
            "Executable branch/path data or hits missing")


COVERAGE_READER = r'''
require '.Build/vendor/autoload.php';
$value = include '.Build/coverage/unit-Audit.cov';
$data = $value['codeCoverage'];
$branches=0; $paths=0; $hitBranches=0; $hitPaths=0;
foreach($data->functionCoverage() as $functions) {
    foreach($functions as $function) {
        $branches += count($function->branches); $paths += count($function->paths);
        foreach($function->branches as $branch) { $hitBranches += (int)($branch->hit !== []); }
        foreach($function->paths as $path) { $hitPaths += (int)($path->hit !== []); }
    }
}
echo json_encode(['files'=>array_keys($data->lineCoverage()), 'tests'=>$value['testResults'],
    'branches'=>$branches, 'paths'=>$paths, 'hitBranches'=>$hitBranches, 'hitPaths'=>$hitPaths,
    'build'=>$value['buildInformation']]);
'''


def main():
    directory = Path(".Build/audit-diagnostic")
    result = {"accepted": False}
    try:
        actual = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True,
                                text=True, timeout=30).stdout.strip()
        require(actual == TARGET, "Actual checkout differs from fixed diagnostic target")
        process = json.loads((directory / "result.json").read_text())
        require(process["returncode"] == 0 and process["signal"] is None and
                process["timed_out"] is False and process["launcher_error"] is None,
                "Audit process did not finish successfully")
        dependencies(json.loads((directory / "dependencies.json").read_text()))
        expected = inventory(directory / "inventory.xml")
        result["junit"] = junit(directory / "junit.xml", expected)
        require(Path(".Build/coverage/unit-Audit.cov").stat().st_size > 0, "Audit coverage part is empty")
        raw = subprocess.run(["php", "-r", COVERAGE_READER], check=True, capture_output=True,
                             text=True, timeout=30)
        measured = json.loads(raw.stdout)
        coverage(measured, expected)
        (directory / "coverage-metrics.json").write_text(json.dumps(measured, indent=2) + "\n")
        result.update(accepted=True, actual_commit=actual, seconds=process["seconds"],
                      branches=measured["branches"], paths=measured["paths"], source_files=len(measured["files"]))
    except (ValueError, KeyError, TypeError, OSError, ET.ParseError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "oracle.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    sys.exit(main())
