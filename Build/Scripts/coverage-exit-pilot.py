#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Temporary paired qualification of immutable coverage-worker containment."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import unittest
import xml.etree.ElementTree as ET

TARGET = "0b99a1dd50c653f4cc31c5ed120419ce7a5d8ebe"
OLD = "a068171b9efd00208914e78369b7086c059fa628"
HASHES = {"old": "b58deec47200b82957e1055d28ebd9d3ad52e799f39c6d5bd6befd50a4485d42",
          "new": "e67025b646ae0dc6f603c6c755625a2de9b7a283bd5d594a2b866bdb235900de"}
OLD_WORKFLOW = "52869585dcd4820c8a32d0b9bf2c2ccb2b1915e2b04812c2a685068a4d80dea0"
NEW_WORKFLOW = "3e94410c9e9fac217ad961e9e21ecbc66f64701ad1a0fec35a1a7dbb87e5bcd1"
COUNT = 660
IDENTITIES = "df2eda2a9f40c2e262c7eec15d631429fb03ef620a60ea72d96be9fd692c1ab0"
SOURCE_COUNT = 194
SOURCE_FILES = "bff87fc19e3dad5f7edd6a0811e3e8daae9f22f76289ea8a9d4ed1dca0a3a31e"
SEED = 1793178338
POLICY = "coverage-exit-paired-v1"
BASE = Path(".Build/coverage-exit-pilot")
CACHE = Path(".phpunit.cache")
TOOLS = Path(__file__).resolve().parent
RECEIPT_FILES = {"unit-Audit.cov", "junit.xml", "events.txt", "coverage.json", "command.json", "stdout.log", "containment.json"}
HELPER_TIMEOUT_SECONDS = 1840
GROUP_CLEANUP_SECONDS = 5
NAMESPACE = "{https://xml.phpunit.de/testSuite}"
RUNTIME = r'''
$extensions=get_loaded_extensions(); sort($extensions);
$ini=[]; foreach(array_filter(array_merge([php_ini_loaded_file()],explode(',',php_ini_scanned_files() ?: ''))) as $file) {
    $file=trim($file); if($file!=='') {$ini[$file]=hash_file('sha256',$file);}
} ksort($ini);
echo json_encode(['php'=>PHP_VERSION,'xdebug'=>phpversion('xdebug'),'binary'=>PHP_BINARY,
    'binary_sha256'=>hash_file('sha256',PHP_BINARY),'extensions'=>$extensions,'ini'=>$ini,
    'coverage_mode'=>getenv('XDEBUG_MODE') ?: ini_get('xdebug.mode')]);
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def fingerprint(value):
    return digest((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def checked(command, timeout=30):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout).stdout


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def helper(phase):
    require(phase in HASHES, "Unknown worker phase")
    path = BASE / "helpers" / phase / "release-coverage.py"
    require(digest(path.read_bytes()) == HASHES[phase], "Immutable worker bytes changed")
    return path


def package_records(packages):
    require(isinstance(packages, list) and packages, "Package metadata is missing")
    records = []
    for package in packages:
        require(isinstance(package.get("name"), str) and package["name"] and
                isinstance(package.get("version"), str) and package["version"], "Package identity missing")
        record = {key: package.get(key) for key in ("name", "version", "type", "source", "dist")}
        require(record["type"] == "metapackage" or any(isinstance(record[key], dict) and
                isinstance(record[key].get("reference"), str) and record[key]["reference"]
                for key in ("source", "dist")), "Package source reference missing")
        records.append(record)
    require(len({row["name"] for row in records}) == len(records), "Duplicate package identity")
    return sorted(records, key=lambda row: row["name"])


def snapshot(label):
    require(checked(["git", "rev-parse", "HEAD"]).strip() == TARGET, "Wrong immutable application checkout")
    require(subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], check=False).returncode == 0,
            "Tracked application source changed")
    source = {}
    for name in checked(["git", "ls-files", "-z"]).rstrip("\0").split("\0"):
        path = Path(name)
        source[name] = digest(b"link\0" + os.fsencode(path.readlink()) if path.is_symlink() else path.read_bytes())
    runtime = json.loads(checked(["php", "-r", RUNTIME]))
    require(runtime["php"] == "8.5.12" and runtime["xdebug"] == "3.5.3" and
            "coverage" in runtime["coverage_mode"].split(","), "Actual PHP/Xdebug coverage runtime changed")
    directory = BASE / "snapshots" / label
    directory.mkdir(parents=True, exist_ok=True)
    lock_bytes = Path("composer.lock").read_bytes()
    installed_bytes = Path(".Build/vendor/composer/installed.json").read_bytes()
    lock, installed = json.loads(lock_bytes), json.loads(installed_bytes)
    records = package_records(installed["packages"])
    require(records == package_records(lock["packages"] + lock.get("packages-dev", [])),
            "Installed full package versions/references differ from lock")
    versions = {row["name"]: row["version"] for row in records}
    require(versions.get("phpunit/phpunit") == "13.4.5" and
            versions.get("phpunit/php-code-coverage") == "14.4.1", "Required test tools changed")
    for phase in HASHES:
        helper(phase)
    require(digest(Path("Build/Scripts/release-coverage.py").read_bytes()) == HASHES["new"] and
            digest(Path(".github/workflows/release-evidence.yml").read_bytes()) == NEW_WORKFLOW,
            "Application worker/staging source differs from reviewed bytes")
    state = {"policy": POLICY, "commit": TARGET, "runtime": runtime, "source": source,
             "dependencies": {"lock_sha256": digest(lock_bytes), "installed_sha256": digest(installed_bytes),
                              "packages": records}, "helper_sha256": HASHES,
             "diagnostic_tools": {name: digest((TOOLS / name).read_bytes()) for name in
                                  ("coverage-exit-pilot.py", "coverage-exit-read.php", "test-coverage-exit-pilot.py")}}
    (directory / "composer.lock").write_bytes(lock_bytes)
    (directory / "installed.json").write_bytes(installed_bytes)
    write(BASE / (label + ".json"), state)
    return state


def same_state(expected, actual):
    require(expected == actual, "Source/runtime/full package references/lock changed between paired phases")


def inventory(path):
    root = ET.parse(path).getroot()
    require(root.tag == NAMESPACE + "testSuite", "Unknown inventory schema")
    ids = [node.get("id") for node in root.findall("./" + NAMESPACE + "tests/" + NAMESPACE +
                                                   "testClass/" + NAMESPACE + "testMethod")]
    require(all(isinstance(value, str) and value for value in ids) and len(ids) == COUNT and
            len(set(ids)) == COUNT and fingerprint(sorted(ids)) == IDENTITIES, "Complete Audit inventory changed")
    return set(ids)


def junit(path, expected):
    root = ET.parse(path).getroot()
    suites = root.findall("testsuite")
    require(root.tag == "testsuites" and len(suites) == 1, "Ambiguous JUnit schema")
    suite = suites[0]
    require(int(suite.attrib["tests"]) == COUNT and all(int(suite.attrib[key]) == 0
            for key in ("errors", "failures", "skipped")), "JUnit has missing/error/failing/skipped cases")
    ids = []
    for case in root.findall(".//testcase"):
        require(not any(case.find(tag) is not None for tag in ("error", "failure", "skipped")), "Unsuccessful JUnit case")
        name = case.attrib["name"]
        match = re.fullmatch(r'(.+) with data set "(.*)"', name) or re.fullmatch(r"(.+) with data set #([0-9]+)", name)
        ids.append(case.attrib["class"] + "::" + (match[1] + "#" + match[2] if match else name))
    require(len(ids) == COUNT and len(set(ids)) == COUNT and set(ids) == expected, "JUnit identity mismatch")
    return {"cases": COUNT, "assertions": int(suite.attrib["assertions"]), "skipped": 0}


def coverage_semantics(value, expected):
    build = value["build"]
    require(value["schemaVersion"] == 1 and build["runtime"]["version"] == "8.5.12" and
            build["phpCodeCoverage"]["version"] == "14.4.1" and
            build["phpCodeCoverage"]["serializationFormat"] == 4 and
            build["phpCodeCoverage"]["driverInformation"] == {"name": "Xdebug", "version": "3.5.3"},
            "Coverage runtime/format differs")
    require(len(value["files"]) == SOURCE_COUNT and len(set(value["files"])) == SOURCE_COUNT and
            fingerprint(sorted(value["files"])) == SOURCE_FILES, "Coverage source scope changed")
    require(set(value["tests"]) == expected and len(value["tests"]) == COUNT and
            all(row["status"] == "success" for row in value["tests"].values()), "Coverage Audit records incomplete")
    require(all(type(value[key]) is int and value[key] > 0
                for key in ("branches", "paths", "hitBranches", "hitPaths")), "Executable path coverage missing")
    require(type(value["collectsHitCounts"]) is bool and set(value["lineCoverage"]) == set(value["files"]) and
            value["functionCoverage"] and set(value["functionCoverage"]).issubset(value["files"]),
            "Canonical line/function coverage scope is incomplete")
    return {"files": sorted(value["files"]),
            "tests": {key: {name: row[name] for name in ("size", "status")} for key, row in value["tests"].items()},
            "lineCoverage": value["lineCoverage"], "functionCoverage": value["functionCoverage"],
            "collectsHitCounts": value["collectsHitCounts"],
            **{key: value[key] for key in ("branches", "paths", "hitBranches", "hitPaths")}}


def compare_coverage(old, new, expected):
    def difference(left, right, path="coverage"):
        if type(left) is not type(right):
            return path
        if isinstance(left, dict):
            if set(left) != set(right):
                return path + ".keys"
            for key in sorted(left):
                mismatch = difference(left[key], right[key], path + "." + key)
                if mismatch:
                    return mismatch
            return None
        if isinstance(left, list):
            if len(left) != len(right):
                return path + ".length"
            for index, (first, second) in enumerate(zip(left, right)):
                mismatch = difference(first, second, path + "[" + str(index) + "]")
                if mismatch:
                    return mismatch
            return None
        return path if left != right else None

    mismatch = difference(coverage_semantics(old, expected), coverage_semantics(new, expected))
    require(mismatch is None, "Canonical coverage definitions/per-test hits differ at " + str(mismatch))


def worker_result(result, phase):
    require(result.get("shard") == "Audit" and type(result.get("returncode")) is int and result["returncode"] == 0 and
            result.get("signal") is None and result.get("timed_out") is False and result.get("launcher_error") is None and
            result.get("coverage_part_nonempty") is True, "Actual complete Audit worker did not pass")
    if phase == "new":
        require(result.get("process_group_cleanup_confirmed") is True, "New process-group cleanup unconfirmed")


def memory_events():
    root = Path("/sys/fs/cgroup")
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::") and (root / line[3:].lstrip("/")).is_dir():
            root = root / line[3:].lstrip("/")
            break
    return {key: int(value) for key, value in (line.split() for line in (root / "memory.events").read_text().splitlines())}


def no_oom(before, after):
    keys = ("oom", "oom_kill", "oom_group_kill")
    require(all(type(before.get(key)) is int and type(after.get(key)) is int and after[key] == before[key]
                for key in keys), "OOM delta or unavailable cgroup evidence")
    return {key: after[key] - before[key] for key in keys}


def original_arguments():
    return ["-c", "Build/phpunit.xml", "--path-coverage",
            "--coverage-php=" + str(Path.cwd() / ".Build/coverage/unit-Audit.cov"),
            "--process-isolation", "Tests/Unit/Audit"]


def phpunit_command(phase, arguments):
    require(phase in HASHES and arguments == original_arguments(), "Worker command is not the original complete Audit target")
    directory = Path.cwd() / BASE / phase
    return [str(Path.cwd() / ".Build/bin/phpunit"), *arguments[:-1], "--order-by=random",
            "--random-order-seed=" + str(SEED), "--cache-directory=" + str(Path.cwd() / CACHE),
            "--log-junit=" + str(directory / "junit.xml"), "--log-events-text=" + str(directory / "events.txt"), arguments[-1]]


def wrapper(arguments):
    phase = os.environ["COVERAGE_EXIT_PHASE"]
    command = phpunit_command(phase, arguments)
    write(BASE / phase / "command.json", {"command": command, "pid": os.getpid(), "cache_started_absent": not CACHE.exists()})
    require(not CACHE.exists(), "Audit cache was warmed before invocation")
    # The receipt precedes this check: once admission closes, either PHP never
    # starts or the controller already has its group ID for final containment.
    require((BASE / phase / "active").is_file(), "Controller closed phase admission before PHPUnit exec")
    os.execv(command[0], command)


def fixture_controls():
    tests = load(Path("Build/Scripts/test-release-coverage.py"), "coverage_fixture")
    tests.SCRIPT = helper("old").resolve()
    tests.MODULE = load(tests.SCRIPT, "old_coverage")
    cases = ("test_crashed_parent_cleans_real_child_before_later_shard",
             "test_successful_parent_cleans_real_child_before_later_shard",
             "test_unconfirmed_live_child_stops_worker_even_after_parent_wait_succeeded")
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(tests.CoverageTest(name) for name in cases))
    require(result.testsRun == 3 and len(result.failures) == 3 and not result.errors,
            "Original real-descendant controls did not reproduce exactly three assertion failures")
    staging = load(Path("Build/Scripts/test-release-coverage-staging.py"), "staging_fixture")
    staging.WORKFLOW = BASE / "old-release-evidence.yml"
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(staging.CoverageStagingTest))
    require(result.testsRun == 7 and len(result.failures) == 17 and not result.errors,
            "Actual original staging shell did not reproduce the known partial-report failures")
    subprocess.run(["bash", "Build/Scripts/verify-harness-ci.sh"], check=True, timeout=180)
    plans = {phase: load(helper(phase), phase + "_planner").plan(Path.cwd()) for phase in HASHES}
    require(plans["old"] == plans["new"] and len(plans["new"]["shards"]) == 27 and
            sorted(len(row["shards"]) for row in plans["new"]["workers"]) == [3, 7, 8, 9],
            "Complete 27-shard/four-worker assignment changed")
    write(BASE / "fixture-oracle.json", {"accepted": True, "old_worker_failed_cases": 3,
          "old_staging_failed_assertions": 17, "new_worker_cases": 17, "new_staging_methods": 7,
          "new_staging_bash_cases": 24, "plans": plans})


def prepare():
    require(not (BASE / "before.json").exists(), "Pilot state already exists")
    for phase, reference in (("old", OLD), ("new", TARGET)):
        path = BASE / "helpers" / phase / "release-coverage.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(subprocess.run(["git", "show", reference + ":Build/Scripts/release-coverage.py"],
                                       check=True, capture_output=True, timeout=30).stdout)
        helper(phase)
    old_workflow = subprocess.run(["git", "show", OLD + ":.github/workflows/release-evidence.yml"],
                                  check=True, capture_output=True, timeout=30).stdout
    require(digest(old_workflow) == OLD_WORKFLOW, "Original staging source changed")
    (BASE / "old-release-evidence.yml").write_bytes(old_workflow)
    snapshot("before")  # All source/runtime/dependency checks precede expensive work.
    fixture_controls()
    checked([".Build/bin/phpunit", "-c", "Build/phpunit.xml", "--list-tests-xml=" + str(BASE / "inventory.xml"),
             "Tests/Unit/Audit"], timeout=60)
    write(BASE / "inventory.json", sorted(inventory(BASE / "inventory.xml")))
    launcher = BASE / "phpunit-wrapper"
    launcher.write_text("#!/usr/bin/env python3\nimport runpy,sys\nsys.argv=[" + repr(str(Path(__file__).resolve())) +
                        ",'phpunit',*sys.argv[1:]]\nrunpy.run_path(sys.argv[0],run_name='__main__')\n")
    launcher.chmod(0o755)
    write(BASE / "plan.json", {"policy": POLICY, "application": TARGET, "old": OLD, "helper_sha256": HASHES,
          "seed": SEED, "count": COUNT, "source_count": SOURCE_COUNT, "shard_timeout_seconds": 1800,
          "outer_helper_timeout_seconds": HELPER_TIMEOUT_SECONDS, "diagnostic_group_cleanup_seconds": GROUP_CLEANUP_SECONDS,
          "commands": {phase: phpunit_command(phase, original_arguments()) for phase in HASHES}})


def accepted(phase):
    directory = BASE / phase
    marker = read(directory / "accepted.json")
    require(marker["result_sha256"] == digest((directory / "result.json").read_bytes()), "Accepted worker result changed")
    require(set(marker["files"]) == RECEIPT_FILES, "Accepted artifact set is incomplete")
    for name, value in marker["files"].items():
        require(digest((directory / name).read_bytes()) == value, "Accepted original artifact changed: " + name)
    require(marker.get("accepted") is True, "Phase was not accepted")
    return marker


def contain(process, directory, inspector):
    result = {"confirmed": False, "helper_reaped": process is None, "worker_group_confirmed": False,
              "live_group_after_worker": None, "command": None, "errors": []}
    try:
        (directory / "active").unlink(missing_ok=True)
    except OSError as error:
        result["errors"].append("Cannot close phase admission: " + str(error))
    if process is not None:
        try:
            # This group is the direct helper, distinct from its PHPUnit group.
            # Reap it before inspecting the last possible child admission receipt.
            inspector.cleanup_group(process)
            result["helper_reaped"] = True
        except (OSError, subprocess.TimeoutExpired) as error:
            result["errors"].append("Helper cleanup unconfirmed: " + str(error))
    try:
        record = read(directory / "command.json")
        group = record["pid"]
        require(type(group) is int and group > 1, "Worker process-group receipt has an invalid ID")
        result["command"] = record
        result["live_group_after_worker"] = inspector.group_is_running(group)
        if result["live_group_after_worker"]:
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The known group exited after inspection; still verify below.
        deadline = time.monotonic() + GROUP_CLEANUP_SECONDS
        while inspector.group_is_running(group):
            require(time.monotonic() < deadline, "Known PHPUnit group still has a live member")
            time.sleep(0.01)
        result["worker_group_confirmed"] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["errors"].append("PHPUnit cleanup unconfirmed: " + str(error))
    result["confirmed"] = not result["errors"] and result["helper_reaped"] and result["worker_group_confirmed"]
    write(directory / "containment.json", result)
    return result


def run_phase(phase):
    before = read(BASE / "before.json")
    same_state(before, snapshot("pre-" + phase))
    if phase == "new":
        accepted("old")
        same_state(before, read(BASE / "between.json"))
    require(not (BASE / phase).exists(), "Phase output already exists; no silent retry")
    require(not CACHE.is_symlink(), "Cache path cannot be a symlink")
    if CACHE.exists():
        shutil.rmtree(CACHE)
    require(not CACHE.exists(), "Phase cache must start absent")
    directory = BASE / phase
    directory.mkdir()
    part = Path(".Build/coverage/unit-Audit.cov")
    part.unlink(missing_ok=True)  # A launch failure cannot retain the previous arm's part.
    inspector = load(helper("new"), "group_inspector")
    start_memory = memory_events()
    started = time.monotonic()
    command = [sys.executable, str(helper(phase)), "worker", "--shards", '["Audit"]',
               "--phpunit", str((BASE / "phpunit-wrapper").resolve())]
    environment = dict(os.environ, COVERAGE_EXIT_PHASE=phase, PYTHONDONTWRITEBYTECODE="1")
    process = None
    returncode = None
    outer_timed_out = False
    launcher_error = None
    (directory / "active").write_text("active\n")
    with (directory / "stdout.log").open("w") as output:
        try:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, env=environment, start_new_session=True)
            returncode = process.wait(timeout=HELPER_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            # The original helper already bounds PHP at1800s; this is an outer diagnostic guard.
            outer_timed_out = True
        except OSError as error:
            launcher_error = str(error)
        finally:
            try:
                containment = contain(process, directory, inspector)
                if returncode is None and process is not None:
                    returncode = process.returncode
            finally:
                if part.is_file():
                    shutil.copy2(part, directory / "unit-Audit.cov")
    outcome = None
    outcome_error = None
    try:
        stdout = (directory / "stdout.log").read_text()
        print(stdout, end="", flush=True)
        outcomes = [json.loads(line.removeprefix("Coverage shard result: ")) for line in stdout.splitlines()
                    if line.startswith("Coverage shard result: ")]
        require(len(outcomes) == 1, "Worker did not record exactly one Audit outcome")
        outcome = outcomes[0]
    except (OSError, ValueError) as error:
        outcome_error = str(error)
    result = {"policy": POLICY, "phase": phase, "helper_returncode": returncode, "worker": outcome,
              "seconds": round(time.monotonic() - started, 3), "command": containment["command"],
              "containment": containment, "outer_timed_out": outer_timed_out, "launcher_error": launcher_error,
              "outcome_error": outcome_error, "live_group_after_worker": containment["live_group_after_worker"],
              "memory_before": start_memory, "memory_after": memory_events()}
    write(directory / "result.json", result)
    require(returncode == 0 and not outer_timed_out and launcher_error is None,
            "Audit helper failed, timed out or could not launch; original result retained")
    require(containment["confirmed"] and containment["live_group_after_worker"] is False,
            "Audit worker retained a live group or diagnostic cleanup was unconfirmed")
    require(outcome_error is None, "Audit outcome invalid: " + str(outcome_error))


def accept_phase(phase):
    directory = BASE / phase
    result = read(directory / "result.json")
    require(result["helper_returncode"] == 0 and result["live_group_after_worker"] is False and
            result["containment"]["confirmed"] is True and result["outer_timed_out"] is False and
            result["launcher_error"] is None and result["outcome_error"] is None,
            "Worker failed or left descendants")
    worker_result(result["worker"], phase)
    require(result["command"]["command"] == phpunit_command(phase, original_arguments()) and
            result["command"]["cache_started_absent"] is True, "Actual command/cache differs from paired plan")
    no_oom(result["memory_before"], result["memory_after"])
    expected = inventory(BASE / "inventory.xml")
    cases = junit(directory / "junit.xml", expected)
    coverage = json.loads(checked(["php", str(TOOLS / "coverage-exit-read.php"), str(directory / "unit-Audit.cov")], timeout=60))
    require(coverage["part_sha256"] == digest((directory / "unit-Audit.cov").read_bytes()),
            "Decoded coverage does not bind the preserved original part")
    coverage_semantics(coverage, expected)
    write(directory / "coverage.json", coverage)
    same_state(read(BASE / "before.json"), snapshot("between" if phase == "old" else "after"))
    files = {name: digest((directory / name).read_bytes()) for name in sorted(RECEIPT_FILES)}
    write(directory / "accepted.json", {"accepted": True, "junit": cases, "files": files,
          "result_sha256": digest((directory / "result.json").read_bytes())})


def final():
    markers = {phase: accepted(phase) for phase in HASHES}
    for label in ("between", "after"):
        same_state(read(BASE / "before.json"), read(BASE / (label + ".json")))
    same_state(read(BASE / "before.json"), snapshot("final"))
    compare_coverage(read(BASE / "old/coverage.json"), read(BASE / "new/coverage.json"), inventory(BASE / "inventory.xml"))
    require(markers["old"]["junit"] == markers["new"]["junit"], "Audit assertion count changed")
    require(read(BASE / "fixture-oracle.json")["accepted"] is True, "Failure fixtures did not pass")
    result = {"accepted": True, "policy": POLICY, "application": TARGET, "helper_sha256": HASHES,
              "complete_audit_cases": COUNT, "current_source_files": SOURCE_COUNT, "same_full_coverage": True,
              "same_frozen_inputs": True, "new_cleanup_confirmed": True, "phase_receipts": markers}
    write(BASE / "oracle.json", result)
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "old", "accept-old", "new", "accept-new", "final", "phpunit"))
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    try:
        if arguments.mode == "phpunit":
            wrapper(arguments.arguments)
        elif arguments.mode == "prepare":
            prepare()
        elif arguments.mode in HASHES:
            run_phase(arguments.mode)
        elif arguments.mode.startswith("accept-"):
            accept_phase(arguments.mode.removeprefix("accept-"))
        else:
            final()
        return 0
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, subprocess.SubprocessError) as error:
        result = {"accepted": False, "policy": POLICY, "mode": arguments.mode, "error": str(error)}
        write(BASE / (arguments.mode + "-failure.json"), result)
        print(json.dumps(result, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
