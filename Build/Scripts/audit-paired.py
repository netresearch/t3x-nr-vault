#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Temporary audit-paired-v1 experiment; historical snapshot oracles stay unchanged."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location("audit_contract", Path(__file__).with_name("verify-audit-isolation.py"))
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
BASE = Path(".Build/audit-paired")
SEED = 1793178338
POLICY = "audit-paired-v1"
RUNTIME = r'''
$extensions=get_loaded_extensions(); sort($extensions);
echo json_encode(['php'=>PHP_VERSION,'xdebug'=>phpversion('xdebug'),
    'binary'=>PHP_BINARY,'binary_sha256'=>hash_file('sha256',PHP_BINARY),
    'extensions'=>$extensions,'coverage_mode'=>getenv('XDEBUG_MODE') ?: ini_get('xdebug.mode')]);
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked(command, timeout=30):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout).stdout


def package_records(packages):
    require(isinstance(packages, list) and packages, "Package metadata is missing")
    records = []
    for package in packages:
        require(isinstance(package.get("name"), str) and package["name"] and
                isinstance(package.get("version"), str) and package["version"], "Package identity missing")
        record = {key: package.get(key) for key in ("name", "version", "type", "source", "dist")}
        require(record["type"] == "metapackage" or any(
            isinstance(record[key], dict) and isinstance(record[key].get("reference"), str) and
            record[key]["reference"] for key in ("source", "dist")), "Package source reference missing")
        records.append(record)
    require(len({row["name"] for row in records}) == len(records), "Duplicate package identity")
    return sorted(records, key=lambda row: row["name"])


def dependency_state(lock_bytes, installed_bytes):
    lock = json.loads(lock_bytes)
    installed = json.loads(installed_bytes)
    records = package_records(installed["packages"])
    locked = package_records(lock["packages"] + lock.get("packages-dev", []))
    require(records == locked, "Installed package versions/references differ from lock")
    versions = {row["name"]: row["version"] for row in records}
    require(versions.get("phpunit/phpunit") == "13.4.5" and
            versions.get("phpunit/php-code-coverage") == "14.4.1", "Required test tool runtime changed")
    return {"lock_sha256": digest(lock_bytes), "installed_sha256": digest(installed_bytes), "packages": records}


def validate_runtime(runtime):
    require(runtime["php"] == "8.5.12" and runtime["xdebug"] == "3.5.3" and
            "coverage" in runtime["coverage_mode"].split(",") and
            re.fullmatch(r"[0-9a-f]{64}", runtime["binary_sha256"]), "Actual PHP/Xdebug coverage runtime changed")


def snapshot(label):
    commit = checked(["git", "rev-parse", "HEAD"]).strip()
    require(commit == CONTRACT.TARGET, "Application checkout differs from fixed target")
    require(subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], check=False).returncode == 0,
            "Tracked application source changed")
    runtime = json.loads(checked(["php", "-r", RUNTIME]))
    validate_runtime(runtime)
    lock_bytes = Path("composer.lock").read_bytes()
    installed_bytes = Path(".Build/vendor/composer/installed.json").read_bytes()
    state = {"policy": POLICY, "commit": commit, "runtime": runtime,
             "dependencies": dependency_state(lock_bytes, installed_bytes)}
    directory = BASE / "snapshots" / label
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "composer.lock").write_bytes(lock_bytes)
    (directory / "installed.json").write_bytes(installed_bytes)
    write(BASE / (label + ".json"), state)
    return state


def same_state(expected, actual):
    require(expected == actual, "Source/runtime/lock/package references changed between paired phases")


def command(phase):
    require(phase in ("baseline", "isolation"), "Unknown paired phase")
    directory = Path.cwd() / BASE / phase
    arguments = [".Build/bin/phpunit", "-c", "Build/phpunit.xml", "--path-coverage",
                 "--coverage-php=" + str(directory / "unit-Audit.cov"), "--order-by=random",
                 "--random-order-seed=" + str(SEED),
                 "--cache-directory=" + str(Path.cwd() / BASE / ("cache-" + phase)),
                 "--log-junit=" + str(directory / "junit.xml"),
                 "--log-events-text=" + str(directory / "events.txt"), "Tests/Unit/Audit"]
    if phase == "isolation":
        arguments.insert(5, "--process-isolation")
    return arguments


def no_oom(process):
    events = process.get("memory_events_delta")
    require(isinstance(events, dict) and all(type(events.get(key)) is int and events[key] == 0
            for key in ("oom", "oom_kill", "oom_group_kill")), "OOM event or missing cgroup OOM evidence")


def process_result(process, phase):
    require(process.get("command") == command(phase), "Measured command differs from complete paired plan")
    require(process.get("timed_out") is False and process.get("launcher_error") is None,
            "Audit timed out or failed to launch")
    no_oom(process)
    if phase == "baseline":
        require(type(process.get("returncode")) is int and process["returncode"] == -11 and
                process.get("signal") == "SIGSEGV", "Baseline did not reproduce actual SIGSEGV")
    else:
        require(type(process.get("returncode")) is int and process["returncode"] == 0 and
                process.get("signal") is None, "Isolated Audit did not pass")


def kernel_capture(label):
    try:
        result = subprocess.run(["sudo", "-n", "dmesg"], capture_output=True, text=True, check=False, timeout=10)
        value = {"available": result.returncode == 0, "text": result.stdout, "error": result.stderr}
    except (OSError, subprocess.SubprocessError) as error:
        value = {"available": False, "text": "", "error": str(error)}
    directory = BASE / label
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "dmesg.txt").write_text(value["text"] + value["error"])
    write(directory / "kernel.json", value)
    return value


def kernel_evidence(before, after):
    if not (before["available"] and after["available"]):
        return {"available": False, "reason": "Kernel log unavailable; actual signal and cgroup evidence retained"}
    timestamps = [float(value) for value in re.findall(r"^\[\s*([0-9]+\.[0-9]+)\]", before["text"], re.MULTILINE)]
    require(timestamps, "Kernel log readable but baseline boundary missing")
    boundary = max(timestamps)
    faults = []
    for line in after["text"].splitlines():
        match = re.match(r"^\[\s*([0-9]+\.[0-9]+)\]", line)
        if match and float(match[1]) > boundary and re.search(r"\bphp\[[0-9]+\].*segfault.*in xdebug\.so\b", line):
            faults.append(line)
    require(faults, "Readable kernel log does not identify a new PHP/Xdebug baseline fault")
    return {"available": True, "new_xdebug_faults": faults}


def prepare():
    require(not (BASE / "before.json").exists(), "Paired state already exists")
    require(all(not (BASE / ("cache-" + phase)).exists() for phase in ("baseline", "isolation")),
            "Both paired cache directories must start absent")
    snapshot("before")  # Source/runtime/package checks precede test discovery and execution.
    checked([".Build/bin/phpunit", "-c", "Build/phpunit.xml",
             "--list-tests-xml=" + str(BASE / "inventory.xml"), "Tests/Unit/Audit"], timeout=60)
    expected = CONTRACT.inventory(BASE / "inventory.xml")
    write(BASE / "inventory.json", sorted(expected))
    kernel_capture("kernel-before")
    write(BASE / "plan.json", {"policy": POLICY, "target": CONTRACT.TARGET, "seed": SEED,
          "cases": CONTRACT.COUNT, "commands": {phase: command(phase) for phase in ("baseline", "isolation")}})


def baseline_proof(process, kernel):
    process_result(process, "baseline")
    return kernel_evidence(read(BASE / "kernel-before/kernel.json"), kernel)


def preflight(phase):
    before = read(BASE / "before.json")
    same_state(before, snapshot("pre-" + phase))
    require(not (BASE / ("cache-" + phase)).exists(), "Phase cache is not fresh")
    if phase == "isolation":
        marker = read(BASE / "baseline-accepted.json")
        process = read(BASE / "baseline/result.json")
        require(marker["process_sha256"] == digest((BASE / "baseline/result.json").read_bytes()),
                "Accepted baseline result changed")
        baseline_proof(process, read(BASE / "baseline/kernel.json"))
        same_state(before, read(BASE / "between.json"))


def run_phase(phase):
    preflight(phase)
    launcher = Path(__file__).with_name("diagnose-audit-coverage.py")
    return subprocess.run([sys.executable, str(launcher), "--output", str(BASE / phase / "result.json"),
                           "--", *command(phase)], check=False, timeout=1860).returncode


def accept_baseline():
    kernel = kernel_capture("baseline")
    proof = baseline_proof(read(BASE / "baseline/result.json"), kernel)
    same_state(read(BASE / "before.json"), snapshot("between"))
    require(not (BASE / "cache-isolation").exists(), "Isolation cache was warmed by baseline")
    write(BASE / "baseline-accepted.json", {"policy": POLICY, "kernel": proof,
          "process_sha256": digest((BASE / "baseline/result.json").read_bytes())})


def final():
    kernel_capture("isolation")
    preflight_state = read(BASE / "before.json")
    same_state(preflight_state, snapshot("after"))
    same_state(preflight_state, read(BASE / "between.json"))
    marker = read(BASE / "baseline-accepted.json")
    require(marker["process_sha256"] == digest((BASE / "baseline/result.json").read_bytes()),
            "Baseline result changed after acceptance")
    baseline_proof(read(BASE / "baseline/result.json"), read(BASE / "baseline/kernel.json"))
    process = read(BASE / "isolation/result.json")
    process_result(process, "isolation")
    expected = CONTRACT.inventory(BASE / "inventory.xml")
    junit = CONTRACT.junit(BASE / "isolation/junit.xml", expected)
    part = BASE / "isolation/unit-Audit.cov"
    require(part.stat().st_size > 0, "Isolated coverage part missing/empty")
    reader = CONTRACT.COVERAGE_READER.replace(".Build/coverage/unit-Audit.cov", str(part))
    coverage = json.loads(checked(["php", "-r", reader]))
    CONTRACT.coverage(coverage, expected)
    write(BASE / "isolation/coverage-metrics.json", coverage)
    return {"accepted": True, "policy": POLICY, "baseline": "SIGSEGV", "junit": junit,
            "packages_identical": True, "source_files": len(coverage["files"]),
            "branches": coverage["branches"], "paths": coverage["paths"],
            "isolated_seconds": process["seconds"], "kernel": marker["kernel"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "baseline", "accept-baseline", "isolation", "final"))
    mode = parser.parse_args().mode
    try:
        if mode == "prepare":
            prepare()
        elif mode in ("baseline", "isolation"):
            return run_phase(mode)
        elif mode == "accept-baseline":
            accept_baseline()
        else:
            result = final()
            write(BASE / "oracle.json", result)
            print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, KeyError, TypeError, OSError, CONTRACT.ET.ParseError, subprocess.SubprocessError) as error:
        result = {"accepted": False, "policy": POLICY, "mode": mode, "error": str(error)}
        write(BASE / ("oracle.json" if mode == "final" else mode + "-failure.json"), result)
        print(json.dumps(result, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
