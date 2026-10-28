#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Offline fail-closed controls for the temporary paired experiment."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("paired", Path(__file__).with_name("audit-paired.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def package(name, version):
    return {"name": name, "version": version, "type": "library",
            "source": {"type": "git", "url": "https://example.test/source", "reference": "a" * 40},
            "dist": {"type": "zip", "url": "https://example.test/dist", "reference": "a" * 40}}


class PairedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        old = Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, old)
        self.packages = [package("phpunit/phpunit", "13.4.5"),
                         package("phpunit/php-code-coverage", "14.4.1"), package("vendor/library", "2.1.0")]
        self.runtime = {"php": "8.5.12", "xdebug": "3.5.3", "coverage_mode": "coverage",
                        "binary": "/usr/bin/php8.5", "binary_sha256": "a" * 64, "extensions": ["xdebug"]}
        self.state = {"policy": MODULE.POLICY, "commit": MODULE.CONTRACT.TARGET,
                      "runtime": self.runtime, "dependencies": self.dependency_state()}
        self.before_kernel = {"available": True, "text": "[ 1.000] ready\n", "error": ""}
        self.after_kernel = {"available": True, "text": "[ 1.000] ready\n[ 2.000] php[42]: segfault in xdebug.so[1]\n", "error": ""}
        self.install_valid_baseline()

    def dependency_state(self, packages=None):
        records = self.packages if packages is None else packages
        return MODULE.dependency_state(json.dumps({"packages": [], "packages-dev": records}).encode(),
                                       json.dumps({"packages": records}).encode())

    def process(self, phase="baseline"):
        return {"command": MODULE.command(phase), "returncode": -11 if phase == "baseline" else 0,
                "signal": "SIGSEGV" if phase == "baseline" else None, "timed_out": False,
                "launcher_error": None, "memory_events_delta": {"oom": 0, "oom_kill": 0, "oom_group_kill": 0}}

    def install_valid_baseline(self, process=None):
        MODULE.write(MODULE.BASE / "before.json", self.state)
        MODULE.write(MODULE.BASE / "between.json", self.state)
        MODULE.write(MODULE.BASE / "baseline/result.json", self.process() if process is None else process)
        MODULE.write(MODULE.BASE / "kernel-before/kernel.json", self.before_kernel)
        MODULE.write(MODULE.BASE / "baseline/kernel.json", self.after_kernel)
        MODULE.write(MODULE.BASE / "baseline-accepted.json", {"policy": MODULE.POLICY,
                     "kernel": MODULE.kernel_evidence(self.before_kernel, self.after_kernel),
                     "process_sha256": MODULE.digest((MODULE.BASE / "baseline/result.json").read_bytes())})

    def test_valid_baseline_and_immutable_preflight_allow_isolation(self):
        MODULE.process_result(self.process(), "baseline")
        MODULE.process_result(self.process("isolation"), "isolation")
        with patch.object(MODULE, "snapshot", return_value=self.state):
            MODULE.preflight("isolation")

    def test_commands_keep_every_case_seed_path_coverage_and_only_change_isolation_mode(self):
        base = MODULE.command("baseline")
        isolated = MODULE.command("isolation")
        normalized = [value.replace("/baseline/", "/isolation/").replace("/cache-baseline", "/cache-isolation") for value in base]
        normalized.insert(5, "--process-isolation")
        self.assertEqual(normalized, isolated)
        for arguments in (base, isolated):
            self.assertEqual(arguments[-1], "Tests/Unit/Audit")
            self.assertIn("--path-coverage", arguments)
            self.assertIn("--random-order-seed=1793178338", arguments)
            self.assertIn("--order-by=random", arguments)
            self.assertFalse(any(value.startswith("--filter") or value.startswith("--exclude") for value in arguments))

    def test_isolation_never_launches_after_baseline_pass_error_timeout_or_oom(self):
        changes = ({"returncode": 0, "signal": None}, {"returncode": 2, "signal": None},
                   {"returncode": -9, "signal": "SIGKILL"}, {"timed_out": True},
                   {"launcher_error": "missing executable"},
                   {"memory_events_delta": {"oom": 1, "oom_kill": 0, "oom_group_kill": 0}},
                   {"memory_events_delta": {"oom": 0, "oom_kill": 1, "oom_group_kill": 0}},
                   {"memory_events_delta": None})
        for change in changes:
            with self.subTest(change=change):
                process = dict(self.process(), **change)
                self.install_valid_baseline(process)
                with patch.object(MODULE, "snapshot", return_value=self.state), patch.object(MODULE.subprocess, "run") as launch:
                    with self.assertRaises(ValueError):
                        MODULE.run_phase("isolation")
                    launch.assert_not_called()

    def test_isolation_never_launches_after_state_or_reference_drift(self):
        altered = []
        for key in ("version", "source", "dist"):
            packages = copy.deepcopy(self.packages)
            if key == "version":
                packages[-1][key] = "2.1.1"
            else:
                packages[-1][key]["reference"] = "b" * 40
            state = copy.deepcopy(self.state)
            state["dependencies"] = self.dependency_state(packages)
            altered.append(state)
        for field in ("lock_sha256", "installed_sha256"):
            state = copy.deepcopy(self.state)
            state["dependencies"][field] = "b" * 64
            altered.append(state)
        state = copy.deepcopy(self.state)
        state["commit"] = "b" * 40
        altered.append(state)
        state = copy.deepcopy(self.state)
        state["runtime"]["binary_sha256"] = "b" * 64
        altered.append(state)
        for state in altered:
            with self.subTest(state=state):
                with patch.object(MODULE, "snapshot", return_value=state), patch.object(MODULE.subprocess, "run") as launch:
                    with self.assertRaises(ValueError):
                        MODULE.run_phase("isolation")
                    launch.assert_not_called()

    def test_lock_and_installed_references_must_match_even_when_version_matches(self):
        installed = copy.deepcopy(self.packages)
        installed[-1]["source"]["reference"] = "b" * 40
        with self.assertRaises(ValueError):
            MODULE.dependency_state(json.dumps({"packages": self.packages}).encode(),
                                    json.dumps({"packages": installed}).encode())

    def test_preflight_blocks_changed_tracked_source_and_wrong_target_before_php(self):
        with patch.object(MODULE, "checked", return_value="b" * 40) as checked:
            with self.assertRaises(ValueError):
                MODULE.snapshot("probe")
            self.assertEqual(checked.call_count, 1)
        with patch.object(MODULE, "checked", return_value=MODULE.CONTRACT.TARGET) as checked, \
                patch.object(MODULE.subprocess, "run", return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(ValueError):
                MODULE.snapshot("probe")
            self.assertEqual(checked.call_count, 1)

    def test_wrong_runtime_and_tool_versions_block(self):
        for change in ({"php": "8.5.11"}, {"xdebug": "3.5.2"}, {"coverage_mode": "off"}):
            with self.assertRaises(ValueError):
                MODULE.validate_runtime(dict(self.runtime, **change))
        packages = copy.deepcopy(self.packages)
        packages[0]["version"] = "13.4.6"
        with self.assertRaises(ValueError):
            self.dependency_state(packages)

    def test_warmed_cache_blocks_before_isolation_launch(self):
        cache = MODULE.BASE / "cache-isolation"
        cache.mkdir(parents=True)
        with patch.object(MODULE, "snapshot", return_value=self.state), patch.object(MODULE.subprocess, "run") as launch:
            with self.assertRaises(ValueError):
                MODULE.run_phase("isolation")
            launch.assert_not_called()

    def test_prepare_rejects_a_warmed_cache_before_expensive_work(self):
        (MODULE.BASE / "before.json").unlink()
        (MODULE.BASE / "cache-baseline").mkdir()
        with patch.object(MODULE, "snapshot") as snapshot:
            with self.assertRaisesRegex(ValueError, "cache"):
                MODULE.prepare()
            snapshot.assert_not_called()

    def test_final_requires_all_phase_evidence_and_accepts_a_complete_pair(self):
        MODULE.write(MODULE.BASE / "isolation/result.json", dict(self.process("isolation"), seconds=200))
        (MODULE.BASE / "isolation/unit-Audit.cov").write_text("fixture payload")
        expected = {"Example::case"}
        measured = {"files": ["Audit/Foo.php"], "branches": 1, "paths": 1}
        with patch.object(MODULE, "snapshot", return_value=self.state), \
                patch.object(MODULE, "kernel_capture"), \
                patch.object(MODULE, "checked", return_value=json.dumps(measured)), \
                patch.object(MODULE.CONTRACT, "inventory", return_value=expected), \
                patch.object(MODULE.CONTRACT, "junit", return_value={"cases": 1, "skipped": 0}) as junit, \
                patch.object(MODULE.CONTRACT, "coverage") as coverage:
            result = MODULE.final()
            self.assertTrue(result["accepted"])
            self.assertEqual(result["policy"], "audit-paired-v1")
            junit.assert_called_once_with(MODULE.BASE / "isolation/junit.xml", expected)
            coverage.assert_called_once_with(measured, expected)
        process = dict(self.process("isolation"), timed_out=True)
        MODULE.write(MODULE.BASE / "isolation/result.json", process)
        with patch.object(MODULE, "snapshot", return_value=self.state), patch.object(MODULE, "kernel_capture"), \
                patch.object(MODULE.CONTRACT, "coverage") as coverage:
            with self.assertRaises(ValueError):
                MODULE.final()
            coverage.assert_not_called()

    def test_kernel_requires_new_xdebug_fault_when_readable_and_marks_unavailable(self):
        self.assertTrue(MODULE.kernel_evidence(self.before_kernel, self.after_kernel)["available"])
        for text in ("[ 0.500] php[42]: segfault in xdebug.so[1]\n", "[ 2.000] php[42]: segfault in other.so[1]\n"):
            with self.assertRaises(ValueError):
                MODULE.kernel_evidence(self.before_kernel, dict(self.after_kernel, text=text))
        self.assertFalse(MODULE.kernel_evidence({"available": False}, self.after_kernel)["available"])

    def test_tampered_baseline_result_cannot_reuse_acceptance(self):
        process = self.process()
        process["returncode"] = 0
        MODULE.write(MODULE.BASE / "baseline/result.json", process)
        with patch.object(MODULE, "snapshot", return_value=self.state), patch.object(MODULE.subprocess, "run") as launch:
            with self.assertRaises(ValueError):
                MODULE.run_phase("isolation")
            launch.assert_not_called()

    def test_isolated_failure_timeout_or_oom_cannot_pass_final_process_policy(self):
        for change in ({"returncode": 1}, {"signal": "SIGSEGV"}, {"timed_out": True},
                       {"memory_events_delta": {"oom": 0, "oom_kill": 0, "oom_group_kill": 1}}):
            with self.assertRaises(ValueError):
                MODULE.process_result(dict(self.process("isolation"), **change), "isolation")


if __name__ == "__main__":
    unittest.main()
