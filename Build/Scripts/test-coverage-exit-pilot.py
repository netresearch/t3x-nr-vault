#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Offline fail-closed controls for the temporary paired worker experiment."""

import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import signal
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("pilot", Path(__file__).with_name("coverage-exit-pilot.py"))
PILOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PILOT)


class PilotTest(unittest.TestCase):
    def setUp(self):
        self.ids = {"Netresearch\\NrVault\\Tests\\Unit\\Audit\\ExampleTest::one",
                    "Netresearch\\NrVault\\Tests\\Unit\\Audit\\ExampleTest::two#sample"}
        self.coverage = {
            "schemaVersion": 1, "files": ["Audit/Example.php"],
            "tests": {value: {"size": "small", "status": "success", "time": 0.1} for value in self.ids},
            "build": {"runtime": {"version": "8.5.12"}, "phpCodeCoverage": {
                "version": "14.4.1", "serializationFormat": 4,
                "driverInformation": {"name": "Xdebug", "version": "3.5.3"}}},
            "lineCoverage": {"Audit/Example.php": {"10": {sorted(self.ids)[0]: 1}}},
            "functionCoverage": {"Audit/Example.php": {"one": {"branches": {"0": {
                "op_start": 0, "op_end": 1, "line_start": 10, "line_end": 11,
                "out": [1], "out_hit": [1], "hit": {sorted(self.ids)[0]: 1}}},
                "paths": {"0": {"path": [0, 1], "hit": {sorted(self.ids)[0]: 1}}}}}},
            "branches": 1, "paths": 1, "hitBranches": 1, "hitPaths": 1,
            "collectsHitCounts": False,
        }
        self.source_patch = patch.multiple(PILOT, COUNT=2, SOURCE_COUNT=1,
                                           SOURCE_FILES=PILOT.fingerprint(self.coverage["files"]))
        self.source_patch.start()
        self.addCleanup(self.source_patch.stop)

    def test_complete_equal_coverage_ignores_only_measurement_time_and_raw_hash(self):
        other = copy.deepcopy(self.coverage)
        other["part_sha256"] = "different serialized bytes"
        other["basePath"] = "/another/root/Classes"
        for value in other["tests"].values():
            value["time"] = 9.1
        PILOT.compare_coverage(self.coverage, other, self.ids)

    def test_equal_totals_cannot_hide_changed_branch_definition(self):
        other = copy.deepcopy(self.coverage)
        other["functionCoverage"]["Audit/Example.php"]["one"]["branches"]["0"]["line_end"] += 1
        with self.assertRaises(ValueError):
            PILOT.compare_coverage(self.coverage, other, self.ids)

    def test_equal_totals_cannot_hide_changed_test_attribution(self):
        other = copy.deepcopy(self.coverage)
        other["functionCoverage"]["Audit/Example.php"]["one"]["paths"]["0"]["hit"] = {sorted(self.ids)[1]: 1}
        with self.assertRaises(ValueError):
            PILOT.compare_coverage(self.coverage, other, self.ids)

    def test_changed_positive_hit_count_path_order_or_collection_mode_blocks(self):
        for mutation in ("count", "path", "mode"):
            other = copy.deepcopy(self.coverage)
            paths = other["functionCoverage"]["Audit/Example.php"]["one"]["paths"]["0"]
            if mutation == "count":
                paths["hit"][sorted(self.ids)[0]] = 2
            elif mutation == "path":
                paths["path"] = [1, 0]
            else:
                other["collectsHitCounts"] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                PILOT.compare_coverage(self.coverage, other, self.ids)

    def test_replacement_case_with_same_count_is_rejected(self):
        other = copy.deepcopy(self.coverage)
        other["tests"]["Netresearch\\NrVault\\Tests\\Unit\\Audit\\OtherTest::replacement"] = other["tests"].pop(sorted(self.ids)[0])
        with self.assertRaises(ValueError):
            PILOT.compare_coverage(self.coverage, other, self.ids)

    def test_missing_case_skip_or_scope_change_blocks(self):
        for mutation in ("missing", "skip", "scope", "runtime", "empty"):
            other = copy.deepcopy(self.coverage)
            if mutation == "missing":
                other["tests"].pop(sorted(self.ids)[0])
            elif mutation == "skip":
                other["tests"][sorted(self.ids)[0]]["status"] = "skipped"
            elif mutation == "scope":
                other["files"] = ["Audit/Different.php"]
            elif mutation == "runtime":
                other["build"]["phpCodeCoverage"]["driverInformation"]["version"] = "3.5.2"
            else:
                other["hitPaths"] = 0
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                PILOT.compare_coverage(self.coverage, other, self.ids)

    def test_actual_worker_failure_signal_timeout_missing_output_and_unconfirmed_cleanup_block(self):
        valid = {"shard": "Audit", "returncode": 0, "signal": None, "timed_out": False,
                 "launcher_error": None, "coverage_part_nonempty": True,
                 "process_group_cleanup_confirmed": True}
        PILOT.worker_result(valid, "new")
        for key, value in (("returncode", -11), ("signal", "SIGSEGV"), ("timed_out", True),
                           ("launcher_error", "failure"), ("coverage_part_nonempty", False),
                           ("process_group_cleanup_confirmed", False)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                PILOT.worker_result(dict(valid, **{key: value}), "new")

    def test_oom_delta_rejects_even_successful_audit(self):
        before = {"oom": 0, "oom_kill": 0, "oom_group_kill": 0}
        self.assertEqual(PILOT.no_oom(before, before), before)
        for key in before:
            with self.subTest(key=key), self.assertRaises(ValueError):
                PILOT.no_oom(before, dict(before, **{key: 1}))
        with self.assertRaises(ValueError):
            PILOT.no_oom(before, {})

    def test_wrapper_accepts_only_original_complete_audit_command(self):
        original = PILOT.original_arguments()
        actual = PILOT.phpunit_command("old", original)
        self.assertIn("--process-isolation", actual)
        self.assertIn("--random-order-seed=" + str(PILOT.SEED), actual)
        self.assertEqual(actual[-1], "Tests/Unit/Audit")
        for changed in (original[:-1], original + ["--filter=one"],
                        [arg for arg in original if arg != "--path-coverage"]):
            with self.assertRaises(ValueError):
                PILOT.phpunit_command("old", changed)

    def test_real_wrapper_exec_preserves_flags_and_records_fresh_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / ".Build/bin/phpunit"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
            binary.chmod(0o755)
            active = root / PILOT.BASE / "old/active"
            active.parent.mkdir(parents=True)
            active.write_text("active\n")
            arguments = ["-c", "Build/phpunit.xml", "--path-coverage",
                         "--coverage-php=" + str(root / ".Build/coverage/unit-Audit.cov"),
                         "--process-isolation", "Tests/Unit/Audit"]
            result = subprocess.run([sys.executable, str(Path(PILOT.__file__).resolve()), "phpunit", *arguments],
                                    cwd=root, env=dict(os.environ, COVERAGE_EXIT_PHASE="old"),
                                    capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads((root / PILOT.BASE / "old/command.json").read_text())
            self.assertTrue(record["cache_started_absent"])
            self.assertEqual(json.loads(result.stdout), record["command"][1:])
            self.assertEqual(record["command"][-1], "Tests/Unit/Audit")

    def test_wrapper_cannot_exec_after_controller_closes_phase_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / ".Build/bin/phpunit"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/usr/bin/env python3\nfrom pathlib import Path\nPath('unexpected-exec').touch()\n")
            binary.chmod(0o755)
            arguments = ["-c", "Build/phpunit.xml", "--path-coverage",
                         "--coverage-php=" + str(root / ".Build/coverage/unit-Audit.cov"),
                         "--process-isolation", "Tests/Unit/Audit"]
            result = subprocess.run([sys.executable, str(Path(PILOT.__file__).resolve()), "phpunit", *arguments],
                                    cwd=root, env=dict(os.environ, COVERAGE_EXIT_PHASE="old"),
                                    capture_output=True, text=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse((root / "unexpected-exec").exists())

    def real_helper_exit(self, output, mode="killed", kill_confirmed=True):
        application_helper = Path("Build/Scripts/release-coverage.py").resolve()
        with tempfile.TemporaryDirectory(prefix="coverage-pilot-fixture-") as temporary:
            root = Path(temporary)
            marker = "coverage-pilot-owned-" + root.name
            worker = ("import json,os,pathlib,time\n"
                      "directory=pathlib.Path('.Build/coverage-exit-pilot/old')\n"
                      "(directory/'command.json').write_text(json.dumps({'pid':os.getpid(),'command':['offline-worker'],'cache_started_absent':True}))\n"
                      "pathlib.Path('group.pid').write_text(str(os.getpid()))\n"
                      "part=pathlib.Path('.Build/coverage/unit-Audit.cov');part.parent.mkdir(parents=True,exist_ok=True);part.write_text('original nonempty partial coverage')\n"
                      "pathlib.Path('heartbeat').write_text('ready')\n"
                      + ("while True:\n pathlib.Path('heartbeat').write_text(str(time.monotonic_ns()))\n time.sleep(0.01)\n"
                         if mode != "green" else ""))
            (root / "offline-worker.py").write_text(worker)
            fake = root / "offline-helper.py"
            fake.write_text("import os,pathlib,signal,subprocess,sys,time\n"
                            "child=subprocess.Popen([sys.executable,'offline-worker.py'," + repr(marker) + "],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                            "deadline=time.monotonic()+3\n"
                            "while not pathlib.Path('heartbeat').exists():\n"
                            " if time.monotonic()>deadline: raise RuntimeError('Owned child did not start')\n"
                            " time.sleep(0.005)\n"
                            + ("child.wait(timeout=3)\n" if mode == "green" else "") +
                            "sys.stdout.write(" + repr(output) + ");sys.stdout.flush()\n"
                            + ("while True: time.sleep(0.1)\n" if mode == "timeout" else
                               "os.kill(os.getpid(),signal.SIGKILL)\n" if mode == "killed" else ""))
            previous = Path.cwd()
            inspector = PILOT.load(application_helper, "real_group_inspector")
            try:
                os.chdir(root)
                base = root / ".Build/coverage-exit-pilot"
                PILOT.write(base / "before.json", {})
                with patch.object(PILOT, "BASE", base), patch.object(PILOT, "CACHE", root / ".phpunit.cache"), \
                        patch.object(PILOT, "snapshot", return_value={}), \
                        patch.object(PILOT, "memory_events", return_value={"oom": 0, "oom_kill": 0, "oom_group_kill": 0}), \
                        patch.object(PILOT, "helper", side_effect=lambda phase: fake if phase == "old" else application_helper), \
                        patch.object(PILOT, "HELPER_TIMEOUT_SECONDS", 1 if mode == "timeout" else 1840, create=True), \
                        patch.object(PILOT, "GROUP_CLEANUP_SECONDS", 0.15, create=True), redirect_stdout(io.StringIO()):
                    if not kill_confirmed:
                        with patch.object(PILOT.os, "killpg"):
                            with self.assertRaises(ValueError):
                                PILOT.run_phase("old")
                    elif mode == "green":
                        PILOT.run_phase("old")
                    else:
                        with self.assertRaises(ValueError):
                            PILOT.run_phase("old")
                    group = int((root / "group.pid").read_text())
                    self.assertEqual(inspector.group_is_running(group), not kill_confirmed)
                    heartbeat = (root / "heartbeat").read_text()
                    time.sleep(0.06)
                    self.assertEqual(heartbeat == (root / "heartbeat").read_text(), kill_confirmed)
                    self.assertEqual((base / "old/unit-Audit.cov").read_text(), "original nonempty partial coverage")
                    result = PILOT.read(base / "old/result.json")
                    self.assertEqual(result["helper_returncode"], 0 if mode == "green" else -signal.SIGKILL)
                    self.assertEqual(result["containment"]["confirmed"], kill_confirmed)
                    self.assertFalse((base / "old/accepted.json").exists())
                    if mode != "green":
                        with patch.object(PILOT.subprocess, "Popen", side_effect=AssertionError("Next arm launched")) as launch:
                            with self.assertRaises(OSError):
                                PILOT.run_phase("new")
                            launch.assert_not_called()
                        self.assertFalse((base / "new").exists())
                    if mode == "timeout":
                        self.assertTrue(result["outer_timed_out"])
            finally:
                pidfile = root / "group.pid"
                if pidfile.exists():
                    group = int(pidfile.read_text())
                    command = Path("/proc/%d/cmdline" % group)
                    if command.exists() and marker.encode() in command.read_bytes():
                        try:
                            os.killpg(group, signal.SIGKILL)
                        except ProcessLookupError:
                            pass  # The uniquely owned fixture group already exited.
                    deadline = time.monotonic() + 3
                    while inspector.group_is_running(group):
                        self.assertLess(time.monotonic(), deadline, "Owned fixture group did not stop")
                        time.sleep(0.01)
                os.chdir(previous)

    def test_abrupt_helper_exit_contains_real_child_before_any_outcome_parsing(self):
        outcome = 'Coverage shard result: {"shard":"Audit","returncode":0}\n'
        for name, output in (("missing", ""), ("malformed", "Coverage shard result: invalid-json\n"),
                             ("duplicate", outcome + outcome), ("one", outcome)):
            with self.subTest(output=name):
                self.real_helper_exit(output)

    def test_valid_helper_outcome_without_live_child_remains_green(self):
        self.real_helper_exit('Coverage shard result: {"shard":"Audit","returncode":0}\n', mode="green")

    def test_unconfirmed_real_child_cleanup_stays_red_and_blocks_next_arm(self):
        self.real_helper_exit('Coverage shard result: {"shard":"Audit","returncode":0}\n', kill_confirmed=False)

    def test_outer_timeout_contains_both_real_process_groups(self):
        self.real_helper_exit('Coverage shard result: {"shard":"Audit","returncode":0}\n', mode="timeout")

    def test_new_phase_preflight_blocks_before_any_launch_on_unaccepted_old_result(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(PILOT, "BASE", Path(directory)), \
                patch.object(PILOT, "CACHE", Path(directory) / "cache"), \
                patch.object(PILOT, "snapshot", return_value={}), patch.object(PILOT, "memory_events", return_value={}), \
                patch.object(PILOT, "helper", return_value=Path("unused-reviewed-helper")), \
                patch.object(PILOT, "load", return_value=Mock()), \
                patch.object(PILOT.subprocess, "Popen", side_effect=AssertionError("Expensive phase was launched")) as launch:
            PILOT.write(PILOT.BASE / "before.json", {})
            PILOT.write(PILOT.BASE / "between.json", {})
            with self.assertRaises(OSError):
                PILOT.run_phase("new")
            launch.assert_not_called()

    def test_source_runtime_or_package_drift_blocks(self):
        state = {"source": "same", "runtime": {"php": "8.5.12"}, "dependencies": {"ref": "same"}}
        PILOT.same_state(state, copy.deepcopy(state))
        for key in state:
            other = copy.deepcopy(state)
            other[key] = "changed"
            with self.subTest(key=key), self.assertRaises(ValueError):
                PILOT.same_state(state, other)

    def test_new_phase_cannot_start_without_accepted_unchanged_old_receipt(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(PILOT, "BASE", Path(directory)):
            with self.assertRaises(OSError):
                PILOT.accepted("old")
            PILOT.write(PILOT.BASE / "old/result.json", {"accepted": True})
            PILOT.write(PILOT.BASE / "old/accepted.json", {"result_sha256": "wrong"})
            with self.assertRaises(ValueError):
                PILOT.accepted("old")

    def test_receipt_rejects_missing_part_set_even_with_valid_result_hash(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(PILOT, "BASE", Path(directory)):
            result = PILOT.BASE / "old/result.json"
            PILOT.write(result, {})
            PILOT.write(PILOT.BASE / "old/accepted.json", {"accepted": True,
                        "result_sha256": PILOT.digest(result.read_bytes()), "files": {}})
            with self.assertRaises(ValueError):
                PILOT.accepted("old")


if __name__ == "__main__":
    unittest.main()
