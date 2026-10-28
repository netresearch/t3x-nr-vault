#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Offline contracts for release coverage scheduling and failure containment."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).with_name("release-coverage.py")


class CoverageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.unit = self.root / "Tests/Unit"
        self.unit.mkdir(parents=True)

    def shard(self, name):
        target = self.unit / ("RootTest.php" if name == "__root" else name + "/Nested/CaseTest.php")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("<?php", encoding="utf-8")

    def call(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=self.root,
                              capture_output=True, text=True, check=False)

    def plan(self):
        result = self.call("plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_discovery_covers_root_new_and_nested_tests_but_not_helpers(self):
        for name in ("Audit", "NewDirectory", "__root"):
            self.shard(name)
        (self.unit / "Fixtures").mkdir()
        (self.unit / "Fixtures/Helper.php").write_text("<?php", encoding="utf-8")
        plan = self.plan()
        self.assertEqual(plan["shards"], ["Audit", "NewDirectory", "__root"])
        assigned = [name for group in plan["workers"] for name in group["shards"]]
        self.assertCountEqual(assigned, plan["shards"])
        self.assertEqual(len(assigned), len(set(assigned)))

    def test_twenty_seven_shards_use_four_nonempty_deterministic_workers(self):
        for index in range(27):
            self.shard("Suite%02d" % index)
        plan = self.plan()
        self.assertEqual(len(plan["workers"]), 4)
        self.assertTrue(all(group["shards"] for group in plan["workers"]))
        self.assertEqual(plan, self.plan())
        self.assertEqual(sum(len(group["shards"]) for group in plan["workers"]), 27)
        self.assertTrue(all(group["timeout"] == len(group["shards"]) * 30 + 10
                            and group["timeout"] <= 360 for group in plan["workers"]))

    def test_fewer_shards_never_create_empty_workers(self):
        for count in range(1, 4):
            self.shard("Suite%d" % count)
            self.assertEqual(len(self.plan()["workers"]), count)

    def test_empty_selection_fails(self):
        self.assertNotEqual(self.call("plan").returncode, 0)

    def test_fixture_directory_with_real_tests_is_not_excluded_by_name(self):
        self.shard("Fixtures")
        self.assertEqual(self.plan()["shards"], ["Fixtures"])

    def test_worker_keeps_later_diagnostics_after_middle_shard_failure(self):
        for name in ("First", "Broken", "__root"):
            self.shard(name)
        fake = self.root / "phpunit"
        fake.write_text("#!/usr/bin/env python3\nimport pathlib,sys\n"
                        "args=sys.argv[1:]\n"
                        "with open('executed','a') as f: f.write(args[-1]+'\\n')\n"
                        "if 'Broken' in args[-1]: sys.exit(1)\n"
                        "out=next(a.split('=',1)[1] for a in args if a.startswith('--coverage-php='))\n"
                        "pathlib.Path(out).write_text('coverage')\n", encoding="utf-8")
        fake.chmod(0o755)
        result = self.call("worker", "--shards", '["First","Broken","__root"]',
                           "--phpunit", str(fake))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "executed").read_text().splitlines(),
                         ["Tests/Unit/First", "Tests/Unit/Broken", "Tests/Unit/RootTest.php"])
        self.assertTrue((self.root / ".Build/coverage/unit-First.cov").is_file())
        self.assertTrue((self.root / ".Build/coverage/unit-__root.cov").is_file())

    def test_worker_rejects_duplicates_unknown_shards_and_path_traversal(self):
        self.shard("Good")
        for names in ('["Good","Good"]', '["Missing"]', '["../outside"]', '[]'):
            with self.subTest(names=names):
                self.assertNotEqual(self.call("worker", "--shards", names).returncode, 0)

    def test_root_targets_exclude_symlinks_and_directories_named_like_tests(self):
        self.shard("__root")
        (self.unit / "LinkedTest.php").symlink_to(self.unit / "RootTest.php")
        (self.unit / "DirectoryTest.php").mkdir()
        fake = self.root / "phpunit"
        fake.write_text("#!/usr/bin/env python3\nimport pathlib,sys\n"
                        "pathlib.Path('targets').write_text('\\n'.join(sys.argv[1:]))\n"
                        "out=next(a.split('=',1)[1] for a in sys.argv if a.startswith('--coverage-php='))\n"
                        "pathlib.Path(out).write_text('coverage')\n", encoding="utf-8")
        fake.chmod(0o755)
        result = self.call("worker", "--shards", '["__root"]', "--phpunit", str(fake))
        self.assertEqual(result.returncode, 0, result.stderr)
        targets = (self.root / "targets").read_text()
        self.assertIn("Tests/Unit/RootTest.php", targets)
        self.assertNotIn("LinkedTest.php", targets)
        self.assertNotIn("DirectoryTest.php", targets)

    def test_timed_out_shard_does_not_stop_later_parts(self):
        self.shard("Slow")
        self.shard("Later")
        fake = self.root / "phpunit"
        fake.write_text("#!/usr/bin/env python3\nimport pathlib,sys,time\n"
                        "if 'Slow' in sys.argv[-1]: time.sleep(2)\n"
                        "out=next(a.split('=',1)[1] for a in sys.argv if a.startswith('--coverage-php='))\n"
                        "pathlib.Path(out).write_text('coverage')\n", encoding="utf-8")
        fake.chmod(0o755)
        result = self.call("worker", "--shards", '["Slow","Later"]',
                           "--phpunit", str(fake), "--timeout-seconds", "0.2")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.root / ".Build/coverage/unit-Later.cov").is_file())
        outcomes = [json.loads(line.removeprefix("Coverage shard result: "))
                    for line in result.stdout.splitlines() if line.startswith("Coverage shard result: ")]
        self.assertEqual([item["shard"] for item in outcomes], ["Slow", "Later"])
        self.assertTrue(outcomes[0]["timed_out"])
        self.assertEqual(outcomes[0]["returncode"], -signal.SIGKILL)
        self.assertEqual(outcomes[0]["signal"], "SIGKILL")
        self.assertEqual(outcomes[1]["returncode"], 0)

    def test_worker_reports_actual_exit_code_and_signal_then_keeps_later_parts(self):
        for name in ("Signal", "Exit", "Later"):
            self.shard(name)
        fake = self.root / "phpunit"
        fake.write_text("#!/usr/bin/env python3\nimport os,pathlib,resource,signal,sys\n"
                        "resource.setrlimit(resource.RLIMIT_CORE,(0,0))\n"
                        "if 'Signal' in sys.argv[-1]: os.kill(os.getpid(),signal.SIGSEGV)\n"
                        "if 'Exit' in sys.argv[-1]: sys.exit(7)\n"
                        "out=next(a.split('=',1)[1] for a in sys.argv if a.startswith('--coverage-php='))\n"
                        "pathlib.Path(out).write_text('coverage')\n", encoding="utf-8")
        fake.chmod(0o755)
        result = self.call("worker", "--shards", '["Signal","Exit","Later"]',
                           "--phpunit", str(fake))
        self.assertEqual(result.returncode, 1, result.stderr)
        outcomes = [json.loads(line.removeprefix("Coverage shard result: "))
                    for line in result.stdout.splitlines() if line.startswith("Coverage shard result: ")]
        self.assertEqual([item["shard"] for item in outcomes], ["Signal", "Exit", "Later"])
        self.assertEqual([item["returncode"] for item in outcomes], [-11, 7, 0])
        self.assertEqual([item["signal"] for item in outcomes], ["SIGSEGV", None, None])
        self.assertEqual([item["coverage_part_nonempty"] for item in outcomes], [False, False, True])
        self.assertTrue(all(not item["timed_out"] and item["launcher_error"] is None for item in outcomes))
        self.assertTrue((self.root / ".Build/coverage/unit-Later.cov").is_file())

    def test_only_audit_adds_per_test_isolation_and_retains_all_original_targets(self):
        for name in ("Audit", "Other", "__root"):
            self.shard(name)
        fake = self.root / "phpunit"
        fake.write_text("#!/usr/bin/env python3\nimport json,pathlib,sys\n"
                        "with open('arguments','a') as stream: stream.write(json.dumps(sys.argv[1:])+'\\n')\n"
                        "out=next(a.split('=',1)[1] for a in sys.argv if a.startswith('--coverage-php='))\n"
                        "pathlib.Path(out).write_text('coverage')\n", encoding="utf-8")
        fake.chmod(0o755)
        result = self.call("worker", "--shards", '["Audit","Other","__root"]', "--phpunit", str(fake))
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = [json.loads(line) for line in (self.root / "arguments").read_text().splitlines()]
        for index, target in enumerate(("Tests/Unit/Audit", "Tests/Unit/Other", "Tests/Unit/RootTest.php")):
            expected = ["-c", "Build/phpunit.xml", "--path-coverage",
                        "--coverage-php=" + str(self.root / ".Build/coverage" / ("unit-" + ("Audit", "Other", "__root")[index] + ".cov"))]
            if index == 0:
                expected.append("--process-isolation")
            self.assertEqual(arguments[index], expected + [target])

    def test_timeout_kills_real_ignoring_child_before_later_shard_runs(self):
        self.shard("Slow")
        self.shard("Later")
        marker = "coverage-timeout-child-" + self.root.name
        child = ("import os,pathlib,signal,time\n"
                 "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                 "pathlib.Path('child.pid').write_text(str(os.getpid()))\n"
                 "pathlib.Path('child.ready').write_text('ready')\n"
                 "while True:\n"
                 " pathlib.Path('heartbeat').write_text(str(time.monotonic_ns()))\n"
                 " time.sleep(0.02)\n")
        fake = self.root / "phpunit"
        fake.write_text("#!/usr/bin/env python3\nimport pathlib,subprocess,sys,time\n"
                        "if 'Slow' in sys.argv[-1]:\n"
                        " subprocess.Popen([sys.executable,'-c'," + repr(child) + "," + repr(marker) + "],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                        " while not pathlib.Path('child.ready').exists(): time.sleep(0.005)\n"
                        " while True: time.sleep(1)\n"
                        "status=pathlib.Path('/proc/'+pathlib.Path('child.pid').read_text()+'/stat')\n"
                        "if status.exists() and status.read_text().split(') ',1)[1].split()[0] not in ('Z','X'): pathlib.Path('child-overlapped-later').write_text('alive')\n"
                        "out=next(a.split('=',1)[1] for a in sys.argv if a.startswith('--coverage-php='))\n"
                        "pathlib.Path(out).write_text('coverage')\n", encoding="utf-8")
        fake.chmod(0o755)

        def stop_owned_child():
            pidfile = self.root / "child.pid"
            if pidfile.exists():
                pid = int(pidfile.read_text())
                command = Path("/proc/%d/cmdline" % pid)
                if command.exists() and marker.encode() in command.read_bytes():
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

        self.addCleanup(stop_owned_child)
        result = self.call("worker", "--shards", '["Slow","Later"]', "--phpunit", str(fake),
                           "--timeout-seconds", "0.5")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue((self.root / "child.ready").is_file(), "Real descendant must start before timeout")
        pid = int((self.root / "child.pid").read_text())
        status = Path("/proc/%d/stat" % pid)
        if status.exists():
            self.assertIn(status.read_text().split(") ", 1)[1].split()[0], ("Z", "X"), "Descendant remains runnable after timeout")
        before = (self.root / "heartbeat").read_text()
        time.sleep(0.1)
        self.assertEqual((self.root / "heartbeat").read_text(), before, "Timed-out descendant keeps executing")
        self.assertFalse((self.root / "child-overlapped-later").exists(), "Descendant overlaps the next shard")
        self.assertTrue((self.root / ".Build/coverage/unit-Later.cov").is_file())
        outcomes = [json.loads(line.removeprefix("Coverage shard result: "))
                    for line in result.stdout.splitlines() if line.startswith("Coverage shard result: ")]
        self.assertTrue(outcomes[0]["timed_out"])
        self.assertEqual(outcomes[0]["returncode"], -signal.SIGKILL)
        self.assertEqual(outcomes[0]["signal"], "SIGKILL")
        self.assertEqual(outcomes[1]["returncode"], 0)


if __name__ == "__main__":
    unittest.main()
