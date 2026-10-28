#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Offline contracts for release coverage scheduling and failure containment."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
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

    def test_fewer_shards_never_create_empty_workers(self):
        for count in range(1, 4):
            self.shard("Suite%d" % count)
            self.assertEqual(len(self.plan()["workers"]), count)

    def test_empty_selection_fails(self):
        self.assertNotEqual(self.call("plan").returncode, 0)

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


if __name__ == "__main__":
    unittest.main()
