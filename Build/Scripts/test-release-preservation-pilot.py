#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Offline fail-closed checks for the temporary native preservation pilot."""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("verify-release-preservation-pilot.py")
SHA = "a" * 40


class PilotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bundle = self.root / ("release-evidence-precheck-" + SHA[:12] + ".tar.gz")
        data = json.dumps({"schemaVersion": 1, "commit": SHA,
                           "checks": [{"id": "release-identity", "status": "warn"}]}).encode()
        with tarfile.open(self.bundle, "w:gz") as archive:
            member = tarfile.TarInfo("./evidence-manifest.json")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()

    def run_pilot(self, attempt=2, actual=SHA, digest=None, directory=None,
                  identity=SHA, artifact="release-evidence-precheck-" + SHA[:12]):
        return subprocess.run([sys.executable, str(SCRIPT), "--expected", SHA,
                               "--actual", actual, "--identity", identity,
                               "--artifact", artifact,
                               "--digest", self.digest if digest is None else digest,
                               "--directory", str(directory or self.root),
                               "--attempt", str(attempt), "--run-id", "123"],
                              capture_output=True, text=True, check=False)

    def test_first_attempt_fails_only_after_writing_verified_receipt(self):
        result = self.run_pilot(attempt=1)
        self.assertEqual(result.returncode, 42, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["digest"], self.digest)
        self.assertEqual(receipt["actual_commit"], SHA)

    def test_retry_verifies_same_outputs_and_artifact(self):
        self.assertEqual(self.run_pilot().returncode, 0)

    def test_lost_output_does_not_become_intentional_failure_or_success(self):
        for attempt in (1, 2):
            for changes in ({"actual": ""}, {"identity": ""}, {"artifact": ""},
                            {"digest": ""}, {"digest": "0" * 64}):
                with self.subTest(attempt=attempt, changes=changes):
                    result = self.run_pilot(attempt=attempt, **changes)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")

    def test_absent_or_expired_artifact_blocks(self):
        self.assertEqual(self.run_pilot(directory=self.root / "missing-artifact").returncode, 1)


if __name__ == "__main__":
    unittest.main()
