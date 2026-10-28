#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Offline controls for current-source evidence and failed-gate-only recovery."""

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET

SCRIPT = Path(__file__).with_name("verify-release-preservation-pilot.py")
SHA = "a" * 40
AUDIT = "Netresearch\\NrVault\\Tests\\Unit\\Audit\\ExampleTest"
IDS = [AUDIT + "::first", AUDIT + "::second#row"]
IDS_DIGEST = hashlib.sha256((json.dumps(sorted(IDS), ensure_ascii=False, separators=(",", ":")) + "\n").encode()).hexdigest()


class PilotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bundle = self.root / ("release-evidence-precheck-" + SHA[:12] + ".tar.gz")
        self.junit = ET.Element("testsuites")
        suite = ET.SubElement(self.junit, "testsuite", tests="3", errors="0", failures="0", skipped="0")
        ET.SubElement(suite, "testcase", {"class": AUDIT, "name": "first"})
        ET.SubElement(suite, "testcase", {"class": AUDIT, "name": 'second with data set "row"'})
        ET.SubElement(suite, "testcase", {"class": "Netresearch\\NrVault\\Tests\\Unit\\OtherTest", "name": "other"})
        self.manifest = {"schemaVersion": 1, "extension": "nr_vault", "commit": SHA,
                         "checks": [{"id": "release-identity", "status": "warn"}]}
        self.write_bundle()

    def write_bundle(self, omit_junit=False, wrong_raw_digest=False):
        data = ET.tostring(self.junit)
        self.manifest["artifacts"] = [{"name": "junit-unit.xml", "path": "artifacts/junit-unit.xml",
                                      "sha256": "0" * 64 if wrong_raw_digest else hashlib.sha256(data).hexdigest()}]
        files = {"./evidence-manifest.json": json.dumps(self.manifest).encode()}
        if not omit_junit:
            files["./artifacts/junit-unit.xml"] = data
        with tarfile.open(self.bundle, "w:gz") as archive:
            for name, content in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()

    def run_pilot(self, attempt=2, actual=SHA, digest=None, directory=None,
                  identity=SHA, artifact="release-evidence-precheck-" + SHA[:12],
                  count=2, audit_digest=IDS_DIGEST, outputs_only=False):
        command = [sys.executable, str(SCRIPT), "--expected", SHA, "--actual", actual,
                   "--identity", identity, "--artifact", artifact,
                   "--digest", self.digest if digest is None else digest,
                   "--directory", str(directory or self.root), "--attempt", str(attempt),
                   "--run-id", "123", "--audit-count", str(count), "--audit-digest", audit_digest]
        if outputs_only:
            command.append("--outputs-only")
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_first_attempt_fails_only_after_verified_current_inventory_receipt(self):
        result = self.run_pilot(attempt=1)
        self.assertEqual(result.returncode, 42, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["digest"], self.digest)
        self.assertEqual(receipt["actual_commit"], SHA)
        self.assertEqual(receipt["audit_cases"], 2)
        self.assertEqual(receipt["audit_digest"], IDS_DIGEST)

    def test_retry_verifies_same_outputs_bundle_and_current_inventory(self):
        self.assertEqual(self.run_pilot().returncode, 0)

    def test_lost_outputs_never_download_all_or_become_intentional_failure(self):
        for outputs_only in (False, True):
            for attempt in (1, 2):
                for changes in ({"actual": ""}, {"identity": ""}, {"artifact": ""}, {"digest": ""}):
                    with self.subTest(attempt=attempt, changes=changes, outputs_only=outputs_only):
                        result = self.run_pilot(attempt=attempt, outputs_only=outputs_only, **changes)
                        self.assertEqual(result.returncode, 1)
                        self.assertEqual(result.stdout, "")

    def test_metadata_preflight_is_not_the_full_verified_receipt(self):
        result = self.run_pilot(outputs_only=True, attempt=1, directory=self.root / "not-downloaded")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_absent_expired_or_digest_mismatched_artifact_blocks(self):
        for changes in ({"directory": self.root / "expired"}, {"digest": "0" * 64}):
            result = self.run_pilot(**changes)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")

    def test_required_raw_junit_and_manifest_digest_must_match(self):
        for flags in ({"omit_junit": True}, {"wrong_raw_digest": True}):
            self.write_bundle(**flags)
            result = self.run_pilot(attempt=1)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")

    def test_current_inventory_cannot_be_replaced_with_historical_count_or_hash(self):
        for change in ({"count": 626}, {"count": 0}, {"audit_digest": "0" * 64}):
            self.assertEqual(self.run_pilot(**change).returncode, 1)

    def test_missing_duplicate_foreign_or_skipped_audit_case_blocks(self):
        for change in ("missing", "duplicate", "foreign", "skipped"):
            with self.subTest(change=change):
                old = ET.tostring(self.junit)
                suite = self.junit.find("testsuite")
                case = suite.findall("testcase")[1]
                if change == "missing":
                    suite.remove(case)
                elif change == "duplicate":
                    case.set("name", "first")
                elif change == "foreign":
                    case.set("class", "ForeignAuditCase")
                else:
                    ET.SubElement(case, "skipped")
                self.write_bundle()
                result = self.run_pilot(attempt=1)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.junit = ET.fromstring(old)

    def test_pilot_must_remain_untagged_and_exact_source(self):
        for change in ({"commit": "b" * 40}, {"extension": "other"}, {"schemaVersion": 2},
                       {"checks": [{"id": "release-identity", "status": "pass"}]}):
            with self.subTest(change=change):
                saved = self.manifest.copy()
                self.manifest.update(change)
                self.write_bundle()
                self.assertEqual(self.run_pilot().returncode, 1)
                self.manifest = saved


if __name__ == "__main__":
    unittest.main()
