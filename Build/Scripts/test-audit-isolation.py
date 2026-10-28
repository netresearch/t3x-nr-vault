#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Offline negative controls for the temporary native Audit oracle."""

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

SPEC = importlib.util.spec_from_file_location("audit_oracle", Path(__file__).with_name("verify-audit-isolation.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AuditOracleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "report.xml"
        self.ids = {"Example\\AuditTest::first", "Example\\AuditTest::second#entry/Error/1"}
        self.files = ["Audit/Foo.php"]
        self.measured = {
            "files": self.files, "tests": {name: {"status": "success"} for name in self.ids},
            "branches": 118, "paths": 81, "hitBranches": 90, "hitPaths": 4,
            "build": {"runtime": {"version": "8.5.12"}, "phpCodeCoverage": {
                "version": "14.4.1", "serializationFormat": 4,
                "driverInformation": {"name": "Xdebug", "version": "3.5.3"}}}}

    def write_junit(self):
        root = ET.Element("testsuites")
        suite = ET.SubElement(root, "testsuite", tests="2", errors="0", failures="0", skipped="0", assertions="10")
        ET.SubElement(suite, "testcase", {"class": "Example\\AuditTest", "name": "first"})
        ET.SubElement(suite, "testcase", {"class": "Example\\AuditTest", "name": 'second with data set "entry/Error/1"'})
        ET.ElementTree(root).write(self.path)
        return root

    def test_complete_junit_and_coverage_pass(self):
        self.write_junit()
        self.assertEqual(MODULE.junit(self.path, self.ids)["cases"], 2)
        MODULE.coverage(self.measured, self.ids, 1, MODULE.fingerprint(self.files))

    def test_inventory_count_identity_and_uniqueness_are_bound(self):
        root = ET.Element(MODULE.NAMESPACE + "testSuite")
        tests = ET.SubElement(root, MODULE.NAMESPACE + "tests")
        case = ET.SubElement(tests, MODULE.NAMESPACE + "testClass")
        nodes = [ET.SubElement(case, MODULE.NAMESPACE + "testMethod", id=name) for name in sorted(self.ids)]
        ET.ElementTree(root).write(self.path)
        digest = MODULE.fingerprint(sorted(self.ids))
        self.assertEqual(MODULE.inventory(self.path, 2, digest), self.ids)
        nodes[1].set("id", nodes[0].get("id"))
        ET.ElementTree(root).write(self.path)
        with self.assertRaises(ValueError):
            MODULE.inventory(self.path, 2, digest)
        with self.assertRaises(ValueError):
            MODULE.inventory(self.path, 626, digest)

    def test_missing_duplicate_or_wrong_junit_case_blocks_even_if_total_claims_two(self):
        for change in ("missing", "duplicate", "foreign"):
            with self.subTest(change=change):
                root = self.write_junit()
                suite = root.find("testsuite")
                case = suite.findall("testcase")[1]
                if change == "missing":
                    suite.remove(case)
                elif change == "duplicate":
                    case.set("name", "first")
                else:
                    case.set("class", "ForeignCase")
                ET.ElementTree(root).write(self.path)
                with self.assertRaises(ValueError):
                    MODULE.junit(self.path, self.ids)

    def test_failed_skipped_or_missing_junit_aggregate_blocks(self):
        for field in ("errors", "failures", "skipped", "tests"):
            with self.subTest(field=field):
                root = self.write_junit()
                root.find("testsuite").set(field, "1")
                ET.ElementTree(root).write(self.path)
                with self.assertRaises(ValueError):
                    MODULE.junit(self.path, self.ids)
        for tag in ("error", "failure", "skipped"):
            root = self.write_junit()
            ET.SubElement(root.find(".//testcase"), tag)
            ET.ElementTree(root).write(self.path)
            with self.assertRaises(ValueError):
                MODULE.junit(self.path, self.ids)

    def test_numeric_dataset_identity_remains_exact(self):
        root = self.write_junit()
        root.findall(".//testcase")[1].set("name", "second with data set #0")
        ET.ElementTree(root).write(self.path)
        MODULE.junit(self.path, {"Example\\AuditTest::first", "Example\\AuditTest::second#0"})

    def test_missing_coverage_paths_scope_case_or_success_record_blocks(self):
        for mutate in (lambda data: data.update(paths=0), lambda data: data.update(hitPaths=0),
                       lambda data: data.update(files=["Foreign.php"]),
                       lambda data: data["tests"].pop(next(iter(self.ids))),
                       lambda data: data["tests"][next(iter(self.ids))].update(status="failure"),
                       lambda data: data["build"]["phpCodeCoverage"]["driverInformation"].update(version="3.5.2"),
                       lambda data: data["build"]["runtime"].update(version="8.5.11")):
            with self.subTest(mutate=mutate):
                data = copy.deepcopy(self.measured)
                mutate(data)
                with self.assertRaises(ValueError):
                    MODULE.coverage(data, self.ids, 1, MODULE.fingerprint(self.files))

    def test_dependency_versions_cannot_drift(self):
        data = {"installed": [{"name": "phpunit/phpunit", "version": "13.4.5"}]}
        digest = MODULE.fingerprint(data["installed"])
        MODULE.dependencies(data, digest)
        data["installed"][0]["version"] = "13.3.2"
        with self.assertRaises(ValueError):
            MODULE.dependencies(data, digest)

    def test_malformed_xml_is_not_accepted(self):
        self.path.write_text("<broken>")
        with self.assertRaises(ET.ParseError):
            MODULE.junit(self.path, self.ids)


if __name__ == "__main__":
    unittest.main()
