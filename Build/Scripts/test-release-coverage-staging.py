#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Execute the workflow's coverage staging shell against producer outcomes."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release-evidence.yml"


def coverage_step(name):
    """Read one literal shell step in coverage-merge without a YAML dependency."""
    lines = WORKFLOW.read_text().splitlines()
    job_start = lines.index("  coverage-merge:") + 1
    job_end = next((index for index in range(job_start, len(lines))
                    if re.fullmatch(r"  [a-z][a-z0-9-]*:", lines[index])), len(lines))
    job = lines[job_start:job_end]
    starts = [index for index, line in enumerate(job)
              if line == "      - name: " + name]
    if len(starts) != 1:
        raise ValueError("Expected exactly one named coverage-merge step: " + name)
    start = starts[0]
    end = next((index for index in range(start + 1, len(job))
                if job[index].startswith("      - ")), len(job))
    step = job[start:end]
    run = step.index("        run: |")
    bindings = {}
    if "        env:" in step[:run]:
        env = step.index("        env:")
        for line in step[env + 1:run]:
            match = re.fullmatch(r"          ([A-Z_]+): (.+)", line)
            if match is None or match[1] in bindings:
                raise ValueError("Unsupported or duplicate staging environment binding")
            bindings[match[1]] = match[2]
    shell_lines = []
    for line in step[run + 1:]:
        if not line:
            shell_lines.append("")
        elif line.startswith("          "):
            shell_lines.append(line[10:])
        elif line.lstrip().startswith("#"):
            break
        else:
            raise ValueError("Expected a literal inline shell block")
    return bindings, "\n".join(shell_lines) + "\n"


class CoverageStagingTest(unittest.TestCase):
    def run_step(self, name="Stage coverage artifacts", **outcomes):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        coverage = directory / ".Build/coverage"
        coverage.mkdir(parents=True)
        reports = {"clover.xml": "<coverage>original report</coverage>\n",
                   "coverage-text.txt": "original coverage metrics\n"}
        for report, content in reports.items():
            (coverage / report).write_text(content)
        environment = dict(os.environ)
        environment.update(PLAN="success", UNIT="success", FUNCTIONAL="success",
                           COMPLETE="true", MERGE="success", SUPPORTED="true", MISSING="")
        environment.update(outcomes)
        _, shell = coverage_step(name)
        result = subprocess.run(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", shell],
                                cwd=directory, env=environment, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual({report: (coverage / report).read_text() for report in reports}, reports,
                         "Staging must preserve the original diagnostic reports")
        staged = {path.name: path.read_text() for path in (directory / "stage").glob("*")}
        return result, staged, reports

    def test_actual_staging_environment_binds_producer_and_merge_results(self):
        bindings, _ = coverage_step("Stage coverage artifacts")
        self.assertEqual(bindings, {
            "PLAN": "${{ needs.coverage-plan.result }}",
            "UNIT": "${{ needs.coverage-unit.result }}",
            "FUNCTIONAL": "${{ needs.coverage-functional.result }}",
            "COMPLETE": "${{ steps.parts.outputs.complete }}",
            "MERGE": "${{ steps.merge.outcome }}",
        })

    def test_complete_success_stages_both_original_reports(self):
        result, staged, reports = self.run_step()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(staged, reports)

    def test_failed_or_missing_producer_result_stages_nothing(self):
        for producer in ("UNIT", "FUNCTIONAL"):
            for outcome in ("failure", "cancelled", "skipped", ""):
                with self.subTest(producer=producer, outcome=outcome):
                    result, staged, _ = self.run_step(**{producer: outcome})
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(staged, {}, "Unsuccessful producer output must remain diagnostic only")

    def test_failed_or_missing_plan_or_merge_stages_nothing(self):
        for producer in ("PLAN", "MERGE"):
            for outcome in ("failure", "cancelled", "skipped", ""):
                with self.subTest(producer=producer, outcome=outcome):
                    result, staged, _ = self.run_step(**{producer: outcome})
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(staged, {})

    def test_incomplete_or_missing_part_set_stages_nothing(self):
        for complete in ("false", "", "TRUE"):
            with self.subTest(complete=complete):
                result, staged, _ = self.run_step(COMPLETE=complete)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(staged, {})

    def test_historical_unsupported_release_stages_nothing_and_stays_supported(self):
        outcomes = {"SUPPORTED": "false", "UNIT": "skipped", "FUNCTIONAL": "skipped",
                    "COMPLETE": "", "MERGE": "skipped"}
        result, staged, _ = self.run_step(**outcomes)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(staged, {})
        result, _, _ = self.run_step("Report coverage outcome", **outcomes)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_failed_producer_still_fails_the_actual_final_gate(self):
        for producer in ("UNIT", "FUNCTIONAL"):
            with self.subTest(producer=producer):
                result, _, _ = self.run_step("Report coverage outcome", **{producer: "failure"})
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
