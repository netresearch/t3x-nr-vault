#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Release identity and latest-run policy fixtures; no network or publisher."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("verify_release", Path(__file__).with_name("verify-release.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REPO = "netresearch/t3x-nr-vault"
COMMIT = "a" * 40
TAG = "v1.2.3"


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bundle = Path(self.tmp.name) / "release-evidence-1.2.3.tar.gz"
        identity = {"id": 1124, "full_name": REPO}
        self.api_data = {
            "repos/" + REPO: dict(identity, default_branch="main"),
            "repos/" + REPO + "/git/ref/tags/" + TAG: {
                "ref": "refs/tags/" + TAG, "object": {"type": "tag", "sha": "b" * 40}},
            "repos/" + REPO + "/git/tags/" + "b" * 40: {
                "tag": TAG, "object": {"type": "commit", "sha": COMMIT},
                "verification": {"verified": True, "reason": "valid"}},
            "repos/" + REPO + "/compare/" + COMMIT + "...main": {
                "status": "ahead", "base_commit": {"sha": COMMIT}},
        }
        self.run_keys = []
        for index, workflow in enumerate(MODULE.REQUIRED_WORKFLOWS):
            self.api_data["repos/" + REPO + "/actions/workflows/" + workflow] = {
                "id": index + 1, "path": ".github/workflows/" + workflow, "state": "active"}
            key = "repos/" + REPO + "/actions/workflows/%d/runs?head_sha=%s&per_page=100" % (index + 1, COMMIT)
            self.run_keys.append(key)
            self.api_data[key] = [{"total_count": 1, "workflow_runs": [{
                "id": index + 100, "workflow_id": index + 1,
                # The REST workflow-run example includes its definition ref;
                # workflow metadata itself still uses the canonical file path.
                "path": ".github/workflows/" + workflow + "@main",
                "head_sha": COMMIT, "head_branch": "main", "event": "push",
                "repository": identity, "head_repository": identity,
                "created_at": "2026-10-28T00:00:00Z", "run_started_at": "2026-10-28T00:00:00Z",
                "run_attempt": 1, "status": "completed", "conclusion": "success"}]}]
        self.manifest = {"schemaVersion": 1, "extension": "nr_vault", "version": "1.2.3",
                         "commit": COMMIT, "checks": [{"id": name, "status": "pass"}
                         for name in MODULE.REQUIRED_CHECKS], "artifacts": []}
        self.parts = {name: b"report" for name in MODULE.REQUIRED_PARTS}
        self.write_bundle()

    def write_bundle(self, corrupt_raw=False, duplicate_manifest=False):
        self.manifest["artifacts"] = [{"name": name, "path": "artifacts/" + name,
                                      "sha256": hashlib.sha256(data).hexdigest()}
                                     for name, data in self.parts.items()]
        files = {"evidence-manifest.json": json.dumps(self.manifest).encode()}
        files.update({"artifacts/" + name: data for name, data in self.parts.items()})
        if corrupt_raw:
            files["artifacts/infection.json"] = b"changed after manifest assembly"
        with tarfile.open(self.bundle, "w:gz") as archive:
            for name, data in files.items():
                member = tarfile.TarInfo("./" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
                if duplicate_manifest and name == "evidence-manifest.json":
                    archive.addfile(member, io.BytesIO(data))
        self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()

    def api(self, path, paginate=False):
        return copy.deepcopy(self.api_data[path])

    def verify(self, **changes):
        args = dict(repository=REPO, commit=COMMIT, tag=TAG, evidence_commit=COMMIT,
                    evidence_tag=TAG, artifact_name="release-evidence-" + TAG,
                    bundle=self.bundle, digest=self.digest, api=self.api)
        args.update(changes)
        return MODULE.verify(**args)

    def test_matching_bundle_signed_main_commit_and_complete_policy_pass(self):
        self.verify()

    def test_run_paths_with_and_without_definition_refs_pass(self):
        for suffix in ("", "@main", "@refs/heads/main", "@" + COMMIT):
            with self.subTest(suffix=suffix):
                for workflow, key in zip(MODULE.REQUIRED_WORKFLOWS, self.run_keys):
                    self.api_data[key][0]["workflow_runs"][0]["path"] = ".github/workflows/" + workflow + suffix
                self.verify()

    def test_other_or_malformed_run_paths_block(self):
        path = ".github/workflows/ci.yml"
        for value in (None, 3, ".github/workflows/other.yml@main", "/" + path + "@main",
                      path + "/extra@main", path + "@", path + "@ main", path + "@main\n",
                      path + "@main\x00", path + "@main\x7f"):
            with self.subTest(path=value):
                self.api_data[self.run_keys[0]][0]["workflow_runs"][0]["path"] = value
                with self.assertRaises(ValueError):
                    self.verify()

    def test_actual_evidence_identity_and_digest_must_match(self):
        for change in ({"evidence_commit": "c" * 40}, {"evidence_tag": "v1.2.2"},
                       {"artifact_name": "another-artifact"}, {"digest": "0" * 64}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.verify(**change)

    def test_failing_or_malformed_manifest_and_missing_raw_report_block(self):
        for mutate in (lambda: self.manifest.update(commit="d" * 40),
                       lambda: self.manifest["checks"][0].update(status="fail"),
                       lambda: self.manifest["checks"].pop(),
                       lambda: self.parts.pop("infection-security.json")):
            with self.subTest(mutate=mutate):
                saved = copy.deepcopy((self.manifest, self.parts))
                mutate()
                self.write_bundle()
                with self.assertRaises(ValueError):
                    self.verify()
                self.manifest, self.parts = saved
                self.write_bundle()

    def test_degraded_doctor_remains_allowed(self):
        next(check for check in self.manifest["checks"] if check["id"] == "vault-doctor")["status"] = "absent"
        self.write_bundle()
        self.verify()

    def test_raw_digest_and_duplicate_manifest_fail_even_with_matching_bundle_digest(self):
        for options in ({"corrupt_raw": True}, {"duplicate_manifest": True}):
            with self.subTest(options=options):
                self.write_bundle(**options)
                with self.assertRaises(ValueError):
                    self.verify()
        self.write_bundle()

    def test_new_pending_failed_cancelled_attempt_blocks_old_green(self):
        for status, conclusion in (("queued", None), ("in_progress", None),
                                   ("completed", "failure"), ("completed", "cancelled")):
            with self.subTest(status=status, conclusion=conclusion):
                page = self.api_data[self.run_keys[0]][0]
                newer = dict(page["workflow_runs"][0], id=999, status=status, conclusion=conclusion,
                             created_at="2026-10-28T01:00:00Z", run_started_at="2026-10-28T01:00:00Z")
                page["workflow_runs"] = [newer, page["workflow_runs"][-1]]
                page["total_count"] = 2
                with self.assertRaises(ValueError):
                    self.verify()

    def test_latest_rerun_of_an_older_run_also_blocks(self):
        page = self.api_data[self.run_keys[0]][0]
        retry = dict(page["workflow_runs"][0], id=1, run_attempt=2, conclusion="failure",
                     created_at="2026-10-27T00:00:00Z", run_started_at="2026-10-28T02:00:00Z")
        page["workflow_runs"].append(retry)
        page["total_count"] = 2
        with self.assertRaises(ValueError):
            self.verify()

    def test_pr_manual_fork_wrong_identity_and_missing_workflow_do_not_qualify(self):
        for changes in ({"event": "pull_request"}, {"event": "workflow_dispatch"},
                        {"repository": {"id": 999, "full_name": "fork/vault"}},
                        {"head_sha": "e" * 40}, {"workflow_id": 999}, {"head_branch": "feature"}):
            with self.subTest(changes=changes):
                saved = copy.deepcopy(self.api_data)
                self.api_data[self.run_keys[0]][0]["workflow_runs"][0].update(changes)
                with self.assertRaises(ValueError):
                    self.verify()
                self.api_data = saved

    def test_exact_merge_group_producer_is_allowed(self):
        for key in self.run_keys:
            self.api_data[key][0]["workflow_runs"][0].update(
                event="merge_group", head_branch="gh-readonly-queue/main/pr-1-deadbeef")
        self.verify()

    def test_pagination_considers_a_new_failed_attempt_on_a_later_page(self):
        pages = self.api_data[self.run_keys[0]]
        later = dict(pages[0]["workflow_runs"][0], id=999, conclusion="failure",
                     created_at="2026-10-28T03:00:00Z", run_started_at="2026-10-28T03:00:00Z")
        pages[0]["total_count"] = 2
        pages.append({"total_count": 2, "workflow_runs": [later]})
        with self.assertRaises(ValueError):
            self.verify()

    def test_api_errors_incomplete_pages_unsigned_tags_and_nonmain_commits_block(self):
        for mutation in (lambda: self.api_data[self.run_keys[0]][0].update(total_count=2),
                         lambda: self.api_data["repos/" + REPO + "/git/tags/" + "b" * 40]["verification"].update(verified=False),
                         lambda: self.api_data["repos/" + REPO + "/compare/" + COMMIT + "...main"].update(status="diverged")):
            with self.subTest(mutation=mutation):
                saved = copy.deepcopy(self.api_data)
                mutation()
                with self.assertRaises(ValueError):
                    self.verify()
                self.api_data = saved
        def broken_api(path, paginate=False):
            raise RuntimeError("API unavailable")
        with self.assertRaises(RuntimeError):
            self.verify(api=broken_api)


if __name__ == "__main__":
    unittest.main()
