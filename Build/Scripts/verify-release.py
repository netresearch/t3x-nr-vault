#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""One-shot, fail-closed verification before invoking the release publisher."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
from urllib.parse import quote

REQUIRED_WORKFLOWS = ("ci.yml", "checks.yml", "e2e.yml", "security-gates.yml",
                      "check-template-drift.yml", "harness-verify.yml", "formal.yml")
REQUIRED_CHECKS = ("release-identity", "tests", "coverage-line", "coverage-security-dirs",
                  "coverage-branch", "mutation-msi", "mutation-msi-security",
                  "static-analysis", "dependency-audit", "vault-doctor")
REQUIRED_PARTS = ("junit-unit.xml", "junit-fuzz.xml", "junit-functional.xml", "clover.xml",
                 "coverage-text.txt", "infection.json", "infection-security.json", "composer-audit.json")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def gh_api(path, paginate=False):
    command = ["gh", "api"]
    if paginate:
        command += ["--paginate", "--slurp"]
    result = subprocess.run(command + [path], capture_output=True, text=True,
                            check=False, timeout=30)
    require(result.returncode == 0, "GitHub API request failed for " + path + ": " + result.stderr.strip())
    return json.loads(result.stdout)


def verify_bundle(bundle, digest, commit, tag):
    require(re.fullmatch(r"[0-9a-f]{64}", digest), "Missing or invalid producer bundle digest")
    with bundle.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == digest, "Evidence bundle digest mismatch")
    with tarfile.open(bundle, "r:gz") as archive:
        members = {}
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts, "Unsafe evidence archive path")
            if member.isdir():
                continue
            require(member.isfile() and str(path) not in members, "Nonregular or duplicate evidence entry")
            members[str(path)] = member
        require("evidence-manifest.json" in members, "Evidence manifest is missing")
        require(members["evidence-manifest.json"].size <= 1024 * 1024, "Evidence manifest is too large")
        manifest = json.load(archive.extractfile(members["evidence-manifest.json"]))
        require(isinstance(manifest, dict) and type(manifest.get("schemaVersion")) is int and
                manifest["schemaVersion"] == 1, "Invalid evidence manifest schema")
        require(manifest.get("commit") == commit and manifest.get("extension") == "nr_vault" and
                manifest.get("version") == tag[1:], "Evidence manifest identity mismatch")
        checks = manifest.get("checks")
        require(isinstance(checks, list) and checks, "Evidence checks are missing")
        by_id = {}
        for check in checks:
            require(isinstance(check, dict) and isinstance(check.get("id"), str), "Malformed evidence check")
            require(check["id"] not in by_id and check.get("status") in ("pass", "warn", "absent"),
                    "Duplicate, failed or invalid evidence check")
            by_id[check["id"]] = check
        require(set(REQUIRED_CHECKS).issubset(by_id) and by_id["release-identity"]["status"] == "pass",
                "Incomplete or untagged evidence verdict")
        entries = manifest.get("artifacts")
        require(isinstance(entries, list), "Evidence artifact inventory is missing")
        recorded = set()
        for entry in entries:
            require(isinstance(entry, dict), "Malformed evidence artifact")
            if "path" not in entry:
                continue  # Pointers to separately signed release assets, not raw inputs.
            path = entry["path"]
            require(isinstance(path, str) and path.startswith("artifacts/") and
                    path in members and path not in recorded and members[path].size > 0,
                    "Missing, empty or duplicate raw evidence artifact")
            with archive.extractfile(members[path]) as stream:
                require(hashlib.file_digest(stream, "sha256").hexdigest() == entry.get("sha256"),
                        "Raw evidence artifact digest mismatch: " + path)
            recorded.add(path)
        require({"artifacts/" + name for name in REQUIRED_PARTS}.issubset(recorded),
                "Required raw evidence reports are missing")


def verify_workflow(api, base, filename, repository, commit):
    workflow = api(base + "/actions/workflows/" + filename)
    require(workflow.get("path") == ".github/workflows/" + filename and
            workflow.get("state") == "active" and type(workflow.get("id")) is int,
            "Unclear workflow identity: " + filename)
    pages = api(base + "/actions/workflows/%d/runs?head_sha=%s&per_page=100" % (workflow["id"], commit),
                paginate=True)
    require(isinstance(pages, list) and pages, "Missing workflow run pages: " + filename)
    runs = []
    total = 0
    for page in pages:
        require(isinstance(page, dict) and isinstance(page.get("workflow_runs"), list) and
                type(page.get("total_count")) is int and page["total_count"] >= 0,
                "Malformed workflow run page: " + filename)
        total = max(total, page["total_count"])
        runs.extend(page["workflow_runs"])
    require(len(runs) >= total, "Incomplete workflow run pagination: " + filename)
    qualifying = []
    for run in runs:
        require(isinstance(run, dict), "Malformed workflow run: " + filename)
        event = run.get("event")
        branch = run.get("head_branch", "")
        if not ((event == "push" and branch == repository["default_branch"]) or
                (event == "merge_group" and isinstance(branch, str) and
                 branch.startswith("gh-readonly-queue/" + repository["default_branch"] + "/"))):
            continue
        # REST run.path may append the workflow definition ref, e.g. ci.yml@main.
        # Only normalize that suffix; the exact canonical producer stays required.
        run_path = run.get("path")
        path, separator, ref = run_path.partition("@") if isinstance(run_path, str) else (None, "", "")
        valid_ref = not separator or (ref and not any(char.isspace() or ord(char) < 32 or ord(char) == 127
                                                     for char in ref))
        require(run.get("head_sha") == commit and run.get("workflow_id") == workflow["id"] and
                path == workflow["path"] and valid_ref, "Workflow run revision/producer mismatch: " + filename)
        for key in ("repository", "head_repository"):
            identity = run.get(key)
            require(isinstance(identity, dict) and identity.get("id") == repository["id"] and
                    identity.get("full_name") == repository["full_name"], "Foreign or missing run repository: " + filename)
        require(type(run.get("id")) is int and type(run.get("run_attempt")) is int and run["run_attempt"] > 0,
                "Missing workflow attempt identity: " + filename)
        # Re-running an old run updates run_started_at; its newer failed attempt
        # must not be hidden behind another run's older green execution.
        started = datetime.fromisoformat(run.get("run_started_at") or run["created_at"])
        created = datetime.fromisoformat(run["created_at"])
        require(started.tzinfo is not None and created.tzinfo is not None, "Workflow timestamp lacks timezone")
        qualifying.append(((started, created, run["id"], run["run_attempt"]), run))
    require(qualifying, "No qualifying exact-SHA push/main or merge-group run: " + filename)
    run = max(qualifying, key=lambda item: item[0])[1]
    require(run.get("status") == "completed" and run.get("conclusion") == "success",
            filename + " run " + str(run["id"]) + " is " + str(run.get("conclusion") or run.get("status")) +
            "; publication blocked. After completion retry only the failed verifier/publisher jobs.")
    print(filename + ": success (run " + str(run["id"]) + ", attempt " + str(run["run_attempt"]) + ")")


def verify(repository, commit, tag, evidence_commit, evidence_tag, artifact_name, bundle, digest, api=gh_api):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "Invalid repository")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag),
            "Release needs a full commit SHA and version tag")
    require(evidence_commit == commit and evidence_tag == tag, "Actual evidence commit/tag differs from release")
    require(artifact_name == "release-evidence-" + tag, "Evidence artifact name differs from release")
    verify_bundle(Path(bundle), digest, commit, tag)
    base = "repos/" + repository
    repo = api(base)
    require(repo.get("full_name") == repository and type(repo.get("id")) is int and
            isinstance(repo.get("default_branch"), str) and repo["default_branch"], "Unclear repository identity")
    ref = api(base + "/git/ref/tags/" + tag)
    require(ref.get("ref") == "refs/tags/" + tag and ref.get("object", {}).get("type") == "tag",
            "Release tag must be an annotated signed tag")
    tag_sha = ref["object"].get("sha", "")
    require(re.fullmatch(r"[0-9a-f]{40}", tag_sha), "Invalid annotated tag identity")
    signed = api(base + "/git/tags/" + tag_sha)
    require(signed.get("tag") == tag and signed.get("object", {}).get("type") == "commit" and
            signed["object"].get("sha") == commit, "Signed tag targets another commit")
    require(signed.get("verification", {}).get("verified") is True and
            signed["verification"].get("reason") == "valid", "Tag signature is not verified")
    ancestry = api(base + "/compare/" + commit + "..." + quote(repo["default_branch"], safe=""))
    require(ancestry.get("status") in ("ahead", "identical") and
            ancestry.get("base_commit", {}).get("sha") == commit, "Tagged commit is not on protected main history")
    for filename in REQUIRED_WORKFLOWS:
        verify_workflow(api, base, filename, repo, commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("repository", "commit", "tag", "evidence-commit", "evidence-tag", "artifact-name", "bundle", "digest"):
        parser.add_argument("--" + field, required=True)
    try:
        verify(**vars(parser.parse_args()))
        print("Release evidence identity, digests and required workflows verified.")
        return 0
    except (ValueError, KeyError, TypeError, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        print("Release blocked: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
