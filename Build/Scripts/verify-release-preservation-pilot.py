#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Temporary no-publisher proof of reusable outputs and same-run artifact reuse."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
import xml.etree.ElementTree as ET


def require(condition, message):
    if not condition:
        raise ValueError(message)


def audit_inventory(data, expected_count, expected_digest):
    root = ET.fromstring(data)
    require(root.tag == "testsuites", "Unexpected Unit JUnit schema")
    ids = []
    for case in root.findall(".//testcase"):
        classname = case.get("class", "")
        if not classname.startswith("Netresearch\\NrVault\\Tests\\Unit\\Audit\\"):
            continue
        require(not any(case.find(tag) is not None for tag in ("error", "failure", "skipped")),
                "Current Audit case failed, errored or skipped")
        name = case.attrib["name"]
        match = re.fullmatch(r'(.+) with data set "(.*)"', name) or re.fullmatch(r"(.+) with data set #([0-9]+)", name)
        ids.append(classname + "::" + (match[1] + "#" + match[2] if match else name))
    digest = hashlib.sha256((json.dumps(sorted(ids), ensure_ascii=False, separators=(",", ":")) + "\n").encode()).hexdigest()
    require(len(ids) == expected_count and len(set(ids)) == expected_count and digest == expected_digest,
            "Unit JUnit does not contain the complete current-source Audit inventory")
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("expected", "actual", "identity", "artifact", "digest", "directory", "run-id"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--attempt", type=int, required=True)
    parser.add_argument("--audit-count", type=int, required=True)
    parser.add_argument("--audit-digest", required=True)
    parser.add_argument("--outputs-only", action="store_true")
    args = parser.parse_args()
    try:
        require(re.fullmatch(r"[0-9a-f]{40}", args.expected), "Invalid immutable target")
        require(args.actual == args.expected and args.identity == args.expected,
                "Producer output lost or actual tested commit differs")
        label = "precheck-" + args.expected[:12]
        require(args.artifact == "release-evidence-" + label, "Producer artifact-name output lost or different")
        require(re.fullmatch(r"[0-9a-f]{64}", args.digest), "Producer digest output lost or malformed")
        require(args.attempt > 0 and args.run_id.isdigit() and int(args.run_id) > 0, "Invalid caller attempt/run identity")
        require(args.audit_count > 0 and re.fullmatch(r"[0-9a-f]{64}", args.audit_digest),
                "Missing current-source inventory binding")
        if args.outputs_only:
            return 0  # Reject lost outputs before download-artifact can default to all artifacts.
        bundle = Path(args.directory) / ("release-evidence-" + label + ".tar.gz")
        with bundle.open("rb") as stream:
            require(hashlib.file_digest(stream, "sha256").hexdigest() == args.digest,
                    "Same-run bundle differs from producer digest")
        with tarfile.open(bundle, "r:gz") as archive:
            manifests = [member for member in archive.getmembers()
                         if member.name in ("evidence-manifest.json", "./evidence-manifest.json")]
            require(len(manifests) == 1 and manifests[0].isfile() and manifests[0].size <= 1024 * 1024,
                    "Missing or duplicate/nonregular manifest")
            manifest = json.load(archive.extractfile(manifests[0]))
            require(isinstance(manifest, dict) and type(manifest.get("schemaVersion")) is int and
                    manifest["schemaVersion"] == 1 and manifest.get("extension") == "nr_vault" and
                    manifest.get("commit") == args.expected, "Manifest schema or actual source differs")
            reports = [entry for entry in manifest.get("artifacts", [])
                       if isinstance(entry, dict) and entry.get("name") == "junit-unit.xml"]
            require(len(reports) == 1 and str(PurePosixPath(reports[0].get("path"))) == "artifacts/junit-unit.xml",
                    "Missing or ambiguous current Unit JUnit report")
            members = [member for member in archive.getmembers()
                       if member.name in ("artifacts/junit-unit.xml", "./artifacts/junit-unit.xml")]
            require(len(members) == 1 and members[0].isfile() and 0 < members[0].size <= 64 * 1024 * 1024,
                    "Missing, oversized or nonregular current Unit JUnit")
            junit = archive.extractfile(members[0]).read()
            require(hashlib.sha256(junit).hexdigest() == reports[0].get("sha256"), "Raw Unit JUnit digest mismatch")
            inventory_digest = audit_inventory(junit, args.audit_count, args.audit_digest)
        identities = [check for check in manifest.get("checks", [])
                      if check.get("id") == "release-identity"]
        require(len(identities) == 1 and identities[0].get("status") == "warn",
                "Pilot must remain an untagged precheck")
        receipt = {"run_id": args.run_id, "caller_attempt": args.attempt,
                   "actual_commit": args.actual, "producer_identity": args.identity,
                   "artifact": args.artifact, "digest": args.digest,
                   "manifest_commit": manifest["commit"], "audit_cases": args.audit_count,
                   "audit_digest": inventory_digest, "junit_sha256": hashlib.sha256(junit).hexdigest()}
        print(json.dumps(receipt, sort_keys=True), flush=True)
        if args.attempt == 1:
            print("Intentional first-attempt failure AFTER output/artifact verification; retry failed jobs only.",
                  file=sys.stderr)
            return 42
        return 0
    except (ValueError, KeyError, TypeError, OSError, tarfile.TarError, ET.ParseError) as error:
        print("Preservation pilot blocked: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
