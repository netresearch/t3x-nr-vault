#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Temporary no-publisher proof of reusable outputs and same-run artifact reuse."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("expected", "actual", "identity", "artifact", "digest", "directory", "run-id"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--attempt", type=int, required=True)
    args = parser.parse_args()
    try:
        require(re.fullmatch(r"[0-9a-f]{40}", args.expected), "Invalid immutable target")
        require(args.actual == args.expected and args.identity == args.expected,
                "Producer output lost or actual tested commit differs")
        label = "precheck-" + args.expected[:12]
        require(args.artifact == "release-evidence-" + label, "Producer artifact-name output lost or different")
        require(re.fullmatch(r"[0-9a-f]{64}", args.digest), "Producer digest output lost or malformed")
        require(args.attempt > 0 and args.run_id.isdigit(), "Invalid caller attempt/run identity")
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
        require(isinstance(manifest, dict) and manifest.get("commit") == args.expected,
                "Manifest actual SHA differs")
        identities = [check for check in manifest.get("checks", [])
                      if check.get("id") == "release-identity"]
        require(len(identities) == 1 and identities[0].get("status") == "warn",
                "Pilot must remain an untagged precheck")
        receipt = {"run_id": args.run_id, "caller_attempt": args.attempt,
                   "actual_commit": args.actual, "producer_identity": args.identity,
                   "artifact": args.artifact, "digest": args.digest,
                   "manifest_commit": manifest["commit"]}
        print(json.dumps(receipt, sort_keys=True), flush=True)
        if args.attempt == 1:
            print("Intentional first-attempt failure AFTER output/artifact verification; retry failed jobs only.",
                  file=sys.stderr)
            return 42
        return 0
    except (ValueError, KeyError, TypeError, OSError, tarfile.TarError) as error:
        print("Preservation pilot blocked: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
