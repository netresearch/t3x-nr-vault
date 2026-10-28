#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Schedule complete coverage parts on four workers; retain a part per shard."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

# Scheduling hints from evidence run 36628230721, in seconds, including setup.
# They affect placement only. New directories are discovered and get 60 seconds.
WEIGHTS = {"Audit": 1030, "Service": 671, "Security": 459, "Hook": 347,
           "Http": 346, "Command": 346, "Domain": 175}


def discover(root):
    unit = root / "Tests/Unit"
    shards = []
    for directory in sorted(unit.iterdir()):
        if directory.is_symlink():
            continue
        if directory.is_dir() and any(path.is_file() and not path.is_symlink()
                                      for path in directory.rglob("*Test.php")):
            if not re.fullmatch(r"[A-Za-z0-9_-]+", directory.name) or directory.name == "__root":
                raise ValueError("Invalid or reserved coverage shard name: " + directory.name)
            shards.append(directory.name)
    if any(path.is_file() and not path.is_symlink() for path in unit.glob("*Test.php")):
        shards.append("__root")
    if not shards:
        raise ValueError("No unit coverage shards found")
    return sorted(shards)


def plan(root):
    shards = discover(root)
    groups = [{"id": index + 1, "shards": [], "seconds": 0}
              for index in range(min(4, len(shards)))]
    for shard in sorted(shards, key=lambda name: (-WEIGHTS.get(name, 60), name)):
        group = min(groups, key=lambda item: (item["seconds"], item["id"]))
        group["shards"].append(shard)
        group["seconds"] += WEIGHTS.get(shard, 60)
    assigned = [name for group in groups for name in group["shards"]]
    if sorted(assigned) != shards or len(assigned) != len(set(assigned)):
        raise ValueError("Coverage worker assignment differs from complete shard manifest")
    return {"shards": shards, "workers": groups}


def worker(root, shards, phpunit):
    if (not isinstance(shards, list) or not shards or
            any(not isinstance(name, str) for name in shards) or
            len(shards) != len(set(shards)) or not set(shards).issubset(discover(root))):
        raise ValueError("Worker must select distinct known coverage shards")
    output = root / ".Build/coverage"
    output.mkdir(parents=True, exist_ok=True)
    failed = []
    for shard in shards:
        targets = (sorted(str(path.relative_to(root)) for path in (root / "Tests/Unit").glob("*Test.php"))
                   if shard == "__root" else ["Tests/Unit/" + shard])
        part = output / ("unit-" + shard + ".cov")
        part.unlink(missing_ok=True)  # An old part cannot turn a failed invocation green.
        command = [phpunit, "-c", "Build/phpunit.xml", "--path-coverage",
                   "--coverage-php=" + str(part), *targets]
        print("Coverage shard: " + shard, flush=True)
        try:
            result = subprocess.run(command, cwd=root, check=False)
            passed = result.returncode == 0 and part.is_file() and part.stat().st_size > 0
        except OSError as error:
            print(str(error), file=sys.stderr)
            passed = False
        if not passed:
            failed.append(shard)
    if failed:
        print("Failed coverage shards: " + ", ".join(failed), file=sys.stderr)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "worker"))
    parser.add_argument("--shards", default="[]")
    parser.add_argument("--phpunit", default=".Build/bin/phpunit")
    args = parser.parse_args()
    try:
        if args.mode == "plan":
            print(json.dumps(plan(Path.cwd()), separators=(",", ":")))
            return 0
        return worker(Path.cwd(), json.loads(args.shards), args.phpunit)
    except (ValueError, OSError) as error:
        print("Coverage: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
