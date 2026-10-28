#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Schedule complete coverage parts on four workers; retain a part per shard."""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

# Scheduling hints from evidence run 36628230721, in seconds, including setup.
# They affect placement only. New directories are discovered and get 60 seconds.
WEIGHTS = {"Audit": 1030, "Service": 671, "Security": 459, "Hook": 347,
           "Http": 346, "Command": 346, "Domain": 175}
CLEANUP_SECONDS = 5


def group_is_running(group):
    # A reaped PHPUnit parent says nothing about its orphaned test children.
    # Linux /proc exposes group membership and distinguishes dead zombies from
    # children that can still execute or resume after a stop.
    for directory in Path("/proc").iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            fields = (directory / "stat").read_text(errors="surrogateescape").rsplit(") ", 1)[1].split()
            if int(fields[2]) == group and fields[0] not in ("Z", "X", "x"):
                return True
        except (FileNotFoundError, ProcessLookupError):
            continue  # The process exited between enumeration and inspection.
        except (IndexError, ValueError) as error:
            raise OSError("Cannot confirm process-group membership: " + str(directory)) from error
    return False


def cleanup_group(process):
    deadline = time.monotonic() + CLEANUP_SECONDS
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass  # The group already exited; membership is still checked below.
    returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
    while group_is_running(process.pid):
        if time.monotonic() >= deadline:
            raise OSError("Process group still has a live member after cleanup deadline")
        time.sleep(0.01)
    return returncode


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
    for group in groups:
        group["timeout"] = len(group["shards"]) * 30 + 10
        if group["timeout"] > 360:
            raise ValueError("Coverage group exceeds GitHub's 360-minute job limit; revise the worker plan")
    return {"shards": shards, "workers": groups}


def worker(root, shards, phpunit, timeout=1800):
    if not 0 < timeout <= 1800:
        raise ValueError("Shard timeout must be positive and at most 1800 seconds")
    if (not isinstance(shards, list) or not shards or
            any(not isinstance(name, str) for name in shards) or
            len(shards) != len(set(shards)) or not set(shards).issubset(discover(root))):
        raise ValueError("Worker must select distinct known coverage shards")
    output = root / ".Build/coverage"
    output.mkdir(parents=True, exist_ok=True)
    failed = []
    for index, shard in enumerate(shards):
        targets = (sorted(str(path.relative_to(root)) for path in (root / "Tests/Unit").glob("*Test.php")
                          if path.is_file() and not path.is_symlink())
                   if shard == "__root" else ["Tests/Unit/" + shard])
        part = output / ("unit-" + shard + ".cov")
        part.unlink(missing_ok=True)  # An old part cannot turn a failed invocation green.
        command = [phpunit, "-c", "Build/phpunit.xml", "--path-coverage",
                   "--coverage-php=" + str(part)]
        if shard == "Audit":
            # Bound Xdebug instrumentation state without dropping any Audit case.
            command.append("--process-isolation")
        command += targets
        print("Coverage shard: " + shard, flush=True)
        returncode = None
        timed_out = False
        cleanup_confirmed = None
        launcher_error = None
        process = None
        try:
            # A separate group includes PHPUnit's per-test PHP children on every
            # exit, including a crash or a successful parent leaving a child alive.
            process = subprocess.Popen(command, cwd=root, start_new_session=True)
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                timed_out = True
                print(str(error), file=sys.stderr)
        except (OSError, subprocess.TimeoutExpired) as error:
            launcher_error = str(error)
            print(launcher_error, file=sys.stderr)
        finally:
            if process is not None:
                cleanup_confirmed = False
                try:
                    cleaned_returncode = cleanup_group(process)
                    if returncode is None:
                        returncode = cleaned_returncode
                    cleanup_confirmed = True
                except (OSError, subprocess.TimeoutExpired) as error:
                    launcher_error = "Process-group cleanup failed: " + str(error)
                    print(launcher_error, file=sys.stderr)
        signal_name = signal.Signals(-returncode).name if returncode is not None and returncode < 0 else None
        nonempty = part.is_file() and part.stat().st_size > 0
        print("Coverage shard result: " + json.dumps({
            "shard": shard, "returncode": returncode, "signal": signal_name,
            "timed_out": timed_out, "launcher_error": launcher_error,
            "timeout_cleanup_confirmed": cleanup_confirmed if timed_out else None,
            "process_group_cleanup_confirmed": cleanup_confirmed,
            "coverage_part_nonempty": nonempty}, sort_keys=True), flush=True)
        passed = returncode == 0 and not timed_out and launcher_error is None and cleanup_confirmed and nonempty
        if not passed:
            failed.append(shard)
        if process is not None and not cleanup_confirmed:
            print("Process-group cleanup unconfirmed; remaining coverage shards not started: " +
                  ", ".join(shards[index + 1:]), file=sys.stderr)
            break
    if failed:
        print("Failed coverage shards: " + ", ".join(failed), file=sys.stderr)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "worker"))
    parser.add_argument("--shards", default="[]")
    parser.add_argument("--phpunit", default=".Build/bin/phpunit")
    parser.add_argument("--timeout-seconds", type=float, default=1800)
    args = parser.parse_args()
    try:
        if args.mode == "plan":
            print(json.dumps(plan(Path.cwd()), separators=(",", ":")))
            return 0
        return worker(Path.cwd(), json.loads(args.shards), args.phpunit, args.timeout_seconds)
    except (ValueError, OSError) as error:
        print("Coverage: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
