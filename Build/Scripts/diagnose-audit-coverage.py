#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
"""Temporary single-process Audit path-coverage signal and memory diagnostic."""

import argparse
import json
from pathlib import Path
import signal
import subprocess
import sys
import time


def snapshot():
    cgroup = Path("/sys/fs/cgroup")
    try:
        for line in Path("/proc/self/cgroup").read_text().splitlines():
            if line.startswith("0::"):
                candidate = cgroup / line[3:].lstrip("/")
                if candidate.is_dir():
                    cgroup = candidate
    except OSError:
        pass
    values = {"cgroup": str(cgroup)}
    for name in ("memory.events", "memory.current", "memory.peak", "memory.max"):
        try:
            values[name] = (cgroup / name).read_text().strip()
        except OSError as error:
            values[name] = {"unavailable": str(error)}
    try:
        values["meminfo"] = Path("/proc/meminfo").read_text()
    except OSError as error:
        values["meminfo"] = {"unavailable": str(error)}
    return values


def events(value):
    if not isinstance(value, str):
        return None
    return {key: int(count) for key, count in (line.split() for line in value.splitlines())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=".Build/audit-diagnostic/result.json")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        # Same executable, flags, absolute part path and target as native worker 1.
        command = [".Build/bin/phpunit", "-c", "Build/phpunit.xml", "--path-coverage",
                   "--coverage-php=" + str(Path.cwd() / ".Build/coverage/unit-Audit.cov"),
                   "Tests/Unit/Audit"]
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    Path(".Build/coverage").mkdir(parents=True, exist_ok=True)
    before = snapshot()
    started = time.monotonic()
    timed_out = False
    error = None
    returncode = None
    print("Audit diagnostic command: " + json.dumps(command), flush=True)
    try:
        result = subprocess.run(command, check=False, timeout=1800)
        returncode = result.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
    except OSError as exception:
        error = str(exception)
    after = snapshot()
    before_events = events(before.get("memory.events"))
    after_events = events(after.get("memory.events"))
    delta = ({key: after_events[key] - before_events.get(key, 0) for key in after_events}
             if before_events is not None and after_events is not None else None)
    signal_name = None
    if returncode is not None and returncode < 0:
        signal_name = signal.Signals(-returncode).name
    report = {"command": command, "returncode": returncode, "signal": signal_name,
              "timed_out": timed_out, "launcher_error": error,
              "seconds": round(time.monotonic() - started, 3),
              "memory_events_delta": delta, "before": before, "after": after}
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if returncode == 0 and not timed_out and error is None else 1


if __name__ == "__main__":
    sys.exit(main())
