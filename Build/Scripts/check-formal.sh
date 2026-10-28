#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/nr-vault-formal.XXXXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

java_bin="${JAVA:-java}"
if ! command -v "$java_bin" >/dev/null 2>&1; then
    echo 'Formal checks require Java 11 or later; set JAVA to its executable.' >&2
    exit 1
fi

# Stable official release, also verified against its published SHA-1 checksum.
# https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4
jar_path="${TLA2TOOLS_JAR:-$work_dir/tla2tools.jar}"
jar_sha256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
if [[ -z "${TLA2TOOLS_JAR:-}" ]]; then
    curl --proto '=https' --tlsv1.2 --retry 2 --fail --silent --show-error --location \
        https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar \
        --output "$jar_path"
fi
if ! printf '%s  %s\n' "$jar_sha256" "$jar_path" | sha256sum --check --status; then
    echo 'TLC JAR checksum mismatch; no model was checked.' >&2
    exit 1
fi

mkdir -p "$work_dir/model"
cp "$root_dir"/Tests/Formal/*.tla "$root_dir"/Tests/Formal/*.cfg "$work_dir/model/"
results_dir="${FORMAL_RESULTS_DIR:-$work_dir/results}"
mkdir -p "$results_dir"

run_model() {
    local config="$1" expected_invariant="${2:-}" status=0 log_path
    log_path="$results_dir/$config.log"
    mkdir -p "$work_dir/$config-states"
    timeout 60 "$java_bin" -XX:+UseParallelGC -Xmx512m -cp "$jar_path" tlc2.TLC \
        -workers 1 -seed 1 -fp 0 -cleanup -metadir "$work_dir/$config-states" \
        -config "$work_dir/model/$config.cfg" "$work_dir/model/VaultAuditAtomicity.tla" \
        >"$log_path" 2>&1 || status=$?

    if [[ -n "$expected_invariant" ]]; then
        # TLC 1.7.4 distinguishes a safety violation (12) from parse/evaluation
        # errors (75+) and process failures. A random failure is NOT a passing
        # negative control. Require the intended invariant and a real trace.
        if [[ "$status" -eq 12 ]] \
            && grep -Fq "Error: Invariant $expected_invariant is violated." "$log_path" \
            && grep -Fq 'Error: The behavior up to this point is:' "$log_path"; then
            printf '%s: expected %s counterexample found\n' "$config" "$expected_invariant"
            return
        fi
    elif [[ "$status" -eq 0 ]] \
        && grep -Fq 'Model checking completed. No error has been found.' "$log_path" \
        && grep -Fq '0 states left on queue.' "$log_path"; then
        printf '%s: exhaustive finite model check passed\n' "$config"
        grep -F 'distinct states found' "$log_path"
        return
    fi

    cat "$log_path" >&2
    printf '%s: unexpected TLC result (exit %s); formal checks failed\n' "$config" "$status" >&2
    return 1
}

run_model Atomic
run_model LegacyCrash SettledAudit
run_model LegacyCompensation NoStaleCompensation
run_model AtomicBothCommitted NeverBothCommitted
run_model AtomicFailure NeverFailed
run_model AtomicCrash NeverCrashed
