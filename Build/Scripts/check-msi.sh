#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
#
# check-msi.sh — Parse Infection JSON output and emit a shields.io endpoint JSON.
#
# Usage:
#   ./Build/Scripts/check-msi.sh                        # writes to stdout
#   ./Build/Scripts/check-msi.sh > .Build/infection/badge.json
#
# Exit codes:
#   0 success
#   1 infection.json not found
#   2 jq not installed
#   3 malformed infection.json (missing .stats.msi)
#
# The output matches the shields.io endpoint schema:
#   https://shields.io/endpoint
#
# Pick up via:
#   ![MSI](https://img.shields.io/endpoint?url=https://.../badge.json)

set -euo pipefail

INFECTION_JSON="${INFECTION_JSON:-.Build/infection/infection.json}"

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required but not installed." >&2
    exit 2
fi

if [[ ! -f "$INFECTION_JSON" ]]; then
    echo "ERROR: Infection report not found at $INFECTION_JSON" >&2
    echo "Run: composer ci:test:php:mutation" >&2
    exit 1
fi

# Infection 0.32 stats structure:
#   .stats.msi               — overall Mutation Score Indicator
#   .stats.coveredCodeMsi    — Covered Code MSI
#   .stats.mutationCodeCoverage
#   .stats.totalMutantsCount
#   .stats.killedCount / .escapedCount / .errorCount / .timedOutCount / .notCoveredCount
MSI="$(jq -r '.stats.msi // empty' "$INFECTION_JSON")"

if [[ -z "$MSI" ]]; then
    echo "ERROR: $INFECTION_JSON is missing .stats.msi" >&2
    exit 3
fi

# Round MSI to 1 decimal for the badge label.
MSI_ROUNDED="$(printf '%.1f' "$MSI")"

# Color thresholds (customary for coverage/quality badges):
#   >= 90 : brightgreen
#   >= 80 : green
#   >= 70 : yellowgreen
#   >= 60 : yellow
#   >= 50 : orange
#   else  : red
COLOR="$(awk -v m="$MSI" 'BEGIN {
    if      (m >= 90) print "brightgreen"
    else if (m >= 80) print "green"
    else if (m >= 70) print "yellowgreen"
    else if (m >= 60) print "yellow"
    else if (m >= 50) print "orange"
    else              print "red"
}')"

# shields.io endpoint schema (schemaVersion 1):
jq -n \
    --arg label "mutation score" \
    --arg message "${MSI_ROUNDED}%" \
    --arg color "$COLOR" \
    '{
        schemaVersion: 1,
        label: $label,
        message: $message,
        color: $color,
        namedLogo: "phpunit",
        labelColor: "555"
    }'
