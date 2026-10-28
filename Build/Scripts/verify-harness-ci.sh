#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: Netresearch DTT GmbH
set -euo pipefail

# Only the existing harness's warnings may pass with exit 2. A helper regression
# returning 2 must still fail; do not wrap this entire script in the old OR-list.
harness_status=0
bash Build/Scripts/verify-harness.sh || harness_status=$?
if [[ "$harness_status" -ne 0 && "$harness_status" -ne 2 ]]; then
    exit "$harness_status"
fi
PYTHONDONTWRITEBYTECODE=1 python3 Build/Scripts/test-release-coverage.py
PYTHONDONTWRITEBYTECODE=1 python3 Build/Scripts/test-verify-release.py
