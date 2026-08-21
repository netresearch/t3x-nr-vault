#!/usr/bin/env bash
#
# Renders Documentation/ with the TYPO3 render-guides container.
#
# This is what `runTests.sh -s renderDocumentation` did in the 797-line runner
# fork this repository carried until it adopted the shared runner. The shared
# runner has no documentation suite and should not grow one for a single
# extension: of the 22 extensions here that ship Documentation/, this was the
# only one whose runner could render it.
#
# Usage:
#   Build/Scripts/renderDocs.sh            render into Documentation-GENERATED-temp
#   Build/Scripts/renderDocs.sh --check    fail on any log message (what CI does)
#   Build/Scripts/renderDocs.sh --clean    remove the rendered output

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_DOCS="${IMAGE_DOCS:-ghcr.io/typo3-documentation/render-guides:latest}"
OUTPUT="${ROOT_DIR}/Documentation-GENERATED-temp"

CONTAINER_BIN="${CONTAINER_BIN:-}"
if [ -z "${CONTAINER_BIN}" ]; then
    if command -v docker >/dev/null 2>&1; then
        CONTAINER_BIN="docker"
    elif command -v podman >/dev/null 2>&1; then
        CONTAINER_BIN="podman"
    else
        echo "renderDocs.sh: neither docker nor podman found" >&2
        exit 1
    fi
fi

case "${1:-}" in
    --clean)
        rm -rf "${OUTPUT}"
        echo "renderDocs.sh: removed ${OUTPUT#"${ROOT_DIR}/"}"
        exit 0
        ;;
    --check)
        shift
        # --fail-on-log is what makes this a gate rather than a preview: a
        # warning in the rendered output is a broken cross-reference or an
        # unparsed directive, and it should not reach docs.typo3.org.
        set -- --no-progress --fail-on-log "$@"
        ;;
esac

mkdir -p "${OUTPUT}"
exec "${CONTAINER_BIN}" run --rm \
    -v "${ROOT_DIR}:/project" \
    -u "$(id -u):$(id -g)" \
    "${IMAGE_DOCS}" --config=Documentation "$@"
