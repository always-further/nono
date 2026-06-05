#!/usr/bin/env bash
# Stream macOS unified logs relevant to nono/claude browser-open failures.
#
# Run this in one terminal, reproduce the failing login in another terminal,
# then Ctrl+C and send back the captured log file.

set -euo pipefail

if [[ "${OSTYPE:-}" != darwin* ]]; then
    echo "This script is macOS-only." >&2
    exit 1
fi

TMP_BASE="${TMPDIR:-/tmp}"
OUT_FILE="${1:-$TMP_BASE/nono-macos-sandbox-stream.log}"
PREDICATE='subsystem == "com.apple.sandbox" OR process == "claude" OR process == "nono" OR process == "open"'

echo "Writing live unified logs to: $OUT_FILE"
echo "Start the failing login flow in another terminal, then Ctrl+C here."
echo

/usr/bin/log stream \
    --style compact \
    --predicate "$PREDICATE" | tee "$OUT_FILE"
