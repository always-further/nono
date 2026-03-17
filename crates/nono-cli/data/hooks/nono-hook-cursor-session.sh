#!/bin/bash
# nono-hook-cursor-session.sh - Cursor sessionStart hook
# Version: 0.0.1
#
# This hook is automatically installed by nono when using the cursor profile.
# It injects nono sandbox context at session start via additional_context.

# Only run if we're inside a nono sandbox
if [ -z "$NONO_CAP_FILE" ] || [ ! -f "$NONO_CAP_FILE" ]; then
    echo '{}'
    exit 0
fi

# Check if jq is available (required for JSON parsing)
if ! command -v jq &> /dev/null; then
    echo '{}'
    exit 0
fi

# Read capabilities from the cap file
CAPS=$(jq -r '.fs[] | "  " + (.resolved // .path) + " (" + .access + ")"' "$NONO_CAP_FILE" 2>/dev/null)
NET=$(jq -r 'if .net_blocked then "blocked" else "allowed" end' "$NONO_CAP_FILE" 2>/dev/null)

CONTEXT="[NONO SANDBOX ACTIVE]
You are running inside the nono security sandbox. This is a hard security boundary that CANNOT be bypassed.

ALLOWED PATHS:
$CAPS
Network: $NET

On ANY 'operation not permitted' or EPERM error:
- STOP immediately. Do not try alternative paths or workarounds.
- Tell the user to exit and restart: nono run --allow /path/to/needed -- cursor
- This is the ONLY solution."

jq -n --arg ctx "$CONTEXT" '{"additional_context": $ctx}'
