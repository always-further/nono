#!/bin/bash
# nono-hook-cursor-tool.sh - Cursor postToolUse hook
# Version: 0.0.1
#
# This hook is automatically installed by nono when using the cursor profile.
# It injects sandbox guidance when tool results contain permission errors.

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

# Read stdin (tool result from Cursor)
INPUT=$(cat)

# Check if tool output contains permission-denied indicators
OUTPUT=$(echo "$INPUT" | jq -r '.tool_output // ""' 2>/dev/null)
if echo "$OUTPUT" | grep -qi -e "operation not permitted" -e "EPERM" -e "permission denied"; then
    CONTEXT="[NONO SANDBOX - PERMISSION DENIED] STOP. This path is blocked by the nono sandbox. Tell the user to exit and restart with: nono run --allow /path/to/needed -- cursor"
    jq -n --arg ctx "$CONTEXT" '{"additional_context": $ctx}'
else
    echo '{}'
fi
