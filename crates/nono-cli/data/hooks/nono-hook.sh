#!/bin/bash
# nono-hook.sh - Claude Code hook for nono sandbox diagnostics
# Version: 0.1.0
#
# This hook is automatically installed by nono when using the claude-code profile.
# It fires on PostToolUseFailure events and injects diagnostic context only when
# there is evidence of a genuine sandbox access violation.
#
# Improvements over v0.0.1:
#   - Reads stdin payload (tool_name, cwd, tool_result) instead of ignoring it
#   - Two-tier signal detection: strong (EPERM/EACCES) vs weak (ENOENT-class)
#   - Extracts and canonicalizes paths from error text (handles /tmp -> /private/tmp)
#   - Checks extracted paths against allow list before firing
#   - Tool-name-aware thresholds (Read/Write/Edit treat ENOENT as strong)
#   - Network-specific advice (--net-allow) when signal has no filesystem path
#   - Nearby paths only (not full allow list dump) to reduce token cost
#   - Deduplication: same blocked path fires only once per nono session
#   - stdin bounded to 64 KB; python3 optional (bash fallback for path resolution)

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

if [ -z "$NONO_CAP_FILE" ] || [ ! -f "$NONO_CAP_FILE" ]; then
    exit 0
fi

if ! command -v jq &>/dev/null; then
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. Read hook payload from stdin (bounded to 64 KB)
# ---------------------------------------------------------------------------

INPUT=$(head -c 65536)

TOOL_NAME=$(printf '%s\n' "$INPUT" | jq -r '.tool_name // ""' 2>/dev/null)
CWD=$(printf '%s\n' "$INPUT"      | jq -r '.cwd       // ""' 2>/dev/null)

# Flatten all string values in the payload for signal/path scanning
ALL_TEXT=$(printf '%s\n' "$INPUT" | jq -r '.. | strings' 2>/dev/null)

# ---------------------------------------------------------------------------
# 2. Signal detection (case-insensitive, cross-platform)
# ---------------------------------------------------------------------------

# Strong: OS-level access denial
STRONG_PAT="[Oo]peration not permitted|[Pp]ermission denied|[Rr]ead-only file system|[Aa]ccess denied|AccessDeniedException|UnauthorizedAccessException|error\\.AccessDenied|error\\.PermissionDenied|don't have permission|doesn't have permission"

# Weak: ENOENT-class — ambiguous; nono can surface blocked paths as ENOENT
WEAK_PAT='[Nn]o such file or directory|ENOENT|[Cc]annot find module|[Mm]odule not found|[Nn]o module named|FileNotFoundException|[Cc]ould not find file|error\.FileNotFound|error\.PathNotFound'

HAS_STRONG=0
HAS_WEAK=0

printf '%s\n' "$ALL_TEXT" | grep -qiE "$STRONG_PAT" && HAS_STRONG=1 || true
printf '%s\n' "$ALL_TEXT" | grep -qiE "$WEAK_PAT"   && HAS_WEAK=1   || true

# Silent if no signals at all
if [ "$HAS_STRONG" -eq 0 ] && [ "$HAS_WEAK" -eq 0 ]; then
    exit 0
fi

# ---------------------------------------------------------------------------
# 3. Path helpers
# ---------------------------------------------------------------------------

# Canonicalize a path: resolve symlinks so /tmp/x matches /private/tmp/x in cap file.
canonicalize_path() {
    local path="$1"
    if command -v python3 &>/dev/null; then
        path="$path" python3 -c "import os; print(os.path.realpath(os.environ['path']))" 2>/dev/null && return
    fi
    # Bash fallback: walk up to deepest existing ancestor, then reassemble with pwd -P
    local existing="$path" suffix=""
    while [ -n "$existing" ] && [ "$existing" != "/" ] && [ ! -e "$existing" ]; do
        suffix="/$(basename "$existing")$suffix"
        existing=$(dirname "$existing")
    done
    if [ -e "$existing" ]; then
        printf '%s%s\n' "$(cd "$existing" && pwd -P)" "$suffix"
    else
        printf '%s\n' "$path"
    fi
}

# Resolve a relative path against cwd
resolve_rel_path() {
    local cwd="$1" rel="$2"
    if command -v python3 &>/dev/null; then
        cwd_val="$cwd" rel_val="$rel" python3 -c "import os, os.path; print(os.path.normpath(os.path.join(os.environ['cwd_val'], os.environ['rel_val'])))" 2>/dev/null && return
    fi
    # readlink -f (GNU coreutils) normalizes .. without requiring path to exist
    if command -v readlink &>/dev/null; then
        readlink -f "$cwd/$rel" 2>/dev/null && return
    fi
    # Last resort: concatenate (may leave .. components unnormalized)
    printf '%s/%s\n' "$cwd" "$rel" | sed 's|/\./|/|g; s|//|/|g'
}

# ---------------------------------------------------------------------------
# 4. Path extraction
# ---------------------------------------------------------------------------

# Extract absolute paths. The leading-character guard prevents matching /foo from ./foo.
ABS_RAW=$(printf '%s\n' "$ALL_TEXT" \
    | grep -oE '(^|[^./a-zA-Z0-9_-])/[a-zA-Z0-9_.][a-zA-Z0-9_./:-]*' \
    | grep -oE '/[a-zA-Z0-9_.][a-zA-Z0-9_./:-]*' \
    | grep -vE '^/(dev|proc|sys)(/|$)' \
    | sed 's/:$//' \
    | sort -u)

# Resolve relative paths if cwd is available
REL_RESOLVED=""
if [ -n "$CWD" ]; then
    REL_RAW=$(printf '%s\n' "$ALL_TEXT" \
        | grep -oE '(\./|\.\./)([a-zA-Z0-9_.][a-zA-Z0-9_./:-]*)?' \
        | grep -v '^$' \
        | sort -u)
    while IFS= read -r rel; do
        [ -z "$rel" ] && continue
        resolved=$(resolve_rel_path "$CWD" "$rel")
        [ -n "$resolved" ] && REL_RESOLVED="${REL_RESOLVED}${resolved}
"
    done <<< "$REL_RAW"
fi

# Combine, canonicalize, and deduplicate all paths
ALL_PATHS_RAW=$(printf '%s\n%s\n' "$ABS_RAW" "$REL_RESOLVED" | grep -v '^$' | sort -u)

ALL_PATHS=$(
    while IFS= read -r path; do
        [ -z "$path" ] && continue
        canon=$(canonicalize_path "$path")
        printf '%s\n%s\n' "$path" "$canon"
    done <<< "$ALL_PATHS_RAW" | grep -v '^$' | sort -u
)

# ---------------------------------------------------------------------------
# 5. Tool-name-aware threshold promotion
# ---------------------------------------------------------------------------
# Read/Write/Edit don't run arbitrary code — ENOENT is far more suspicious.
if [ "$HAS_STRONG" -eq 0 ] && [ "$HAS_WEAK" -eq 1 ]; then
    case "$TOOL_NAME" in
        Read|Write|Edit) HAS_STRONG=1; HAS_WEAK=0 ;;
    esac
fi

# ---------------------------------------------------------------------------
# 6. Allow-list coverage check (path-boundary safe)
# ---------------------------------------------------------------------------

is_covered() {
    local path="$1"
    local canon_path
    canon_path=$(canonicalize_path "$path")
    while IFS= read -r cap_entry; do
        local apath canon_apath
        apath=$(printf '%s\n' "$cap_entry" | jq -r '.path' 2>/dev/null)
        [ -z "$apath" ] && continue
        canon_apath=$(canonicalize_path "$apath")
        if [[ "$path" == "$apath" ]] || [[ "$path" == "$apath/"* ]] || \
           [[ "$path" == "$canon_apath" ]] || [[ "$path" == "$canon_apath/"* ]] || \
           [[ "$canon_path" == "$apath" ]] || [[ "$canon_path" == "$apath/"* ]] || \
           [[ "$canon_path" == "$canon_apath" ]] || [[ "$canon_path" == "$canon_apath/"* ]]; then
            return 0
        fi
    done < <(jq -c '.fs[]' "$NONO_CAP_FILE" 2>/dev/null)
    return 1
}

OUTSIDE_PATHS=""
while IFS= read -r path; do
    [ -z "$path" ] && continue
    if ! is_covered "$path"; then
        OUTSIDE_PATHS="${OUTSIDE_PATHS}${path}
"
    fi
done <<< "$ALL_PATHS"
OUTSIDE_PATHS=$(printf '%s\n' "$OUTSIDE_PATHS" | grep -v '^$' | sort -u)

# Weak signal + all paths covered → real missing file, not a sandbox issue
if [ "$HAS_WEAK" -eq 1 ] && [ "$HAS_STRONG" -eq 0 ] && [ -z "$OUTSIDE_PATHS" ]; then
    exit 0
fi

# No strong signal and nothing outside the sandbox → silent
if [ -z "$OUTSIDE_PATHS" ] && [ "$HAS_STRONG" -eq 0 ]; then
    exit 0
fi

# ---------------------------------------------------------------------------
# 7. Network-specific handling
# ---------------------------------------------------------------------------
NET_STATUS=$(jq -r 'if .net_blocked then "blocked" else "allowed" end' "$NONO_CAP_FILE" 2>/dev/null || printf 'unknown\n')

# Strong signal + no filesystem path + network blocked → network advice
if [ "$HAS_STRONG" -eq 1 ] && [ -z "$OUTSIDE_PATHS" ] && [ "$NET_STATUS" = "blocked" ]; then
    CONTEXT="[NONO SANDBOX] Possible sandbox network block. Network is blocked in this sandbox session and an operation failed with an access-denied signal but no blocked filesystem path was identified.

Tell the user to restart with network access:

  nono run --net-allow -- claude

This is the only solution. The sandbox cannot be modified from within."
    jq -n --arg ctx "$CONTEXT" '{
      "hookSpecificOutput": {
        "hookEventName": "PostToolUseFailure",
        "additionalContext": $ctx
      }
    }'
    exit 0
fi

# ---------------------------------------------------------------------------
# 8. Deduplication: suppress repeat messages for the same blocked path
# ---------------------------------------------------------------------------
FIRST_OUTSIDE=$(printf '%s\n' "$OUTSIDE_PATHS" | grep -v '^$' | head -1)

# Include cap file inode so PID-reuse across sessions doesn't collide on the seen file
CAP_INODE=""
if command -v stat &>/dev/null; then
    CAP_INODE=$(stat -f "%i" "$NONO_CAP_FILE" 2>/dev/null \
        || stat -c "%i" "$NONO_CAP_FILE" 2>/dev/null) || true
fi

NONO_HOOK_HASH=""
if command -v sha256sum &>/dev/null; then
    NONO_HOOK_HASH=$(printf '%s%s%s' "$CAP_INODE" "$NONO_CAP_FILE" "$FIRST_OUTSIDE" \
        | sha256sum | awk '{print $1}')
elif command -v shasum &>/dev/null; then
    NONO_HOOK_HASH=$(printf '%s%s%s' "$CAP_INODE" "$NONO_CAP_FILE" "$FIRST_OUTSIDE" \
        | shasum -a 256 | awk '{print $1}')
fi

if [ -n "$NONO_HOOK_HASH" ]; then
    SEEN_FILE="${TMPDIR:-/tmp}/nono-hook-seen-$NONO_HOOK_HASH"
    if [ -f "$SEEN_FILE" ]; then
        exit 0
    fi
    touch "$SEEN_FILE" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 9. Determine confidence level
# ---------------------------------------------------------------------------
if [ "$HAS_STRONG" -eq 1 ] && [ -n "$OUTSIDE_PATHS" ]; then
    LEVEL="Confirmed"
else
    LEVEL="Possible"
fi

# ---------------------------------------------------------------------------
# 10. Build nearby allowed paths (path-boundary safe)
# ---------------------------------------------------------------------------
NEARBY=""
if [ -n "$FIRST_OUTSIDE" ]; then
    PARENT=$(dirname "$FIRST_OUTSIDE")
    GRANDPARENT=$(dirname "$PARENT")

    while IFS= read -r cap_entry; do
        local_apath=$(printf '%s\n' "$cap_entry" | jq -r '.path'   2>/dev/null)
        local_acc=$(printf '%s\n'   "$cap_entry" | jq -r '.access' 2>/dev/null)
        [ -z "$local_apath" ] && continue
        APAR=$(dirname "$local_apath")

        if [[ "$local_apath" == "$PARENT" ]]  || [[ "$local_apath" == "$PARENT/"* ]]  || \
           [[ "$PARENT"      == "$local_apath" ]] || [[ "$PARENT" == "$local_apath/"* ]] || \
           [ "$APAR" = "$PARENT" ] || [ "$APAR" = "$GRANDPARENT" ]; then
            NEARBY="${NEARBY}  ${local_apath} (${local_acc})
"
        fi
    done < <(jq -c '.fs[]' "$NONO_CAP_FILE" 2>/dev/null)
fi

# ---------------------------------------------------------------------------
# 11. Emit diagnostic context
# ---------------------------------------------------------------------------
if [ -n "$FIRST_OUTSIDE" ]; then
    RESTART_CMD="nono run --allow $FIRST_OUTSIDE -- claude"
else
    RESTART_CMD="nono run --allow /path/to/needed -- claude"
fi

CONTEXT="[NONO SANDBOX] $LEVEL sandbox access violation. Tell the user the path is not accessible in the nono sandbox and they need to restart with:

  $RESTART_CMD"

if [ -n "$NEARBY" ]; then
    CONTEXT="${CONTEXT}

Nearby allowed paths:
${NEARBY}"
fi

CONTEXT="${CONTEXT}
Network: $NET_STATUS"

jq -n --arg ctx "$CONTEXT" '{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUseFailure",
    "additionalContext": $ctx
  }
}'
