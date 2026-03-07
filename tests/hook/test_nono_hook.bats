#!/usr/bin/env bats
# tests/hook/test_nono_hook.bats
# Black-box tests for crates/nono-cli/data/hooks/nono-hook.sh
#
# Requirements: bats-core  (brew install bats-core / apt install bats)
# Run: bats tests/hook/test_nono_hook.bats
#      make test-hook

HOOK="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)/crates/nono-cli/data/hooks/nono-hook.sh"
FIXTURES="$(dirname "$BATS_TEST_FILENAME")/fixtures"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Create a cap file with one allowed path + .npm read-only entry
make_cap() {
    local allowed_path="${1:-/Users/testuser/project}"
    local net_blocked="${2:-false}"
    cat > "$BATS_TEST_TMPDIR/caps.json" <<EOF
{
  "fs": [
    { "path": "$allowed_path", "access": "readwrite" },
    { "path": "/Users/testuser/.npm", "access": "read" }
  ],
  "net_blocked": $net_blocked
}
EOF
    export NONO_CAP_FILE="$BATS_TEST_TMPDIR/caps.json"
}

setup() {
    export TMPDIR="$BATS_TEST_TMPDIR"
    make_cap "/Users/testuser/project" "false"
}

teardown() {
    unset NONO_CAP_FILE TMPDIR
}

assert_contains() {
    local needle="$1"
    if ! echo "$output" | grep -qi -e "$needle"; then
        echo "Expected output to contain: $needle" >&3
        echo "Actual output: $output" >&3
        return 1
    fi
}

assert_not_contains() {
    local needle="$1"
    if echo "$output" | grep -qi -e "$needle"; then
        echo "Expected output NOT to contain: $needle" >&3
        echo "Actual output: $output" >&3
        return 1
    fi
}

assert_fired() {
    [ "$status" -eq 0 ] || { echo "Hook exited with status $status" >&3; return 1; }
    assert_contains "hookSpecificOutput"
}

assert_silent() {
    [ "$status" -eq 0 ] || { echo "Hook exited with status $status" >&3; return 1; }
    if [ -n "$output" ]; then
        echo "Expected no output but got: $output" >&3
        return 1
    fi
}

# ---------------------------------------------------------------------------
# SILENT scenarios
# ---------------------------------------------------------------------------

@test "node MODULE_NOT_FOUND for path inside allow list is silent" {
    run bash "$HOOK" < "$FIXTURES/node_module_not_found_allowed.json"
    assert_silent
}

@test "python FileNotFoundError for relative path inside allow list is silent" {
    run bash "$HOOK" < "$FIXTURES/python_enoent_relative_allowed.json"
    assert_silent
}

@test "dotnet FileNotFoundException for allowed path is silent" {
    run bash "$HOOK" < "$FIXTURES/dotnet_file_not_found_allowed.json"
    assert_silent
}

@test "zig error.FileNotFound for allowed path is silent" {
    run bash "$HOOK" < "$FIXTURES/zig_file_not_found_allowed.json"
    assert_silent
}

@test "bash command not found is silent" {
    run bash "$HOOK" < "$FIXTURES/bash_command_not_found.json"
    assert_silent
}

@test "Bash tool ENOENT for allowed path is silent" {
    run bash "$HOOK" < "$FIXTURES/bash_tool_enoent_allowed.json"
    assert_silent
}

# ---------------------------------------------------------------------------
# CONFIRMED scenarios
# ---------------------------------------------------------------------------

@test "EPERM on blocked path is confirmed" {
    run bash "$HOOK" < "$FIXTURES/eperm_blocked.json"
    assert_fired
    assert_contains "Confirmed"
}

@test "pnpm lowercase operation not permitted is confirmed" {
    run bash "$HOOK" < "$FIXTURES/pnpm_lowercase_eperm.json"
    assert_fired
    assert_contains "Confirmed"
}

@test "python Permission denied on blocked path is confirmed" {
    run bash "$HOOK" < "$FIXTURES/python_permission_denied.json"
    assert_fired
    assert_contains "Confirmed"
}

@test "go permission denied on blocked path is confirmed" {
    run bash "$HOOK" < "$FIXTURES/go_permission_denied.json"
    assert_fired
    assert_contains "Confirmed"
}

@test "java AccessDeniedException is confirmed" {
    run bash "$HOOK" < "$FIXTURES/java_access_denied.json"
    assert_fired
    assert_contains "Confirmed"
}

@test "dotnet UnauthorizedAccessException is confirmed" {
    run bash "$HOOK" < "$FIXTURES/dotnet_unauthorized.json"
    assert_fired
    assert_contains "Confirmed"
}

@test "zig error.AccessDenied on blocked path is confirmed" {
    run bash "$HOOK" < "$FIXTURES/zig_access_denied.json"
    assert_fired
    assert_contains "Confirmed"
}

@test "swift NSPOSIXErrorDomain Code=13 is confirmed" {
    run bash "$HOOK" < "$FIXTURES/swift_posix.json"
    assert_fired
    assert_contains "Confirmed"
}

@test "swift NSCocoaErrorDomain permission is confirmed" {
    run bash "$HOOK" < "$FIXTURES/swift_cocoa.json"
    assert_fired
    assert_contains "Confirmed"
}

# ---------------------------------------------------------------------------
# POSSIBLE scenarios
# ---------------------------------------------------------------------------

@test "dotnet Could not find file on blocked path is possible" {
    run bash "$HOOK" < "$FIXTURES/dotnet_file_not_found_blocked.json"
    assert_fired
    assert_contains "Possible"
}

@test "zig error.FileNotFound on blocked path is possible" {
    run bash "$HOOK" < "$FIXTURES/zig_file_not_found_blocked.json"
    assert_fired
    assert_contains "Possible"
}

@test "SSH Permission denied publickey is possible (no filesystem path)" {
    run bash "$HOOK" < "$FIXTURES/ssh_publickey.json"
    assert_fired
    assert_contains "Possible"
}

# ---------------------------------------------------------------------------
# Gap #1: Network blocking gives --net-allow advice
# ---------------------------------------------------------------------------

@test "strong signal with no path and net_blocked gives --net-allow advice" {
    make_cap "/Users/testuser/project" "true"
    run bash "$HOOK" < "$FIXTURES/ssh_publickey.json"
    assert_fired
    assert_contains "net-allow"
}

@test "network blocked but filesystem path found gives --allow not --net-allow" {
    make_cap "/Users/testuser/project" "true"
    run bash "$HOOK" < "$FIXTURES/eperm_blocked.json"
    assert_fired
    assert_contains "--allow"
    assert_not_contains "net-allow"
}

# ---------------------------------------------------------------------------
# Gap #2: Tool-name-aware thresholds
# ---------------------------------------------------------------------------

@test "Read tool ENOENT on blocked path is confirmed (threshold promotion)" {
    run bash "$HOOK" < "$FIXTURES/read_tool_enoent_blocked.json"
    assert_fired
    assert_contains "Confirmed"
}

@test "Bash tool ENOENT on blocked path is only possible (no promotion)" {
    cat > "$BATS_TEST_TMPDIR/bash_enoent_blocked.json" <<'EOF'
{
  "tool_name": "Bash",
  "hook_event_name": "PostToolUseFailure",
  "cwd": "/Users/testuser/project",
  "tool_input": { "command": "cat /Users/testuser/secrets/missing.txt" },
  "tool_result": "cat: /Users/testuser/secrets/missing.txt: No such file or directory"
}
EOF
    run bash "$HOOK" < "$BATS_TEST_TMPDIR/bash_enoent_blocked.json"
    assert_fired
    assert_contains "Possible"
}

# ---------------------------------------------------------------------------
# Gap #3: Path-boundary coverage check (.npm must not cover .npmrc)
# ---------------------------------------------------------------------------

@test "path boundary: .npm does not cover .npmrc (hook fires on .npmrc)" {
    # The cap file includes /Users/testuser/.npm (read).
    # The fixture accesses /Users/testuser/.npmrc — NOT covered by .npm.
    # The hook must fire (not be silent) because .npmrc is outside the allow list.
    run bash "$HOOK" < "$FIXTURES/nearby_paths_npmrc.json"
    assert_fired
}

# ---------------------------------------------------------------------------
# Gap #4: stdin size bound
# ---------------------------------------------------------------------------

@test "hook handles oversized stdin without hanging" {
    # Build a payload > 64 KB of harmless padding + a permission error at the end.
    # The hook must complete within 5 seconds regardless of truncation behavior.
    {
        printf '{"tool_name":"Bash","hook_event_name":"PostToolUseFailure","cwd":"/Users/testuser/project","tool_input":{"command":"make"},"tool_result":"'
        # 200 KB of x's
        python3 -c "import sys; sys.stdout.write('x' * 204800)" 2>/dev/null \
            || dd if=/dev/zero bs=204800 count=1 2>/dev/null | tr '\0' 'x'
        printf '"}'
    } > "$BATS_TEST_TMPDIR/large_payload.json"

    run timeout 5 bash "$HOOK" < "$BATS_TEST_TMPDIR/large_payload.json"
    [ "$status" -ne 124 ]  # 124 = timed out
}

# ---------------------------------------------------------------------------
# Gap #5: python3 fallback for relative path resolution
# ---------------------------------------------------------------------------

@test "relative path inside allow list is silent without python3" {
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    printf '#!/bin/bash\nexit 127\n' > "$BATS_TEST_TMPDIR/bin/python3"
    chmod +x "$BATS_TEST_TMPDIR/bin/python3"
    run env PATH="$BATS_TEST_TMPDIR/bin:$PATH" bash "$HOOK" < "$FIXTURES/python_enoent_relative_allowed.json"
    assert_silent
}

# ---------------------------------------------------------------------------
# Gap #6: Deduplication
# ---------------------------------------------------------------------------

@test "same blocked path fires only once per session (deduplication)" {
    run bash "$HOOK" < "$FIXTURES/eperm_blocked.json"
    assert_fired

    run bash "$HOOK" < "$FIXTURES/eperm_blocked.json"
    assert_silent
}

@test "different blocked paths each fire once" {
    run bash "$HOOK" < "$FIXTURES/eperm_blocked.json"
    assert_fired

    run bash "$HOOK" < "$FIXTURES/go_permission_denied.json"
    assert_fired
}

# ---------------------------------------------------------------------------
# Gap #7: Symlink canonicalization
# ---------------------------------------------------------------------------

@test "path via symlink to allowed directory is silent" {
    mkdir -p "$BATS_TEST_TMPDIR/real"
    ln -sfn "$BATS_TEST_TMPDIR/real" "$BATS_TEST_TMPDIR/link"

    cat > "$BATS_TEST_TMPDIR/caps.json" <<EOF
{
  "fs": [{ "path": "$BATS_TEST_TMPDIR/real", "access": "readwrite" }],
  "net_blocked": false
}
EOF
    export NONO_CAP_FILE="$BATS_TEST_TMPDIR/caps.json"

    cat > "$BATS_TEST_TMPDIR/symlink_payload.json" <<EOF
{
  "tool_name": "Bash",
  "hook_event_name": "PostToolUseFailure",
  "cwd": "$BATS_TEST_TMPDIR/real",
  "tool_input": { "command": "cat $BATS_TEST_TMPDIR/link/missing.txt" },
  "tool_result": "cat: $BATS_TEST_TMPDIR/link/missing.txt: No such file or directory"
}
EOF
    run bash "$HOOK" < "$BATS_TEST_TMPDIR/symlink_payload.json"
    assert_silent
}

@test "path via symlink to blocked directory still fires" {
    mkdir -p "$BATS_TEST_TMPDIR/real_blocked"
    mkdir -p "$BATS_TEST_TMPDIR/allowed"
    ln -sfn "$BATS_TEST_TMPDIR/real_blocked" "$BATS_TEST_TMPDIR/link_blocked"

    cat > "$BATS_TEST_TMPDIR/caps.json" <<EOF
{
  "fs": [{ "path": "$BATS_TEST_TMPDIR/allowed", "access": "readwrite" }],
  "net_blocked": false
}
EOF
    export NONO_CAP_FILE="$BATS_TEST_TMPDIR/caps.json"

    cat > "$BATS_TEST_TMPDIR/symlink_blocked_payload.json" <<EOF
{
  "tool_name": "Bash",
  "hook_event_name": "PostToolUseFailure",
  "cwd": "$BATS_TEST_TMPDIR/allowed",
  "tool_input": { "command": "cat $BATS_TEST_TMPDIR/link_blocked/secret.txt" },
  "tool_result": "cat: $BATS_TEST_TMPDIR/link_blocked/secret.txt: Operation not permitted"
}
EOF
    run bash "$HOOK" < "$BATS_TEST_TMPDIR/symlink_blocked_payload.json"
    assert_fired
    assert_contains "Confirmed"
}

# ---------------------------------------------------------------------------
# Output format sanity
# ---------------------------------------------------------------------------

@test "fired output is valid JSON with hookSpecificOutput.additionalContext" {
    run bash "$HOOK" < "$FIXTURES/eperm_blocked.json"
    assert_fired
    echo "$output" | jq -e '.hookSpecificOutput.additionalContext' > /dev/null
}

@test "fired output includes nono run restart command" {
    run bash "$HOOK" < "$FIXTURES/eperm_blocked.json"
    assert_fired
    assert_contains "nono run"
    assert_contains "--allow"
}

@test "no NONO_CAP_FILE env var produces no output" {
    unset NONO_CAP_FILE
    run bash "$HOOK" < "$FIXTURES/eperm_blocked.json"
    assert_silent
}

@test "missing cap file path produces no output" {
    export NONO_CAP_FILE="/nonexistent/caps.json"
    run bash "$HOOK" < "$FIXTURES/eperm_blocked.json"
    assert_silent
}
