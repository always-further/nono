#!/bin/bash
# Audit Trail Tests
# Verifies that audit sessions are recorded correctly in all execution scenarios.
# Audit is on by default for supervised execution and can be opted out with --no-audit.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Audit Trail Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "audit suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

# Use the real rollback root (same as nono uses via dirs::home_dir)
ROLLBACK_ROOT="$HOME/.nono/rollbacks"
mkdir -p "$ROLLBACK_ROOT"

# Helper: find the session.json for a specific nono PID.
# Session dirs are named YYYYMMDD-HHMMSS-PID so we can grep for the PID suffix.
find_session_for_pid() {
    local pid="$1"
    local match=""
    match=$(grep -rl "\"session_id\": \"[^\"]*-${pid}\"" "$ROLLBACK_ROOT" --include='session.json' 2>/dev/null | head -1) || true
    echo "$match"
}

# Helper: run nono and return its PID (waits for completion)
# Usage: run_nono_get_pid <args...>
# Sets LAST_NONO_PID after return
run_nono() {
    "$NONO_BIN" "$@" </dev/null >/dev/null 2>&1 &
    LAST_NONO_PID=$!
    wait $LAST_NONO_PID 2>/dev/null || true
}

echo ""
echo "Test directory: $TMPDIR"
echo "Rollback root: $ROLLBACK_ROOT"
echo ""

# =============================================================================
# Audit always-on (default supervised mode)
# =============================================================================

echo "--- Audit Always-On (Supervised Default) ---"

# Test 1: Plain run (no --rollback) should create a session
TESTS_RUN=$((TESTS_RUN + 1))
run_nono run --silent --allow-cwd --allow "$TMPDIR" -- echo "audit test"
session_file=$(find_session_for_pid "$LAST_NONO_PID")
if [[ -n "$session_file" && -f "$session_file" ]]; then
    echo -e "  ${GREEN}PASS${NC}: plain run creates audit session"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: plain run creates audit session"
    echo "       PID: $LAST_NONO_PID, session_file: ${session_file:-not found}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 2: Session.json contains expected fields
TESTS_RUN=$((TESTS_RUN + 1))
if [[ -n "$session_file" && -f "$session_file" ]]; then
    has_fields=true
    for field in session_id started ended command exit_code; do
        if ! grep -q "\"$field\"" "$session_file"; then
            has_fields=false
            break
        fi
    done
    if $has_fields; then
        echo -e "  ${GREEN}PASS${NC}: session.json contains required fields"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: session.json contains required fields"
        echo "       Content: $(head -20 "$session_file")"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "  ${RED}FAIL${NC}: session.json contains required fields"
    echo "       No session.json found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 3: Read-only session should still create audit
TESTS_RUN=$((TESTS_RUN + 1))
run_nono run --silent --allow-cwd --read "$TMPDIR" -- echo "readonly audit"
session_file=$(find_session_for_pid "$LAST_NONO_PID")
if [[ -n "$session_file" && -f "$session_file" ]]; then
    echo -e "  ${GREEN}PASS${NC}: read-only session creates audit"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: read-only session creates audit"
    echo "       PID: $LAST_NONO_PID, session_file: ${session_file:-not found}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 4: Session records correct exit code
TESTS_RUN=$((TESTS_RUN + 1))
run_nono run --silent --allow-cwd --allow "$TMPDIR" -- sh -c "exit 42"
session_file=$(find_session_for_pid "$LAST_NONO_PID")
if [[ -n "$session_file" ]] && grep -q '"exit_code": 42' "$session_file"; then
    echo -e "  ${GREEN}PASS${NC}: session records non-zero exit code"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: session records non-zero exit code"
    if [[ -n "$session_file" ]]; then
        echo "       exit_code in file: $(grep exit_code "$session_file")"
    fi
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# --no-audit opt-out
# =============================================================================

echo ""
echo "--- Audit Opt-Out (--no-audit) ---"

# Test 5: --no-audit suppresses session creation
TESTS_RUN=$((TESTS_RUN + 1))
run_nono run --silent --no-audit --allow-cwd --allow "$TMPDIR" -- echo "no audit"
session_file=$(find_session_for_pid "$LAST_NONO_PID")
if [[ -z "$session_file" ]]; then
    echo -e "  ${GREEN}PASS${NC}: --no-audit suppresses audit session"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: --no-audit suppresses audit session"
    echo "       Unexpected session: $session_file"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test: --no-audit + --rollback is rejected by clap
expect_failure "--no-audit conflicts with --rollback" \
    "$NONO_BIN" run --silent --no-audit --rollback --allow-cwd --allow "$TMPDIR" -- echo "conflict"

# =============================================================================
# Audit with rollback
# =============================================================================

echo ""
echo "--- Audit with Rollback ---"

# Test 6: --rollback with writable path creates session with snapshot data
TESTS_RUN=$((TESTS_RUN + 1))
WRITE_DIR=$(mktemp -d "$TMPDIR/write-XXXXXX")
run_nono run --silent --rollback --no-rollback-prompt --allow-cwd --allow "$WRITE_DIR" -- touch "$WRITE_DIR/testfile"
session_file=$(find_session_for_pid "$LAST_NONO_PID")
if [[ -n "$session_file" ]] && grep -q '"snapshot_count"' "$session_file"; then
    snapshot_count=$(grep -o '"snapshot_count": [0-9]*' "$session_file" | grep -o '[0-9]*$')
    if [[ "$snapshot_count" -gt 0 ]]; then
        echo -e "  ${GREEN}PASS${NC}: rollback session has snapshot data (count=$snapshot_count)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: rollback session has snapshot data"
        echo "       snapshot_count: $snapshot_count"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "  ${RED}FAIL${NC}: rollback session has snapshot data"
    echo "       session_file: ${session_file:-not found}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Note: --rollback with read-only user paths is not tested here because
# platform groups (system_write_macos) grant write to parent directories
# (e.g. /private/var/folders) which the snapshot tracker picks up.

# =============================================================================
# Direct mode (nono wrap) should NOT create audit
# =============================================================================

echo ""
echo "--- Direct Mode (nono wrap) ---"

# Test 8: nono wrap does not create audit sessions (no parent process)
TESTS_RUN=$((TESTS_RUN + 1))
run_nono wrap --allow "$TMPDIR" -- echo "wrap no audit"
session_file=$(find_session_for_pid "$LAST_NONO_PID")
if [[ -z "$session_file" ]]; then
    echo -e "  ${GREEN}PASS${NC}: nono wrap does not create audit session"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: nono wrap does not create audit session"
    echo "       Unexpected session: $session_file"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# nono audit list
# =============================================================================

echo ""
echo "--- Audit List Command ---"

# Test 9: nono audit list shows sessions
TESTS_RUN=$((TESTS_RUN + 1))
set +e
list_output=$("$NONO_BIN" audit list 2>&1)
list_exit=$?
set -e
if [[ "$list_exit" -eq 0 ]] && echo "$list_output" | grep -q "session"; then
    echo -e "  ${GREEN}PASS${NC}: audit list shows sessions"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: audit list shows sessions"
    echo "       Exit: $list_exit"
    echo "       Output: ${list_output:0:500}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
