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
trap 'cleanup_test_dir "$TMPDIR"; rm -rf "$AUDIT_DIR"' EXIT

# Use a dedicated rollback root so we don't pollute ~/.nono/rollbacks
AUDIT_DIR=$(mktemp -d)
# Helper: count session.json files under the rollback root
count_sessions() {
    find "$AUDIT_DIR/.nono/rollbacks" -name session.json 2>/dev/null | wc -l | tr -d ' '
}

# Helper: get the most recent session.json
latest_session_json() {
    find "$AUDIT_DIR/.nono/rollbacks" -name session.json 2>/dev/null | sort | tail -1
}

# Prepare the rollback root
mkdir -p "$AUDIT_DIR/.nono/rollbacks"

# Override HOME so nono writes sessions to our temp dir
export HOME="$AUDIT_DIR"

echo ""
echo "Test directory: $TMPDIR"
echo "Audit directory: $AUDIT_DIR/.nono/rollbacks"
echo ""

# =============================================================================
# Audit always-on (default supervised mode)
# =============================================================================

echo "--- Audit Always-On (Supervised Default) ---"

# Test 1: Plain run (no --rollback) should create a session
TESTS_RUN=$((TESTS_RUN + 1))
before=$(count_sessions)
"$NONO_BIN" run --silent --allow "$TMPDIR" -- echo "audit test" </dev/null >/dev/null 2>&1 || true
after=$(count_sessions)
if [[ "$after" -gt "$before" ]]; then
    echo -e "  ${GREEN}PASS${NC}: plain run creates audit session"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: plain run creates audit session"
    echo "       Sessions before: $before, after: $after"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 2: Session.json contains expected fields
TESTS_RUN=$((TESTS_RUN + 1))
session_file=$(latest_session_json)
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

# Test 3: Read-only session (--allow-cwd defaults to read) should still create audit
TESTS_RUN=$((TESTS_RUN + 1))
before=$(count_sessions)
"$NONO_BIN" run --silent --read "$TMPDIR" -- echo "readonly audit" </dev/null >/dev/null 2>&1 || true
after=$(count_sessions)
if [[ "$after" -gt "$before" ]]; then
    echo -e "  ${GREEN}PASS${NC}: read-only session creates audit"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: read-only session creates audit"
    echo "       Sessions before: $before, after: $after"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 4: Session records correct exit code
TESTS_RUN=$((TESTS_RUN + 1))
"$NONO_BIN" run --silent --allow "$TMPDIR" -- sh -c "exit 42" </dev/null >/dev/null 2>&1 || true
session_file=$(latest_session_json)
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
before=$(count_sessions)
"$NONO_BIN" run --silent --no-audit --allow "$TMPDIR" -- echo "no audit" </dev/null >/dev/null 2>&1 || true
after=$(count_sessions)
if [[ "$after" -eq "$before" ]]; then
    echo -e "  ${GREEN}PASS${NC}: --no-audit suppresses audit session"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: --no-audit suppresses audit session"
    echo "       Sessions before: $before, after: $after"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test: --no-audit + --rollback is rejected by clap
expect_failure "--no-audit conflicts with --rollback" \
    "$NONO_BIN" run --silent --no-audit --rollback --allow "$TMPDIR" -- echo "conflict"

# =============================================================================
# Audit with rollback
# =============================================================================

echo ""
echo "--- Audit with Rollback ---"

# Test 6: --rollback with writable path creates session with snapshot data
TESTS_RUN=$((TESTS_RUN + 1))
WRITE_DIR=$(mktemp -d "$TMPDIR/write-XXXXXX")
before=$(count_sessions)
"$NONO_BIN" run --silent --rollback --no-rollback-prompt --allow "$WRITE_DIR" -- touch "$WRITE_DIR/testfile" </dev/null >/dev/null 2>&1 || true
after=$(count_sessions)
session_file=$(latest_session_json)
if [[ "$after" -gt "$before" ]] && [[ -n "$session_file" ]] && grep -q '"snapshot_count"' "$session_file"; then
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
    echo "       Sessions before: $before, after: $after"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 7: --rollback with read-only paths still creates audit (but no snapshots)
TESTS_RUN=$((TESTS_RUN + 1))
before=$(count_sessions)
"$NONO_BIN" run --silent --rollback --no-rollback-prompt --read "$TMPDIR" -- echo "rollback readonly" </dev/null >/dev/null 2>&1 || true
after=$(count_sessions)
session_file=$(latest_session_json)
if [[ "$after" -gt "$before" ]] && [[ -n "$session_file" ]]; then
    snapshot_count=$(grep -o '"snapshot_count": [0-9]*' "$session_file" | grep -o '[0-9]*$')
    if [[ "$snapshot_count" -eq 0 ]]; then
        echo -e "  ${GREEN}PASS${NC}: rollback + read-only creates audit without snapshots"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: rollback + read-only creates audit without snapshots"
        echo "       snapshot_count: $snapshot_count (expected 0)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "  ${RED}FAIL${NC}: rollback + read-only creates audit without snapshots"
    echo "       Sessions before: $before, after: $after"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Direct mode (nono wrap) should NOT create audit
# =============================================================================

echo ""
echo "--- Direct Mode (nono wrap) ---"

# Test 8: nono wrap does not create audit sessions (no parent process)
TESTS_RUN=$((TESTS_RUN + 1))
before=$(count_sessions)
"$NONO_BIN" wrap --allow "$TMPDIR" -- echo "wrap no audit" </dev/null >/dev/null 2>&1 || true
after=$(count_sessions)
if [[ "$after" -eq "$before" ]]; then
    echo -e "  ${GREEN}PASS${NC}: nono wrap does not create audit session"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: nono wrap does not create audit session"
    echo "       Sessions before: $before, after: $after"
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
