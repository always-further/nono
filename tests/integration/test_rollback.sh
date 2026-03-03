#!/bin/bash
# Rollback/Undo System Tests
# Tests the rollback lifecycle: session creation, listing, showing, verifying

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Rollback Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "rollback suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/workdir"
echo "original content" > "$TMPDIR/workdir/file.txt"

echo ""
echo "Test directory: $TMPDIR"
echo ""

# =============================================================================
# Rollback List (baseline)
# =============================================================================

echo "--- Rollback List ---"

# rollback list should work (may have existing sessions from prior runs)
expect_success "rollback list exits 0" \
    "$NONO_BIN" rollback list

# =============================================================================
# Rollback Session Creation
# =============================================================================

echo ""
echo "--- Rollback Session Creation ---"

# Run a command with --rollback that modifies a file
expect_success "rollback session with file modification" \
    "$NONO_BIN" run --rollback --no-rollback-prompt --allow "$TMPDIR/workdir" -- \
    sh -c "echo 'modified content' > '$TMPDIR/workdir/file.txt'"

# Run a command with --rollback that creates a new file
expect_success "rollback session with file creation" \
    "$NONO_BIN" run --rollback --no-rollback-prompt --allow "$TMPDIR/workdir" -- \
    sh -c "echo 'new file' > '$TMPDIR/workdir/new.txt'"

# =============================================================================
# Rollback List (after sessions)
# =============================================================================

echo ""
echo "--- Rollback List After Sessions ---"

# List should still work and show sessions
expect_success "rollback list after sessions exits 0" \
    "$NONO_BIN" rollback list

# List output should contain our workdir path
expect_output_contains "rollback list shows workdir" "workdir" \
    "$NONO_BIN" rollback list

# =============================================================================
# Rollback Show
# =============================================================================

echo ""
echo "--- Rollback Show ---"

# Get the most recent session ID from rollback list
set +e
session_list=$("$NONO_BIN" rollback list </dev/null 2>&1)
set -e

# Extract a session ID (format: YYYYMMDD-HHMMSS-PID)
session_id=$(echo "$session_list" | grep -oE '[0-9]{8}-[0-9]{6}-[0-9]+' | head -1)

if [[ -n "$session_id" ]]; then
    expect_success "rollback show session succeeds" \
        "$NONO_BIN" rollback show "$session_id"
else
    skip_test "rollback show session succeeds" "no session ID found in list output"
fi

# =============================================================================
# Rollback Verify
# =============================================================================

echo ""
echo "--- Rollback Verify ---"

if [[ -n "$session_id" ]]; then
    expect_success "rollback verify session succeeds" \
        "$NONO_BIN" rollback verify "$session_id"
else
    skip_test "rollback verify session succeeds" "no session ID found in list output"
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
