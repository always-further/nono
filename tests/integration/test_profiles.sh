#!/bin/bash
# Built-in Profile Tests
# Verifies built-in profiles load, produce correct dry-run output, and enforce expected policies

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Profile Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "profiles suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/workdir"
echo "readable content" > "$TMPDIR/workdir/file.txt"

echo ""
echo "Test directory: $TMPDIR"
echo ""

expect_captured_output_contains() {
    local name="$1"
    local expected_str="$2"
    local output="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if echo "$output" | grep -q "$expected_str"; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: $name"
        echo "       Output missing: '$expected_str'"
        local stripped
        stripped=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
        echo "       Actual output: ${stripped:0:2000}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

expect_captured_output_not_contains() {
    local name="$1"
    local unexpected_str="$2"
    local output="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if echo "$output" | grep -q "$unexpected_str"; then
        echo -e "  ${RED}FAIL${NC}: $name"
        echo "       Output should NOT contain: '$unexpected_str'"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi
}

# =============================================================================
# Profile Dry Run
# =============================================================================

echo "--- Profile Dry Run ---"

set +e
CLAUDE_DRY_RUN_OUTPUT=$("$NONO_BIN" run --profile claude-code --dry-run -- echo "test" </dev/null 2>&1)
CLAUDE_DRY_RUN_EXIT=$?
set -e

run_test "claude-code profile dry-run exits 0" 0 bash -lc "exit $CLAUDE_DRY_RUN_EXIT"

if skip_unless_linux "claude-code profile dry-run omits macOS keychain warning on Linux"; then
    expect_captured_output_not_contains "claude-code profile dry-run omits macOS keychain warning on Linux" "login.keychain-db" \
        "$CLAUDE_DRY_RUN_OUTPUT"
fi

expect_success "opencode profile dry-run exits 0" \
    "$NONO_BIN" run --profile opencode --dry-run -- echo "test"

expect_failure "nonexistent profile exits non-zero" \
    "$NONO_BIN" run --profile nonexistent-profile --dry-run -- echo "test"

expect_captured_output_contains "claude-code profile lists .claude in dry-run" ".claude" \
    "$CLAUDE_DRY_RUN_OUTPUT"

expect_captured_output_contains "dry-run output shows Capabilities section" "Capabilities:" \
    "$CLAUDE_DRY_RUN_OUTPUT"

# =============================================================================
# Profile Enforcement
# =============================================================================

echo ""
echo "--- Profile Enforcement ---"

# claude-code profile blocks rm by default
expect_failure "claude-code profile blocks rm" \
    "$NONO_BIN" run --profile claude-code --allow "$TMPDIR" -- rm "$TMPDIR/workdir/file.txt"

# Verify file still exists
run_test "file not deleted (rm was blocked by profile)" 0 test -f "$TMPDIR/workdir/file.txt"

# claude-code profile blocks pip by default
if command_exists pip; then
    expect_failure "claude-code profile blocks pip" \
        "$NONO_BIN" run --profile claude-code --allow "$TMPDIR" -- pip --version
else
    skip_test "claude-code profile blocks pip" "pip not installed"
fi

# claude-code profile allows cat on granted path
expect_success "claude-code profile allows cat on granted path" \
    "$NONO_BIN" run --profile claude-code --allow "$TMPDIR" -- cat "$TMPDIR/workdir/file.txt"

# =============================================================================
# Profile with Workdir
# =============================================================================

echo ""
echo "--- Profile with Workdir ---"

expect_success "profile with --workdir flag accepted" \
    "$NONO_BIN" run --profile claude-code --workdir "$TMPDIR/workdir" --dry-run -- echo "workdir test"

# With --allow-cwd and --workdir, the workdir should be accessible
expect_success "profile with --workdir and --allow-cwd accepted" \
    "$NONO_BIN" run --profile claude-code --workdir "$TMPDIR/workdir" --allow-cwd --dry-run -- echo "workdir test"

# =============================================================================
# Summary
# =============================================================================

print_summary
