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
NONO_BIN_ABS="$(cd "$(dirname "$NONO_BIN")" && pwd)/$(basename "$NONO_BIN")"

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/workdir"
echo "readable content" > "$TMPDIR/workdir/file.txt"

echo ""
echo "Test directory: $TMPDIR"
echo ""

# =============================================================================
# Profile Dry Run
# =============================================================================

echo "--- Profile Dry Run ---"

expect_success "claude-code profile dry-run exits 0" \
    "$NONO_BIN" run --profile claude-code --dry-run -- echo "test"

expect_success "codex profile dry-run exits 0" \
    "$NONO_BIN" run --profile codex --dry-run -- echo "test"

expect_success "opencode profile dry-run exits 0" \
    "$NONO_BIN" run --profile opencode --dry-run -- echo "test"

expect_failure "nonexistent profile exits non-zero" \
    "$NONO_BIN" run --profile nonexistent-profile --dry-run -- echo "test"

expect_output_contains "claude-code profile lists .claude in dry-run" ".claude" \
    "$NONO_BIN" run --profile claude-code --dry-run -- echo "test"

if [[ -d "$HOME/.codex" ]]; then
    expect_output_contains "codex profile lists .codex in dry-run" ".codex" \
        "$NONO_BIN" run --profile codex --dry-run -- echo "test"
else
    expect_output_not_contains "codex profile hides missing .codex by default" ".codex" \
        "$NONO_BIN" run --profile codex --dry-run -- echo "test"
    expect_output_contains "codex profile shows missing .codex warning with -v" \
        "Profile path '\$HOME/.codex' does not exist, skipping" \
        "$NONO_BIN" run -v --profile codex --dry-run -- echo "test"
fi

expect_output_contains "opencode profile lists OpenTUI data dir in dry-run" ".local/share/opentui" \
    "$NONO_BIN" run --profile opencode --dry-run -- echo "test"

expect_output_contains "dry-run output shows Capabilities section" "Capabilities:" \
    "$NONO_BIN" run --profile claude-code --dry-run -- echo "test"

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

# codex profile allows cargo from user-local runtime paths
if command_exists cargo; then
    expect_success "codex profile allows cargo from runtime path" \
        bash -lc "cd \"$TMPDIR/workdir\" && \"$NONO_BIN_ABS\" run --profile codex --allow-cwd -- cargo --version"
else
    skip_test "codex profile allows cargo from runtime path" "cargo not installed"
fi

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
