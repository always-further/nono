#!/bin/bash
# Dangerous Command Blocking Tests
# Verifies that dangerous commands are blocked by default

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Dangerous Command Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "dangerous commands suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

echo "deleteme" > "$TMPDIR/deleteme.txt"
echo "protected" > "$TMPDIR/protected.txt"
touch "$TMPDIR/chmod_test.txt"

echo ""
echo "Test directory: $TMPDIR"
echo ""

# =============================================================================
# Default Blocked Commands
# =============================================================================

echo "--- Default Blocked Commands ---"

# rm is blocked by default
expect_failure "rm blocked by default" \
    "$NONO_BIN" run --allow "$TMPDIR" -- rm "$TMPDIR/deleteme.txt"

# Verify file still exists
run_test "file was not deleted (rm was blocked)" 0 test -f "$TMPDIR/deleteme.txt"

# rmdir is blocked
mkdir -p "$TMPDIR/testdir"
expect_failure "rmdir blocked by default" \
    "$NONO_BIN" run --allow "$TMPDIR" -- rmdir "$TMPDIR/testdir"

# chmod is blocked
expect_failure "chmod blocked by default" \
    "$NONO_BIN" run --allow "$TMPDIR" -- chmod 777 "$TMPDIR/chmod_test.txt"

# chown is blocked
expect_failure "chown blocked by default" \
    "$NONO_BIN" run --allow "$TMPDIR" -- chown nobody "$TMPDIR/chmod_test.txt"

# sudo is blocked
expect_failure "sudo blocked by default" \
    "$NONO_BIN" run --allow "$TMPDIR" -- sudo ls

# dd is blocked (dangerous disk operations)
expect_failure "dd blocked by default" \
    "$NONO_BIN" run --allow "$TMPDIR" -- dd if=/dev/zero of="$TMPDIR/dd_test" bs=1 count=1

# =============================================================================
# Allow Command Override
# =============================================================================

echo ""
echo "--- Allow Command Override ---"

# Create a new file to delete with override
echo "todelete" > "$TMPDIR/todelete.txt"

expect_success "rm allowed with --allow-command rm" \
    "$NONO_BIN" run --allow "$TMPDIR" --allow-command rm -- rm "$TMPDIR/todelete.txt"

# Verify file was deleted
run_test "file successfully deleted with --allow-command rm" 1 test -f "$TMPDIR/todelete.txt"

# Multiple command overrides
echo "test1" > "$TMPDIR/multi1.txt"
echo "test2" > "$TMPDIR/multi2.txt"

expect_success "multiple commands allowed with multiple --allow-command" \
    "$NONO_BIN" run --allow "$TMPDIR" --allow-command rm --allow-command chmod -- \
    sh -c "rm '$TMPDIR/multi1.txt' && chmod 644 '$TMPDIR/multi2.txt'"

# =============================================================================
# Custom Block Command
# =============================================================================

echo ""
echo "--- Custom Block Command ---"

expect_failure "cat blocked with --block-command cat" \
    "$NONO_BIN" run --allow "$TMPDIR" --block-command cat -- cat "$TMPDIR/protected.txt"

expect_failure "ls blocked with --block-command ls" \
    "$NONO_BIN" run --allow "$TMPDIR" --block-command ls -- ls "$TMPDIR"

# Block and allow interactions
expect_failure "explicitly blocked command overrides default allow" \
    "$NONO_BIN" run --allow "$TMPDIR" --block-command echo -- echo "should fail"

# =============================================================================
# Package Managers
# =============================================================================

echo ""
echo "--- Package Manager Blocking ---"

if command_exists pip; then
    expect_failure "pip blocked by default" \
        "$NONO_BIN" run --allow "$TMPDIR" -- pip --version
else
    skip_test "pip blocked" "pip not installed"
fi

if command_exists npm; then
    expect_failure "npm blocked by default" \
        "$NONO_BIN" run --allow "$TMPDIR" -- npm --version
else
    skip_test "npm blocked" "npm not installed"
fi

if command_exists brew && is_macos; then
    expect_failure "brew blocked by default" \
        "$NONO_BIN" run --allow "$TMPDIR" -- brew --version
else
    skip_test "brew blocked" "brew not installed or not macOS"
fi

# =============================================================================
# Privilege Escalation
# =============================================================================

echo ""
echo "--- Privilege Escalation Blocking ---"

expect_failure "sudo blocked" \
    "$NONO_BIN" run --allow "$TMPDIR" -- sudo echo "test"

if command_exists doas; then
    expect_failure "doas blocked" \
        "$NONO_BIN" run --allow "$TMPDIR" -- doas echo "test"
else
    skip_test "doas blocked" "doas not installed"
fi

if command_exists su; then
    expect_failure "su blocked" \
        "$NONO_BIN" run --allow "$TMPDIR" -- su -c "echo test"
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
