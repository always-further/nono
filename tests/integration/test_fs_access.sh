#!/bin/bash
# Filesystem Access Control Tests
# Tests that nono correctly enforces read/write permissions on directories and files

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Filesystem Access Tests ===${NC}"

verify_nono_binary

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/allowed" "$TMPDIR/denied" "$TMPDIR/readonly" "$TMPDIR/writeonly"
echo "allowed content" > "$TMPDIR/allowed/test.txt"
echo "forbidden content" > "$TMPDIR/denied/secret.txt"
echo "readable content" > "$TMPDIR/readonly/file.txt"
touch "$TMPDIR/writeonly/existing.txt"

echo ""
echo "Test directory: $TMPDIR"
echo ""

# =============================================================================
# Directory Read Access
# =============================================================================

echo "--- Directory Read Access ---"

expect_success "read file in granted directory" \
    "$NONO_BIN" run --allow "$TMPDIR/allowed" -- cat "$TMPDIR/allowed/test.txt"

# Note: On macOS, /var/folders (TMPDIR) is a system-writable path
# Read/write denial within TMPDIR doesn't work as expected
# Actual denial is tested via sensitive paths (test_sensitive_paths.sh)
# Here we verify the basic grant works correctly
expect_success "can read from explicitly granted directory" \
    "$NONO_BIN" run --allow "$TMPDIR/allowed" -- cat "$TMPDIR/allowed/test.txt"

# Nested directory access
mkdir -p "$TMPDIR/allowed/nested/deep"
echo "nested content" > "$TMPDIR/allowed/nested/deep/file.txt"

expect_success "read file in nested subdirectory" \
    "$NONO_BIN" run --allow "$TMPDIR/allowed" -- cat "$TMPDIR/allowed/nested/deep/file.txt"

# =============================================================================
# Directory Write Access
# =============================================================================

echo ""
echo "--- Directory Write Access ---"

expect_success "write file to granted directory" \
    "$NONO_BIN" run --allow "$TMPDIR/allowed" -- sh -c "echo 'new content' > '$TMPDIR/allowed/new.txt'"

# Verify file was created
run_test "file was actually created" 0 test -f "$TMPDIR/allowed/new.txt"

# Note: Write denial within TMPDIR doesn't work on macOS because /var/folders
# is a system-writable path. Write denial to system paths is tested in
# test_system_paths.sh (e.g., cannot write to /usr/bin, /etc).
# Here we just verify writes to granted paths work correctly.
expect_success "can write to nested path in granted directory" \
    "$NONO_BIN" run --allow "$TMPDIR/allowed" -- sh -c "echo 'nested' > '$TMPDIR/allowed/nested/deep/written.txt'"

# =============================================================================
# Directory Rename (atomic directory rename via RemoveDir permission)
# =============================================================================

echo ""
echo "--- Directory Rename ---"

# Create source directory with content for rename test
mkdir -p "$TMPDIR/allowed/rename_src"
echo "rename content" > "$TMPDIR/allowed/rename_src/data.txt"

expect_success "rename directory within granted writable path" \
    "$NONO_BIN" run --allow "$TMPDIR/allowed" --allow-command mv -- mv "$TMPDIR/allowed/rename_src" "$TMPDIR/allowed/rename_dst"

# Verify the rename actually happened
run_test "renamed directory exists at destination" 0 test -d "$TMPDIR/allowed/rename_dst"
run_test "renamed directory content preserved" 0 test -f "$TMPDIR/allowed/rename_dst/data.txt"
run_test "source directory no longer exists" 1 test -d "$TMPDIR/allowed/rename_src"

# =============================================================================
# Read-only vs Write-only Access
# =============================================================================

echo ""
echo "--- Read-only / Write-only Access ---"

# Note: These tests use --allow /tmp which triggers Landlock EBADFD on Linux CI containers.
# Skip on Linux; the core read/write functionality is tested in other tests without --allow /tmp.
if is_linux; then
    skip_test "read with --read flag" "Landlock EBADFD with /tmp in CI containers"
    skip_test "write with --write flag" "Landlock EBADFD with /tmp in CI containers"
else
    expect_success "read with --read flag" \
        "$NONO_BIN" run --read "$TMPDIR/readonly" --allow /tmp -- cat "$TMPDIR/readonly/file.txt"

    # Note: Write denial within TMPDIR doesn't work on macOS because /var/folders
    # is a system-writable path. Write denial is tested via:
    # - test_system_paths.sh (cannot write to /usr/bin, /etc, etc.)
    # - test_sensitive_paths.sh (cannot write to sensitive paths)
    # Here we just verify the --read and --write flags are accepted

    expect_success "write with --write flag" \
        "$NONO_BIN" run --write "$TMPDIR/writeonly" --allow /tmp -- sh -c "echo 'written' > '$TMPDIR/writeonly/output.txt'"
fi

# =============================================================================
# Single File Access
# =============================================================================

echo ""
echo "--- Single File Access ---"

# Note: These tests use --allow /tmp which triggers Landlock EBADFD on Linux CI containers.
# Skip on Linux; single-file access is tested elsewhere without --allow /tmp.
if is_linux; then
    skip_test "read single file with --read-file" "Landlock EBADFD with /tmp in CI containers"
    skip_test "write single file with --write-file" "Landlock EBADFD with /tmp in CI containers"
else
    expect_success "read single file with --read-file" \
        "$NONO_BIN" run --read-file "$TMPDIR/allowed/test.txt" --allow /tmp -- cat "$TMPDIR/allowed/test.txt"

    # Note: File-level denial tests within TMPDIR don't work on macOS due to
    # /var/folders being system-accessible. Denial is tested via sensitive paths.

    # Create a file for write-file test
    touch "$TMPDIR/allowed/writeable.txt"

    expect_success "write single file with --write-file" \
        "$NONO_BIN" run --write-file "$TMPDIR/allowed/writeable.txt" --allow /tmp -- sh -c "echo 'updated' > '$TMPDIR/allowed/writeable.txt'"
fi

# =============================================================================
# Multiple Grants
# =============================================================================

echo ""
echo "--- Multiple Grants ---"

expect_success "access multiple granted directories" \
    "$NONO_BIN" run --allow "$TMPDIR/allowed" --read "$TMPDIR/readonly" -- \
    sh -c "cat '$TMPDIR/allowed/test.txt' && cat '$TMPDIR/readonly/file.txt'"

expect_success "overlapping grants (parent and child)" \
    "$NONO_BIN" run --allow "$TMPDIR/allowed" --allow "$TMPDIR/allowed/nested" -- \
    cat "$TMPDIR/allowed/nested/deep/file.txt"

# =============================================================================
# Summary
# =============================================================================

print_summary
