#!/bin/bash
# Interactive Shell Tests
# Verifies nono shell runs commands inside the sandbox and enforces restrictions

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Shell Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "shell suite"; then
    print_summary
    exit 0
fi

PROJECT_ROOT="$(get_project_root)"

BASE_DIR="$(mktemp -d "$PROJECT_ROOT/target/nono-shell-test-XXXX")"
trap 'cleanup_test_dir "$BASE_DIR"' EXIT

ALLOWED_DIR="$BASE_DIR/allowed"
DENIED_DIR="$BASE_DIR/denied"

mkdir -p "$ALLOWED_DIR" "$DENIED_DIR"
echo "ALLOWED_OK" > "$ALLOWED_DIR/ok.txt"
echo "DENIED_SECRET" > "$DENIED_DIR/secret.txt"

if is_macos; then
    EXPECT_DENIED="Operation not permitted"
else
    EXPECT_DENIED="Permission denied"
fi

echo ""
echo "Test directory: $BASE_DIR"
echo ""

# Shell should read allowed path
expect_output_contains "shell can read allowed file" "ALLOWED_OK" \
    bash -c "cat <<'EOF' | \"$NONO_BIN\" shell --allow \"$ALLOWED_DIR\" --shell /bin/sh
cat \"$ALLOWED_DIR/ok.txt\"
exit
EOF"

# Shell should not read denied path
expect_output_contains "shell blocks denied file" "$EXPECT_DENIED" \
    bash -c "cat <<'EOF' | \"$NONO_BIN\" shell --allow \"$ALLOWED_DIR\" --shell /bin/sh
cat \"$DENIED_DIR/secret.txt\"
exit
EOF"

# Shell dry-run should not execute commands from stdin
expect_success "shell --dry-run accepts shell command and shows plan" \
    bash -c "cat <<'EOF' | \"$NONO_BIN\" shell --dry-run --allow \"$ALLOWED_DIR\" --shell /bin/sh
echo 'dry-run-write' > \"$ALLOWED_DIR/dry_run_should_not_exist.txt\"
exit
EOF"

expect_output_contains "shell --dry-run shows dry-run message" "Dry run mode" \
    bash -c "cat <<'EOF' | \"$NONO_BIN\" shell --dry-run --allow \"$ALLOWED_DIR\" --shell /bin/sh
echo 'noop'
exit
EOF"

run_test "shell --dry-run did not execute command" 1 \
    test -f "$ALLOWED_DIR/dry_run_should_not_exist.txt"

# Shell with --net-block should not allow outbound network
if command_exists curl; then
    expect_failure "shell --net-block blocks curl" \
        bash -c "cat <<'EOF' | \"$NONO_BIN\" shell --net-block --allow \"$ALLOWED_DIR\" --shell /bin/sh
curl -s --max-time 5 https://example.com
exit
EOF"
else
    skip_test "shell --net-block blocks curl" "curl not installed"
fi

# Invalid shell path should fail before entering shell
expect_failure "shell with invalid --shell path fails" \
    "$NONO_BIN" shell --allow "$ALLOWED_DIR" --shell /definitely/not/a/real/shell

expect_output_contains "shell invalid --shell path reports exec error" "Command execution failed" \
    "$NONO_BIN" shell --allow "$ALLOWED_DIR" --shell /definitely/not/a/real/shell

# =============================================================================
# Summary
# =============================================================================

print_summary
