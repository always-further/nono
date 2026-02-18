#!/bin/bash
# Policy Query Tests
# Verifies `nono why` decisions for filesystem and network policy evaluation.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Policy Query Tests ===${NC}"

verify_nono_binary

TMPDIR=$(setup_test_dir)
PROJECT_ROOT="$(get_project_root)"
READONLY_DIR="$PROJECT_ROOT/target/nono-policy-readonly-$$"
trap 'cleanup_test_dir "$TMPDIR"; cleanup_test_dir "$READONLY_DIR"' EXIT

touch "$TMPDIR/write-target.txt"
DENIED_PATH="$HOME/nono-integration-denied-check-$$.txt"
mkdir -p "$READONLY_DIR"
touch "$READONLY_DIR/read-only-target.txt"

echo ""
echo "Test directory: $TMPDIR"
echo ""

echo "--- Path Policy Queries ---"

expect_output_contains "sensitive path is denied" "\"reason\": \"sensitive_path\"" \
    "$NONO_BIN" --silent why --json --path ~/.ssh --op read

expect_output_contains "non-granted path is denied" "\"reason\": \"path_not_granted\"" \
    "$NONO_BIN" --silent why --json --path "$DENIED_PATH" --op read

expect_output_contains "allow grants write for matching path" "\"status\": \"allowed\"" \
    "$NONO_BIN" --silent why --json --path "$TMPDIR/write-target.txt" --op write --allow "$TMPDIR"

expect_output_contains "read-only grant blocks write operation" "\"reason\": \"insufficient_access\"" \
    "$NONO_BIN" --silent why --json --path "$READONLY_DIR/read-only-target.txt" --op write --read "$READONLY_DIR"

expect_output_contains "read-file on sensitive path stays denied" "\"reason\": \"sensitive_path\"" \
    "$NONO_BIN" --silent why --json --path ~/.zshrc --op read --read-file ~/.zshrc

echo ""
echo "--- Network Policy Queries ---"

expect_output_contains "network allowed by default" "\"reason\": \"network_allowed\"" \
    "$NONO_BIN" --silent why --json --host example.com --port 443

expect_output_contains "network denied with --net-block" "\"reason\": \"network_blocked\"" \
    "$NONO_BIN" --silent why --json --host example.com --port 443 --net-block

print_summary
