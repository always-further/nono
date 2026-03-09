#!/bin/bash
# Silent mode regression checks

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Silent Output Tests ===${NC}"

verify_nono_binary
if ! skip_unless_linux "silent output suite"; then
    print_summary
    exit 0
fi

expect_output_empty() {
    local name="$1"
    shift

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$("$@" </dev/null 2>&1)
    exit_code=$?
    set -e

    if [[ "$exit_code" -eq 0 && -z "$output" ]]; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi

    echo -e "  ${RED}FAIL${NC}: $name"
    echo "       Expected empty output with exit 0, got exit $exit_code"
    if [[ -n "$output" ]]; then
        local stripped
        stripped=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
        echo "       Actual output: ${stripped:0:2000}"
    fi
    TESTS_FAILED=$((TESTS_FAILED + 1))
    return 1
}

expect_output_contains \
    "claude-code dry-run surfaces missing profile warnings without --silent" \
    "Profile file '\$HOME/Library/Keychains/login.keychain-db' does not exist, skipping" \
    "$NONO_BIN" run --profile claude-code --allow-cwd --dry-run -- echo ok

expect_output_empty \
    "silent dry-run suppresses tracing warnings and CLI status output" \
    "$NONO_BIN" run --profile claude-code --allow-cwd --silent --dry-run -- echo ok

print_summary
