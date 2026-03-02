#!/bin/bash
# Environment Variable Sanitization Tests
# Verifies dangerous environment variables are stripped before reaching the child process

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Environment Sanitization Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "env sanitization suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

echo ""
echo "Test directory: $TMPDIR"
echo ""

# Helper: check that an env var is NOT passed to the child
expect_env_stripped() {
    local name="$1"
    local var_name="$2"
    local var_value="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$(env "${var_name}=${var_value}" "$NONO_BIN" run --allow "$TMPDIR" -- env </dev/null 2>&1)
    set -e

    if echo "$output" | grep -q "^${var_name}="; then
        echo -e "  ${RED}FAIL${NC}: $name"
        echo "       ${var_name} should be stripped but was present in child env"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    else
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

# Helper: check that an env var IS present in child
expect_env_present() {
    local name="$1"
    local var_name="$2"

    TESTS_RUN=$((TESTS_RUN + 1))

    set +e
    output=$("$NONO_BIN" run --allow "$TMPDIR" -- env </dev/null 2>&1)
    set -e

    if echo "$output" | grep -q "^${var_name}="; then
        echo -e "  ${GREEN}PASS${NC}: $name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "  ${RED}FAIL${NC}: $name"
        echo "       ${var_name} should be present but was not found in child env"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# =============================================================================
# Linker Injection Variables
# =============================================================================

echo "--- Linker Injection Variables ---"

expect_env_stripped "LD_PRELOAD not passed to child" \
    "LD_PRELOAD" "/tmp/evil.so"

expect_env_stripped "DYLD_INSERT_LIBRARIES not passed to child" \
    "DYLD_INSERT_LIBRARIES" "/tmp/evil.dylib"

expect_env_stripped "LD_LIBRARY_PATH not passed to child" \
    "LD_LIBRARY_PATH" "/tmp/evil"

# =============================================================================
# Interpreter Injection Variables
# =============================================================================

echo ""
echo "--- Interpreter Injection Variables ---"

expect_env_stripped "PYTHONSTARTUP not passed to child" \
    "PYTHONSTARTUP" "/tmp/evil.py"

expect_env_stripped "NODE_OPTIONS not passed to child" \
    "NODE_OPTIONS" "--require /tmp/evil.js"

expect_env_stripped "PERL5OPT not passed to child" \
    "PERL5OPT" "-M/tmp/evil"

# =============================================================================
# Credential Leakage Variables
# =============================================================================

echo ""
echo "--- Credential Leakage Variables ---"

expect_env_stripped "OP_SERVICE_ACCOUNT_TOKEN not passed to child" \
    "OP_SERVICE_ACCOUNT_TOKEN" "ops_secret_token_value"

expect_env_stripped "OP_SESSION_my not passed to child" \
    "OP_SESSION_my" "session_token_value"

# =============================================================================
# Safe Variables Preserved
# =============================================================================

echo ""
echo "--- Safe Variables Preserved ---"

expect_env_present "PATH passed to child" "PATH"
expect_env_present "HOME passed to child" "HOME"
expect_env_present "USER passed to child" "USER"
# TERM may not be set in CI environments (e.g., GitHub Actions)
if [[ -n "${TERM:-}" ]]; then
    expect_env_present "TERM passed to child" "TERM"
else
    skip_test "TERM passed to child" "TERM not set in this environment"
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
