#!/bin/bash
# nono Integration Test Runner
# Builds nono and runs all integration test suites

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}======================================${NC}"
echo -e "${BOLD}  nono Integration Test Suite${NC}"
echo -e "${BOLD}======================================${NC}"
echo ""

# =============================================================================
# Build
# =============================================================================

echo -e "${BLUE}Building nono...${NC}"
cd "$PROJECT_ROOT"

if ! cargo build --release 2>&1; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

export NONO_BIN="$PROJECT_ROOT/target/release/nono"
export PATH="$PROJECT_ROOT/target/release:$PATH"

# Verify binary exists
if [[ ! -x "$NONO_BIN" ]]; then
    echo -e "${RED}ERROR: nono binary not found at $NONO_BIN${NC}"
    exit 1
fi

echo ""
echo -e "Binary: ${GREEN}$NONO_BIN${NC}"
echo -e "Version: $("$NONO_BIN" --version 2>/dev/null || echo 'unknown')"
echo -e "Platform: $(uname -s) $(uname -m)"
echo ""

# =============================================================================
# Run Test Suites
# =============================================================================

TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0
FAILED_NAMES=""

run_suite() {
    local suite="$1"
    local name="$2"

    TOTAL_SUITES=$((TOTAL_SUITES + 1))

    echo ""
    echo -e "${BOLD}Running: $name${NC}"
    echo "----------------------------------------"

    if bash "$suite"; then
        echo -e "${GREEN}Suite PASSED${NC}: $name"
        PASSED_SUITES=$((PASSED_SUITES + 1))
        return 0
    else
        echo -e "${RED}Suite FAILED${NC}: $name"
        FAILED_SUITES=$((FAILED_SUITES + 1))
        FAILED_NAMES="$FAILED_NAMES  - $name\n"
        return 1
    fi
}

# Make test scripts executable
chmod +x "$SCRIPT_DIR"/integration/*.sh
chmod +x "$SCRIPT_DIR"/lib/*.sh

# Run all test suites
# Continue even if a suite fails
set +e

run_suite "$SCRIPT_DIR/integration/test_fs_access.sh" "Filesystem Access"
run_suite "$SCRIPT_DIR/integration/test_sensitive_paths.sh" "Sensitive Paths"
run_suite "$SCRIPT_DIR/integration/test_system_paths.sh" "System Paths"
run_suite "$SCRIPT_DIR/integration/test_binary_exec.sh" "Binary Execution"
run_suite "$SCRIPT_DIR/integration/test_network.sh" "Network"
run_suite "$SCRIPT_DIR/integration/test_commands.sh" "Dangerous Commands"
run_suite "$SCRIPT_DIR/integration/test_edge_cases.sh" "Edge Cases"
run_suite "$SCRIPT_DIR/integration/test_policy_queries.sh" "Policy Queries"
run_suite "$SCRIPT_DIR/integration/test_shell.sh" "Shell"

set -e

# =============================================================================
# Final Summary
# =============================================================================

echo ""
echo -e "${BOLD}======================================${NC}"
echo -e "${BOLD}  Final Results${NC}"
echo -e "${BOLD}======================================${NC}"
echo ""
echo "Test suites run: $TOTAL_SUITES"
echo -e "Suites passed:   ${GREEN}$PASSED_SUITES${NC}"

if [[ "$FAILED_SUITES" -gt 0 ]]; then
    echo -e "Suites failed:   ${RED}$FAILED_SUITES${NC}"
    echo ""
    echo -e "Failed suites:"
    echo -e "$FAILED_NAMES"
else
    echo -e "Suites failed:   $FAILED_SUITES"
fi

echo ""

if [[ "$FAILED_SUITES" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}Some tests failed.${NC}"
    exit 1
fi
