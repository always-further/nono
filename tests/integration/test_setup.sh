#!/bin/bash
# Setup Command Tests
# Tests nono setup output and behavior

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Setup Tests ===${NC}"

verify_nono_binary

# Setup does not require a working sandbox (it checks sandbox support)

echo ""

# =============================================================================
# Setup
# =============================================================================

echo "--- Setup ---"

expect_success "setup --check-only exits 0" \
    "$NONO_BIN" setup --check-only

expect_output_contains "setup output contains platform info" "Platform:" \
    "$NONO_BIN" setup --check-only

expect_output_contains "setup output contains sandbox backend status" "sandbox" \
    "$NONO_BIN" setup --check-only

expect_output_contains "setup output contains version" "nono" \
    "$NONO_BIN" setup --check-only

# =============================================================================
# Summary
# =============================================================================

print_summary
