#!/bin/bash
# Network Control Tests
# Verifies network blocking works correctly

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Network Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "network suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

echo ""
echo "Test directory: $TMPDIR"
echo ""

# =============================================================================
# Network Blocked (--net-block)
# =============================================================================

echo "--- Network Blocked ---"

if command_exists curl; then
    expect_failure "curl blocked with --net-block" \
        "$NONO_BIN" run --net-block --allow "$TMPDIR" -- curl -s --max-time 5 https://example.com
else
    skip_test "curl blocked" "curl not installed"
fi

if command_exists wget; then
    expect_failure "wget blocked with --net-block" \
        "$NONO_BIN" run --net-block --allow "$TMPDIR" -- wget -q --timeout=5 -O - https://example.com
else
    skip_test "wget blocked" "wget not installed"
fi

# Note: ping requires special privileges, may not work in all environments
if command_exists ping; then
    # Use timeout to avoid hanging
    expect_failure "ping blocked with --net-block" \
        timeout 5 "$NONO_BIN" run --net-block --allow "$TMPDIR" -- ping -c 1 -W 2 8.8.8.8 2>/dev/null || true
else
    skip_test "ping blocked" "ping not installed"
fi

if command_exists nc; then
    expect_failure "nc (netcat) blocked with --net-block" \
        "$NONO_BIN" run --net-block --allow "$TMPDIR" -- nc -z -w 2 example.com 80
else
    skip_test "nc blocked" "nc not installed"
fi

# Test that even local network is blocked
if command_exists nc; then
    expect_failure "localhost connection blocked with --net-block" \
        "$NONO_BIN" run --net-block --allow "$TMPDIR" -- nc -z -w 1 127.0.0.1 22 2>/dev/null || true
fi

# =============================================================================
# Network Allowed (Default)
# =============================================================================

echo ""
echo "--- Network Allowed (Default) ---"

if command_exists curl; then
    expect_success "curl works by default" \
        "$NONO_BIN" run --allow "$TMPDIR" -- curl -s --max-time 10 https://example.com >/dev/null
else
    skip_test "curl works by default" "curl not installed"
fi

if command_exists wget; then
    expect_success "wget works by default" \
        "$NONO_BIN" run --allow "$TMPDIR" -- wget -q --timeout=10 -O /dev/null https://example.com
else
    skip_test "wget works by default" "wget not installed"
fi

# DNS resolution
if command_exists host; then
    expect_success "DNS resolution works (host)" \
        "$NONO_BIN" run --allow "$TMPDIR" -- host example.com
elif command_exists nslookup; then
    expect_success "DNS resolution works (nslookup)" \
        "$NONO_BIN" run --allow "$TMPDIR" -- nslookup example.com
elif command_exists dig; then
    expect_success "DNS resolution works (dig)" \
        "$NONO_BIN" run --allow "$TMPDIR" -- dig +short example.com
else
    skip_test "DNS resolution" "no DNS tools installed"
fi

# =============================================================================
# Network with Language Runtimes
# =============================================================================

echo ""
echo "--- Network with Language Runtimes ---"

# Note: Language runtime network tests are skipped because they may require
# access to installation paths (e.g., Homebrew) that aren't in system allowlists.
# Network functionality is already verified by curl/wget tests above.

skip_test "python3 network tests" "covered by curl/wget tests"
skip_test "node network tests" "covered by curl/wget tests"

# =============================================================================
# Summary
# =============================================================================

print_summary
