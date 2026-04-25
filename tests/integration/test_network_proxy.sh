#!/bin/bash
# Network Proxy Tests
# Verifies proxy-routed allow_domain behavior across Linux and macOS.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Network Proxy Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "network proxy suite"; then
    print_summary
    exit 0
fi

TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

PROFILE="$TMPDIR/proxy-allow-domain.json"
cat > "$PROFILE" <<'JSON'
{
  "meta": { "name": "proxy-allow-domain", "version": "1.0.0" },
  "workdir": { "access": "readwrite" },
  "network": {
    "allow_domain": [
      "github.com",
      "*.hashicorp.com"
    ]
  }
}
JSON

echo ""
echo "Test directory: $TMPDIR"
echo ""

if ! command_exists curl; then
    skip_test "network proxy allow_domain tests" "curl not installed"
    print_summary
    exit 0
fi

# =============================================================================
# allow_domain proxy routing
# =============================================================================

echo "--- allow_domain proxy routing ---"

expect_success_output_equals "exact allow_domain host routes through proxy" "200" \
    "$NONO_BIN" run -s --allow-cwd --profile "$PROFILE" -- \
    curl -sS --max-time 10 --connect-timeout 3 \
        -o /dev/null -w '%{http_code}' https://github.com/

expect_success_output_equals "wildcard allow_domain host routes through proxy" "200" \
    "$NONO_BIN" run -s --allow-cwd --profile "$PROFILE" -- \
    curl -sS --max-time 10 --connect-timeout 3 \
        -o /dev/null -w '%{http_code}' https://releases.hashicorp.com/

# =============================================================================
# NO_PROXY handling
# =============================================================================

echo ""
echo "--- NO_PROXY handling ---"

expect_success_output_equals "proxy mode NO_PROXY only contains loopback" \
    $'localhost,127.0.0.1\nlocalhost,127.0.0.1' \
    "$NONO_BIN" run -s --allow-cwd --profile "$PROFILE" -- \
    sh -c 'printf "%s\n%s" "$NO_PROXY" "$no_proxy"'

expect_success_output_not_contains "exact allow_domain host is not in NO_PROXY" "github.com" \
    "$NONO_BIN" run -s --allow-cwd --profile "$PROFILE" -- \
    sh -c 'printf "%s\n%s" "$NO_PROXY" "$no_proxy"'

expect_success_output_not_contains "wildcard allow_domain host is not in NO_PROXY" "*.hashicorp.com" \
    "$NONO_BIN" run -s --allow-cwd --profile "$PROFILE" -- \
    sh -c 'printf "%s\n%s" "$NO_PROXY" "$no_proxy"'

expect_success_output_not_contains "wildcard concrete host is not in NO_PROXY" "releases.hashicorp.com" \
    "$NONO_BIN" run -s --allow-cwd --profile "$PROFILE" -- \
    sh -c 'printf "%s\n%s" "$NO_PROXY" "$no_proxy"'

# =============================================================================
# Bypass and deny behavior
# =============================================================================

echo ""
echo "--- bypass and deny behavior ---"

expect_failure "direct curl bypass is blocked for exact allow_domain host" \
    "$NONO_BIN" run -s --allow-cwd --profile "$PROFILE" -- \
    curl -sS --noproxy '*' --max-time 5 --connect-timeout 3 https://github.com/

expect_failure "host outside allow_domain is denied by proxy" \
    "$NONO_BIN" run -s --allow-cwd --profile "$PROFILE" -- \
    curl -sS --max-time 5 --connect-timeout 3 https://example.com/

# =============================================================================
# allow-net override
# =============================================================================

echo ""
echo "--- allow-net override ---"

expect_success_output_not_contains "allow-net clears nono proxy token" "NONO_PROXY_TOKEN=" \
    "$NONO_BIN" run -s --allow-cwd --profile "$PROFILE" --allow-net -- env

expect_success_output_not_contains "allow-net clears nono HTTPS proxy" "HTTPS_PROXY=http://nono:" \
    "$NONO_BIN" run -s --allow-cwd --profile "$PROFILE" --allow-net -- env

# =============================================================================
# Summary
# =============================================================================

print_summary
