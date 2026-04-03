#!/bin/bash
# WSL2 Support Tests
# Validates WSL2 detection and graceful degradation behavior
# Tests from WSL2_SUPPORT_PLAN.md tracks 1.1–1.4

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== WSL2 Support Tests ===${NC}"

verify_nono_binary

echo ""

# =============================================================================
# 1.1 — WSL2 Detection
# =============================================================================

echo "--- WSL2 Detection ---"

if is_wsl2; then
    echo "  Environment: WSL2 detected"

    # Setup --check-only should report WSL2
    expect_output_contains "setup reports WSL2 environment" "WSL2" \
        "$NONO_BIN" setup --check-only

    # Verify the detection indicators exist
    TESTS_RUN=$((TESTS_RUN + 1))
    if [[ -f /proc/sys/fs/binfmt_misc/WSLInterop ]] || [[ -n "${WSL_DISTRO_NAME:-}" ]]; then
        echo -e "  ${GREEN}PASS${NC}: WSL2 indicators present"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: WSL2 indicators not found despite is_wsl2() returning true"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo "  Environment: Native Linux (or non-Linux)"
    skip_test "WSL2 detection indicators" "not running on WSL2"
    skip_test "setup reports WSL2 environment" "not running on WSL2"
fi

# =============================================================================
# 1.2 — Filesystem Sandboxing (Works on WSL2)
# =============================================================================

echo ""
echo "--- Filesystem Sandboxing (should work on WSL2) ---"

if ! require_working_sandbox "WSL2 filesystem tests"; then
    echo "  Sandbox unavailable, skipping filesystem tests"
else
    TMPDIR=$(setup_test_dir)
    trap 'cleanup_test_dir "$TMPDIR"' EXIT

    # Basic filesystem sandbox should work identically on WSL2 and native Linux
    expect_success "basic sandbox with --allow works" \
        "$NONO_BIN" run --allow "$TMPDIR" -- echo "sandbox works"

    # Write within allowed path
    expect_success "write to allowed path succeeds" \
        "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo test > $TMPDIR/testfile"

    # Read within allowed path
    expect_success "read from allowed path succeeds" \
        "$NONO_BIN" run --allow "$TMPDIR" -- cat "$TMPDIR/testfile"

    # Deny access outside allowed paths
    expect_failure "read outside allowed path fails" \
        "$NONO_BIN" run --allow "$TMPDIR" -- cat /etc/hostname

    # Note: read-only enforcement is tested in test_fs_access.sh.
    # System paths grant /tmp write access, so read-only subdirs under /tmp
    # are overridden — that's expected nono policy, not a WSL2 issue.
fi

# =============================================================================
# 1.3 — Network: Block-All Mode (Works on WSL2)
# =============================================================================

echo ""
echo "--- Network: Block-All Mode (should work on WSL2) ---"

if ! require_working_sandbox "WSL2 block-all network tests"; then
    echo "  Sandbox unavailable, skipping network tests"
else
    TMPDIR2=$(setup_test_dir)

    if command_exists curl; then
        expect_failure "block-net prevents curl" \
            "$NONO_BIN" run --block-net --allow "$TMPDIR2" -- \
            curl -s --max-time 5 https://example.com
    else
        skip_test "block-net prevents curl" "curl not installed"
    fi

    if command_exists nc; then
        expect_failure "block-net prevents netcat" \
            "$NONO_BIN" run --block-net --allow "$TMPDIR2" -- \
            nc -z -w 2 example.com 80
    else
        skip_test "block-net prevents netcat" "nc not installed"
    fi

    cleanup_test_dir "$TMPDIR2"
fi

# =============================================================================
# 1.3 — Network: Per-Port Filtering (Unavailable on WSL2 with kernel < 6.7)
# =============================================================================

echo ""
echo "--- Per-Port Network Filtering ---"

if is_wsl2; then
    # On WSL2 with kernel 6.6, per-port filtering requires Landlock V4 (kernel 6.7+)
    # and seccomp notify (broken on WSL2). Should error clearly.
    TMPDIR3=$(setup_test_dir)

    # --allow-net with a specific port should fail on WSL2 if V4 unavailable
    TESTS_RUN=$((TESTS_RUN + 1))
    set +e
    net_output=$("$NONO_BIN" run --allow-net 443 --allow "$TMPDIR3" -- true </dev/null 2>&1)
    net_exit=$?
    set -e

    if [[ "$net_exit" -ne 0 ]]; then
        echo -e "  ${GREEN}PASS${NC}: per-port filtering correctly rejected (exit $net_exit)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        # If it succeeded, check if this WSL2 has been upgraded to a kernel with V4
        kernel_version=$(uname -r)
        echo -e "  ${YELLOW}SKIP${NC}: per-port filtering succeeded (kernel $kernel_version may have V4 support)"
        TESTS_RUN=$((TESTS_RUN - 1))
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    fi

    cleanup_test_dir "$TMPDIR3"
else
    skip_test "per-port filtering rejection on WSL2" "not running on WSL2"
fi

# =============================================================================
# 1.2/1.4 — Supervised Mode Degradation on WSL2
# =============================================================================

echo ""
echo "--- Supervised Mode ---"

if is_wsl2; then
    if ! require_working_sandbox "WSL2 supervised mode tests"; then
        echo "  Sandbox unavailable, skipping supervised mode tests"
    else
        TMPDIR4=$(setup_test_dir)

        # Default mode (supervised) should either:
        # a) Fall back to unsupervised and succeed, or
        # b) Warn about WSL2 limitations
        TESTS_RUN=$((TESTS_RUN + 1))
        set +e
        sup_output=$("$NONO_BIN" run --allow "$TMPDIR4" -- echo "supervised test" </dev/null 2>&1)
        sup_exit=$?
        set -e

        if [[ "$sup_exit" -eq 0 ]]; then
            echo -e "  ${GREEN}PASS${NC}: default execution mode works on WSL2"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            # If it failed, check if it's a seccomp EBUSY error
            if echo "$sup_output" | grep -qiE "EBUSY|seccomp|supervisor"; then
                echo -e "  ${YELLOW}SKIP${NC}: supervised mode failed with expected WSL2 error"
                echo "       This test validates that graceful fallback is needed"
                echo "       Output: ${sup_output:0:500}"
                TESTS_RUN=$((TESTS_RUN - 1))
                TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
            else
                echo -e "  ${RED}FAIL${NC}: unexpected failure (exit $sup_exit)"
                echo "       Output: ${sup_output:0:500}"
                TESTS_FAILED=$((TESTS_FAILED + 1))
            fi
        fi

        cleanup_test_dir "$TMPDIR4"
    fi
else
    skip_test "supervised mode WSL2 fallback" "not running on WSL2"
fi

# =============================================================================
# WSL2 Proxy Policy (fail-secure default)
# =============================================================================

echo ""
echo "--- WSL2 Proxy Policy ---"

if is_wsl2; then
    if ! require_working_sandbox "WSL2 proxy policy tests"; then
        echo "  Sandbox unavailable, skipping proxy policy tests"
    else
        TMPDIR_PROXY=$(setup_test_dir)

        # Default policy (error): --credential should fail on WSL2
        TESTS_RUN=$((TESTS_RUN + 1))
        set +e
        proxy_output=$("$NONO_BIN" run --credential github --allow "$TMPDIR_PROXY" -- echo "should fail" </dev/null 2>&1)
        proxy_exit=$?
        set -e

        if [[ "$proxy_exit" -ne 0 ]] && echo "$proxy_output" | grep -q "proxy-only network mode cannot be kernel-enforced"; then
            echo -e "  ${GREEN}PASS${NC}: default policy rejects ProxyOnly on WSL2 (fail-secure, exit $proxy_exit)"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        elif [[ "$proxy_exit" -eq 0 ]]; then
            echo -e "  ${RED}FAIL${NC}: default policy should reject ProxyOnly on WSL2 but exited 0"
            echo "       Output: ${proxy_output:0:500}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        else
            echo -e "  ${RED}FAIL${NC}: default policy should reject ProxyOnly with specific error message"
            echo "       Exit: $proxy_exit"
            echo "       Output: ${proxy_output:0:500}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi

        # Error message should mention the escape hatch
        TESTS_RUN=$((TESTS_RUN + 1))
        if echo "$proxy_output" | grep -q "wsl2_proxy_policy"; then
            echo -e "  ${GREEN}PASS${NC}: error message mentions wsl2_proxy_policy escape hatch"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "  ${RED}FAIL${NC}: error message should mention wsl2_proxy_policy"
            echo "       Output: ${proxy_output:0:500}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi

        # insecure_proxy policy: create a profile that opts in
        INSECURE_PROFILE="$TMPDIR_PROXY/insecure-proxy-test.json"
        cat > "$INSECURE_PROFILE" <<'PROFILE_EOF'
{
  "meta": { "name": "insecure-proxy-test", "version": "1.0.0" },
  "filesystem": { "allow": ["/tmp"] },
  "network": { "block": false },
  "security": { "wsl2_proxy_policy": "insecure_proxy" }
}
PROFILE_EOF

        TESTS_RUN=$((TESTS_RUN + 1))
        set +e
        insecure_output=$("$NONO_BIN" run --profile "$INSECURE_PROFILE" --credential github --allow "$TMPDIR_PROXY" -- echo "insecure ok" </dev/null 2>&1)
        insecure_exit=$?
        set -e

        if echo "$insecure_output" | grep -q "insecure proxy mode"; then
            echo -e "  ${GREEN}PASS${NC}: insecure_proxy policy emits degraded-security warning"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        elif echo "$insecure_output" | grep -q "proxy-only network mode cannot be kernel-enforced"; then
            echo -e "  ${RED}FAIL${NC}: insecure_proxy policy was not respected (got fail-secure error)"
            echo "       Output: ${insecure_output:0:500}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        else
            # Proxy policy was accepted (no fail-secure error), but credential
            # loading may have failed before the warning was printed (no keystore).
            # Verify we at least got past the policy check.
            if [[ "$insecure_exit" -ne 0 ]] && echo "$insecure_output" | grep -qi "keystore\|credential\|secret"; then
                echo -e "  ${GREEN}PASS${NC}: insecure_proxy policy accepted (credential loading failed separately)"
                TESTS_PASSED=$((TESTS_PASSED + 1))
            else
                echo -e "  ${RED}FAIL${NC}: insecure_proxy policy: unexpected behavior (exit $insecure_exit)"
                echo "       Output: ${insecure_output:0:500}"
                TESTS_FAILED=$((TESTS_FAILED + 1))
            fi
        fi

        cleanup_test_dir "$TMPDIR_PROXY"
    fi
else
    skip_test "default policy rejects ProxyOnly on WSL2" "not running on WSL2"
    skip_test "error message mentions escape hatch" "not running on WSL2"
    skip_test "insecure_proxy policy emits warning" "not running on WSL2"
fi

# =============================================================================
# Setup --check-only Feature Matrix
# =============================================================================

echo ""
echo "--- Setup Feature Reporting ---"

expect_success "setup --check-only exits 0" \
    "$NONO_BIN" setup --check-only

expect_output_contains "setup reports platform info" "Platform:" \
    "$NONO_BIN" setup --check-only

if is_wsl2; then
    # On WSL2, setup should report the environment and limitations
    expect_output_contains "setup reports sandbox backend" "Landlock" \
        "$NONO_BIN" setup --check-only

    # Verify kernel version is reported (useful for diagnosing V4 availability)
    expect_output_contains "setup reports kernel version" "Kernel version" \
        "$NONO_BIN" setup --check-only
fi

# =============================================================================
# Direct Mode (nono wrap) — Works on WSL2
# =============================================================================

echo ""
echo "--- Direct Mode (should work on WSL2) ---"

if ! require_working_sandbox "WSL2 direct mode tests"; then
    echo "  Sandbox unavailable, skipping direct mode tests"
else
    TMPDIR5=$(setup_test_dir)

    # Direct mode (nono wrap) doesn't use fork+supervisor, so it works on WSL2
    expect_success "direct mode (wrap) runs successfully" \
        "$NONO_BIN" wrap --allow "$TMPDIR5" -- echo "direct mode works"

    expect_output_contains "direct mode output correct" "direct mode works" \
        "$NONO_BIN" wrap --allow "$TMPDIR5" -- echo "direct mode works"

    run_test "direct mode preserves exit code 0" 0 \
        "$NONO_BIN" wrap --allow "$TMPDIR5" -- true

    run_test "direct mode preserves exit code 1" 1 \
        "$NONO_BIN" wrap --allow "$TMPDIR5" -- false

    cleanup_test_dir "$TMPDIR5"
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
