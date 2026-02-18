#!/bin/bash
# System Path Protection Tests
# Verifies system directories are readable but not writable

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== System Path Protection Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "system path suite"; then
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
# System Paths Should Be Readable
# =============================================================================

echo "--- System Paths Readable ---"

expect_success "can list /usr/bin (system executables)" \
    "$NONO_BIN" run --allow "$TMPDIR" -- ls /usr/bin/ >/dev/null

expect_success "can execute /bin/echo" \
    "$NONO_BIN" run --allow "$TMPDIR" -- /bin/echo "test"

if [[ -d /usr/lib ]]; then
    expect_success "can list /usr/lib" \
        "$NONO_BIN" run --allow "$TMPDIR" -- ls /usr/lib/ >/dev/null
fi

if [[ -d /etc ]]; then
    expect_success "can read /etc/hosts" \
        "$NONO_BIN" run --allow "$TMPDIR" -- cat /etc/hosts >/dev/null
fi

# =============================================================================
# System Paths Should NOT Be Writable
# =============================================================================

echo ""
echo "--- System Paths NOT Writable ---"

expect_failure "cannot write to /usr/bin" \
    "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo hack > /usr/bin/evil-$$"

expect_failure "cannot write to /etc" \
    "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo hack > /etc/evil-$$.conf"

expect_failure "cannot write to /usr/lib" \
    "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo hack > /usr/lib/evil-$$.so"

# =============================================================================
# macOS Specific System Paths
# =============================================================================

echo ""
echo "--- macOS System Paths ---"

if is_macos; then
    expect_success "can read /System/Library" \
        "$NONO_BIN" run --allow "$TMPDIR" -- ls /System/Library/ >/dev/null

    expect_failure "cannot write to /System/Library" \
        "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo x > /System/Library/evil-$$"

    expect_success "can read /Library" \
        "$NONO_BIN" run --allow "$TMPDIR" -- ls /Library/ >/dev/null

    expect_failure "cannot write to /Library" \
        "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo x > /Library/evil-$$"

    if [[ -d /Applications ]]; then
        expect_success "can read /Applications" \
            "$NONO_BIN" run --allow "$TMPDIR" -- ls /Applications/ >/dev/null
    fi
else
    skip_test "/System/Library readable" "not macOS"
    skip_test "/System/Library not writable" "not macOS"
    skip_test "/Library readable" "not macOS"
    skip_test "/Library not writable" "not macOS"
fi

# =============================================================================
# Linux Specific System Paths
# =============================================================================

echo ""
echo "--- Linux System Paths ---"

if is_linux; then
    if [[ -d /lib ]]; then
        expect_success "can read /lib" \
            "$NONO_BIN" run --allow "$TMPDIR" -- ls /lib/ >/dev/null

        expect_failure "cannot write to /lib" \
            "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo x > /lib/evil-$$.so"
    fi

    if [[ -d /lib64 ]]; then
        expect_success "can read /lib64" \
            "$NONO_BIN" run --allow "$TMPDIR" -- ls /lib64/ >/dev/null
    fi

    if [[ -d /proc ]]; then
        expect_success "can read /proc/self/status" \
            "$NONO_BIN" run --allow "$TMPDIR" -- cat /proc/self/status >/dev/null
    fi

    if [[ -d /sys ]]; then
        expect_success "can read /sys" \
            "$NONO_BIN" run --allow "$TMPDIR" -- ls /sys/ >/dev/null
    fi
else
    skip_test "/lib readable" "not Linux"
    skip_test "/lib not writable" "not Linux"
    skip_test "/proc readable" "not Linux"
fi

# =============================================================================
# Temp Directories Should Be Writable
# =============================================================================

echo ""
echo "--- Temp Directories Writable ---"

# TODO: Re-enable /tmp tests on Linux once Landlock EBADFD issue is resolved
# GitHub Actions Ubuntu 24.04 returns EBADFD (error 77) when adding
# Landlock rules for /tmp directories. This may be related to:
# - Container/namespace interactions with Landlock
# - tmpfs configuration on GitHub Actions runners
# - Kernel version differences
# Works correctly on native Linux systems; issue is specific to CI containers.
if is_linux; then
    skip_test "can write to /tmp" "Landlock EBADFD issue in CI containers"
else
    expect_success "can write to /tmp" \
        "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo test > /tmp/nono-test-$$"
    # Cleanup
    rm -f /tmp/nono-test-$$
fi

if is_macos; then
    expect_success "can write to /private/tmp (macOS)" \
        "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo test > /private/tmp/nono-test-$$"
    rm -f /private/tmp/nono-test-$$
fi

# Test TMPDIR environment variable path
if [[ -n "${TMPDIR:-}" ]]; then
    # Skip on Linux due to same Landlock EBADFD issue with tmpfs
    if is_linux; then
        skip_test "can write to \$TMPDIR" "Landlock EBADFD issue in CI containers"
    else
        expect_success "can write to \$TMPDIR" \
            "$NONO_BIN" run --allow "$TMPDIR" -- sh -c "echo test > '$TMPDIR/nono-env-test-$$'"
        rm -f "$TMPDIR/nono-env-test-$$"
    fi
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
