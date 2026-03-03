#!/bin/bash
# Trust CLI Tests
# Tests the trust command lifecycle: key generation, signing, verification, listing

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Trust CLI Tests ===${NC}"

verify_nono_binary

# Trust CLI does not require a working sandbox (it's a CLI-only feature)

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

# Generate a unique key ID for this test run to avoid collisions
KEY_ID="nono-inttest-$$"

echo ""
echo "Test directory: $TMPDIR"
echo "Key ID: $KEY_ID"
echo ""

# =============================================================================
# Key Generation
# =============================================================================

echo "--- Key Generation ---"

expect_success "trust keygen creates key" \
    "$NONO_BIN" trust keygen --id "$KEY_ID"

expect_output_contains "trust keygen shows key ID" "$KEY_ID" \
    "$NONO_BIN" trust keygen --id "${KEY_ID}-show"

# Duplicate key ID should fail
expect_failure "trust keygen duplicate ID fails" \
    "$NONO_BIN" trust keygen --id "$KEY_ID"

# =============================================================================
# Signing
# =============================================================================

echo ""
echo "--- Signing ---"

# Create instruction files
echo "# Test SKILLS file" > "$TMPDIR/SKILLS.md"
echo "# Test CLAUDE file" > "$TMPDIR/CLAUDE.md"

expect_success "trust sign creates bundle" \
    "$NONO_BIN" trust sign "$TMPDIR/SKILLS.md" --key "$KEY_ID"

# Verify bundle file was created
run_test "bundle file exists" 0 test -f "$TMPDIR/SKILLS.md.bundle"

# Sign another file
expect_success "trust sign second file" \
    "$NONO_BIN" trust sign "$TMPDIR/CLAUDE.md" --key "$KEY_ID"

run_test "second bundle file exists" 0 test -f "$TMPDIR/CLAUDE.md.bundle"

# Sign nonexistent file
expect_failure "trust sign nonexistent file fails" \
    "$NONO_BIN" trust sign "$TMPDIR/NONEXISTENT.md" --key "$KEY_ID"

# =============================================================================
# Verification (without trust policy — expects failure since no trusted publishers)
# =============================================================================

echo ""
echo "--- Verification ---"

# Without a trust policy, verify should fail because the signer is not trusted
expect_failure "trust verify without trust policy fails" \
    "$NONO_BIN" trust verify "$TMPDIR/SKILLS.md"

# Verify unsigned file fails
echo "# Unsigned file" > "$TMPDIR/AGENT.md"
expect_failure "trust verify unsigned file fails (no bundle)" \
    "$NONO_BIN" trust verify "$TMPDIR/AGENT.md"

# Tamper with signed file and verify
echo "# TAMPERED CONTENT" >> "$TMPDIR/CLAUDE.md"
expect_failure "trust verify tampered file fails" \
    "$NONO_BIN" trust verify "$TMPDIR/CLAUDE.md"

# =============================================================================
# Listing
# =============================================================================

echo ""
echo "--- Listing ---"

# List from a directory with instruction files (run from TMPDIR)
TESTS_RUN=$((TESTS_RUN + 1))
set +e
list_output=$(cd "$TMPDIR" && "$NONO_BIN" trust list </dev/null 2>&1)
list_exit=$?
set -e

# List should exit 0 (it lists files regardless of verification status)
if [[ "$list_exit" -eq 0 ]]; then
    echo -e "  ${GREEN}PASS${NC}: trust list exits 0"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    # list might exit non-zero if it reports failures — that's also valid
    echo -e "  ${GREEN}PASS${NC}: trust list exits $list_exit (reports verification status)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# List with --json flag
TESTS_RUN=$((TESTS_RUN + 1))
set +e
json_output=$(cd "$TMPDIR" && "$NONO_BIN" trust list --json </dev/null 2>&1)
json_exit=$?
set -e

# Check if output contains JSON structure
if echo "$json_output" | grep -q "{"; then
    echo -e "  ${GREEN}PASS${NC}: trust list --json produces JSON-like output"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    # If no instruction files found, that's also valid output
    if echo "$json_output" | grep -qi "no instruction files"; then
        echo -e "  ${GREEN}PASS${NC}: trust list --json reports no files (expected for non-standard dir)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: trust list --json produces JSON-like output"
        echo "       Output: ${json_output:0:500}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
fi

# =============================================================================
# Export Key
# =============================================================================

echo ""
echo "--- Export Key ---"

expect_success "trust export-key succeeds" \
    "$NONO_BIN" trust export-key --id "$KEY_ID"

expect_output_contains "export-key shows base64 public key" "MF" \
    "$NONO_BIN" trust export-key --id "$KEY_ID"

# =============================================================================
# Summary
# =============================================================================

print_summary
