#!/bin/bash
# Test script for nono secrets functionality
# Works on both macOS and Linux

set -e

TEST_SECRET="test-secret-value-12345"
TEST_ACCOUNT="test_api_key"

echo "=== nono secrets test ==="
echo ""

# Detect platform
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    echo "Platform: macOS (Keychain)"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
    echo "Platform: Linux (Secret Service)"
else
    echo "Unsupported platform: $OSTYPE"
    exit 1
fi

# Step 1: Store test secret
echo ""
echo "Step 1: Storing test secret '$TEST_ACCOUNT' in keystore..."

if [[ "$PLATFORM" == "macos" ]]; then
    # Delete existing entry if present (ignore errors)
    security delete-generic-password -s "nono" -a "$TEST_ACCOUNT" 2>/dev/null || true
    # Add new entry
    security add-generic-password -s "nono" -a "$TEST_ACCOUNT" -w "$TEST_SECRET"
    echo "  Stored in macOS Keychain"
else
    # Linux: use secret-tool
    if ! command -v secret-tool &> /dev/null; then
        echo "  ERROR: secret-tool not found. Install libsecret-tools:"
        echo "    sudo apt install libsecret-tools  # Debian/Ubuntu"
        echo "    sudo dnf install libsecret        # Fedora"
        exit 1
    fi
    # Clear existing (ignore errors)
    secret-tool clear service nono username "$TEST_ACCOUNT" 2>/dev/null || true
    # Store new secret
    echo -n "$TEST_SECRET" | secret-tool store --label="nono: $TEST_ACCOUNT" service nono username "$TEST_ACCOUNT"
    echo "  Stored in Secret Service"
fi

# Step 2: Verify secret was stored
echo ""
echo "Step 2: Verifying secret was stored..."

if [[ "$PLATFORM" == "macos" ]]; then
    RETRIEVED=$(security find-generic-password -s "nono" -a "$TEST_ACCOUNT" -w 2>/dev/null)
else
    RETRIEVED=$(secret-tool lookup service nono username "$TEST_ACCOUNT" 2>/dev/null)
fi

if [[ "$RETRIEVED" == "$TEST_SECRET" ]]; then
    echo "  OK: Secret retrieved successfully"
else
    echo "  ERROR: Retrieved value doesn't match!"
    echo "  Expected: $TEST_SECRET"
    echo "  Got: $RETRIEVED"
    exit 1
fi

# Step 3: Build nono if needed
echo ""
echo "Step 3: Building nono..."
cargo build --quiet
echo "  OK: Build complete"

# Step 4: Test secret injection
echo ""
echo "Step 4: Testing secret injection with nono..."
echo "  Running: nono run --allow . --secrets $TEST_ACCOUNT -- env"
echo ""
echo "--- BEGIN OUTPUT ---"

# Run nono with the secret and grep for our env var
# The env var should be TEST_API_KEY (uppercased from test_api_key)
./target/debug/nono run --allow . --secrets "$TEST_ACCOUNT" -- sh -c 'echo "TEST_API_KEY=$TEST_API_KEY"'

echo "--- END OUTPUT ---"

# Step 5: Cleanup
echo ""
echo "Step 5: Cleaning up test secret..."

if [[ "$PLATFORM" == "macos" ]]; then
    security delete-generic-password -s "nono" -a "$TEST_ACCOUNT" 2>/dev/null || true
else
    secret-tool clear service nono username "$TEST_ACCOUNT" 2>/dev/null || true
fi
echo "  OK: Test secret removed"

echo ""
echo "=== Test complete ==="
