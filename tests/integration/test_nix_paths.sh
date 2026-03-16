#!/bin/bash
# Nix Path Integration Tests
# Tests that nono correctly handles Nix store paths, symlink chains,
# wrapper scripts, and dynamic library loading from /nix/store.
#
# Covers issues: #19, #76, #93, #205, #262, #287

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Nix Path Tests ===${NC}"

verify_nono_binary

# Skip entire suite if Nix is not installed
if ! require_nix "nix paths suite"; then
    print_summary
    exit 0
fi

if ! require_working_sandbox "nix paths suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

echo ""
echo "Test directory: $TMPDIR"

# Resolve Nix binary paths
NIX_ECHO=$(nix_realpath echo)
NIX_CAT=$(nix_realpath cat)
NIX_LS=$(nix_realpath ls)
NIX_BASH=$(nix_realpath bash)
NIX_PYTHON3=$(nix_realpath python3)
NIX_NODE=$(nix_realpath node)

echo "Nix echo:    $NIX_ECHO"
echo "Nix bash:    $NIX_BASH"
echo "Nix python3: $NIX_PYTHON3"
echo "Nix node:    $NIX_NODE"
echo ""

# =============================================================================
# Nix Store Binary Execution (covers #19)
# =============================================================================

echo "--- Nix Store Binary Execution ---"

# Basic execution of binaries living in /nix/store
expect_output_contains "echo from nix store path" "hello from nix" \
    "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$NIX_ECHO" "hello from nix"

echo "test content" > "$TMPDIR/testfile.txt"
expect_output_contains "cat from nix store path" "test content" \
    "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$NIX_CAT" "$TMPDIR/testfile.txt"

expect_success "ls from nix store path" \
    "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$NIX_LS" "$TMPDIR"

expect_success "bash from nix store path runs command" \
    "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$NIX_BASH" -c "echo ok"

# Verify binaries accessed via symlink chain (e.g. ~/.nix-profile/bin/echo)
SYMLINK_ECHO=$(type -P -- echo 2>/dev/null || true)
if [[ -n "$SYMLINK_ECHO" && "$SYMLINK_ECHO" == *nix* ]]; then
    expect_output_contains "echo via nix symlink chain" "symlink ok" \
        "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$SYMLINK_ECHO" "symlink ok"
else
    skip_test "echo via nix symlink chain" "echo not from nix"
fi

# Python from nix store
expect_output_contains "python3 from nix store" "Python" \
    "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$NIX_PYTHON3" --version

# Node from nix store
expect_success "node from nix store" \
    "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$NIX_NODE" -e "console.log('ok')"

# =============================================================================
# Dynamic Linker / Shared Library Loading (covers #205, #262)
# =============================================================================

echo ""
echo "--- Dynamic Linker / Shared Libraries ---"

if is_linux; then
    # Python importing ssl triggers shared library loading (libssl, libcrypto)
    # which uses openat(dirfd, "relative") on NixOS
    expect_output_contains "python3 ssl import (shared lib loading)" "OpenSSL" \
        "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- \
        "$NIX_PYTHON3" -c "import ssl; print(ssl.OPENSSL_VERSION)"

    # Node.js triggers dynamic linker for V8, ICU, etc.
    expect_output_contains "node shared lib loading" "nix-node-ok" \
        "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- \
        "$NIX_NODE" -e "console.log('nix-node-ok')"

    # Python importing json + os (stdlib with C extensions)
    expect_success "python3 C extension loading" \
        "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- \
        "$NIX_PYTHON3" -c "import json, os, hashlib; print('ok')"
else
    skip_test "python3 ssl import (shared lib loading)" "Linux only"
    skip_test "node shared lib loading" "Linux only"
    skip_test "python3 C extension loading" "Linux only"
fi

# =============================================================================
# Wrapper Script Resolution (covers #287)
# =============================================================================

echo ""
echo "--- Wrapper Script Resolution ---"

# Nix python3 is often a wrapper script. Verify --version reports Python, not
# some other runtime (issue #287: opencode resolved to Bun).
PYTHON3_WHICH=$(type -P -- python3 2>/dev/null || true)
if [[ -n "$PYTHON3_WHICH" && "$PYTHON3_WHICH" == *nix* ]]; then
    expect_output_contains "python3 wrapper resolves to Python" "Python" \
        "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$PYTHON3_WHICH" --version

    # Verify the wrapper chain: which -> symlink -> ... -> /nix/store/.../python3
    PYTHON3_REAL=$(readlink -f "$PYTHON3_WHICH" 2>/dev/null || true)
    if [[ -n "$PYTHON3_REAL" && "$PYTHON3_REAL" == /nix/store/* ]]; then
        expect_output_contains "python3 real binary in nix store" "Python" \
            "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$PYTHON3_REAL" --version
    else
        skip_test "python3 real binary in nix store" "could not resolve real path"
    fi
else
    skip_test "python3 wrapper resolves to Python" "python3 not from nix"
    skip_test "python3 real binary in nix store" "python3 not from nix"
fi

# Same for node
NODE_WHICH=$(type -P -- node 2>/dev/null || true)
if [[ -n "$NODE_WHICH" && "$NODE_WHICH" == *nix* ]]; then
    expect_output_contains "node wrapper resolves to Node" "ok" \
        "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$NODE_WHICH" -e "console.log('ok')"
else
    skip_test "node wrapper resolves to Node" "node not from nix"
fi

# =============================================================================
# Symlink Chain Traversal
# =============================================================================

echo ""
echo "--- Symlink Chain Traversal ---"

# Verify each directory in the symlink chain from ~/.nix-profile to /nix/store
# is accessible under sandbox with /nix read access
NIX_PROFILE="$HOME/.nix-profile"
if [[ -L "$NIX_PROFILE" || -d "$NIX_PROFILE" ]]; then
    # The profile itself should be listable
    expect_success "list ~/.nix-profile/bin" \
        "$NONO_BIN" run --read /nix --read "$HOME/.nix-profile" --read "$HOME/.local/state" --allow "$TMPDIR" -- \
        "$NIX_LS" "$NIX_PROFILE/bin"

    # Verify a binary in the profile is executable
    if [[ -x "$NIX_PROFILE/bin/python3" ]]; then
        expect_output_contains "python3 via ~/.nix-profile" "Python" \
            "$NONO_BIN" run --read /nix --read "$HOME/.nix-profile" --read "$HOME/.local/state" --allow "$TMPDIR" -- \
            "$NIX_PROFILE/bin/python3" --version
    else
        skip_test "python3 via ~/.nix-profile" "python3 not in ~/.nix-profile"
    fi
else
    skip_test "list ~/.nix-profile/bin" "~/.nix-profile does not exist"
    skip_test "python3 via ~/.nix-profile" "~/.nix-profile does not exist"
fi

# Verify /nix/store read access allows following deep store paths
if [[ -d "/nix/store" ]]; then
    # Pick a store path from the resolved python3 binary
    NIX_STORE_DIR=$(dirname "$NIX_PYTHON3")
    expect_success "ls resolved nix store directory" \
        "$NONO_BIN" run --read /nix --allow "$TMPDIR" -- "$NIX_LS" "$NIX_STORE_DIR"
else
    skip_test "ls resolved nix store directory" "/nix/store does not exist"
fi

# =============================================================================
# nix_runtime Policy Group (profile validation)
# =============================================================================

echo ""
echo "--- nix_runtime Policy Group ---"

if is_linux; then
    # The developer profile includes nix_runtime group which grants read access
    # to ~/.nix-profile, ~/.nix-defexpr, /nix/var/nix/profiles, etc.
    expect_success "developer profile dry-run with nix paths" \
        "$NONO_BIN" run --profile developer --dry-run -- echo "test"

    # Verify nix_runtime paths appear in dry-run output
    expect_output_contains "developer profile includes /nix in capabilities" "/nix" \
        "$NONO_BIN" run --profile developer --dry-run -- echo "test"

    # Verify developer profile can run nix binaries
    expect_output_contains "developer profile runs nix python3" "Python" \
        "$NONO_BIN" run --profile developer --allow "$TMPDIR" --allow-cwd -- "$NIX_PYTHON3" --version
else
    skip_test "developer profile dry-run with nix paths" "Linux only"
    skip_test "developer profile includes /nix in capabilities" "Linux only"
    skip_test "developer profile runs nix python3" "Linux only"
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
