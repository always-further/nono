#!/bin/bash
# nono Integration Test Runner
# Builds nono and runs all integration test suites in parallel

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

# Make test scripts executable
chmod +x "$SCRIPT_DIR"/integration/*.sh
chmod +x "$SCRIPT_DIR"/lib/*.sh

# =============================================================================
# Run Test Suites in Parallel (with concurrency limit)
# =============================================================================

# Temp directory for suite output files
RESULTS_DIR=$(mktemp -d)
trap 'rm -rf "$RESULTS_DIR"' EXIT

# All suites to run (script:name pairs)
SUITES=(
    "test_fs_access.sh:Filesystem Access"
    "test_sensitive_paths.sh:Sensitive Paths"
    "test_system_paths.sh:System Paths"
    "test_binary_exec.sh:Binary Execution"
    "test_network.sh:Network"
    "test_commands.sh:Dangerous Commands"
    "test_edge_cases.sh:Edge Cases"
    "test_policy_queries.sh:Policy Queries"
    "test_shell.sh:Shell"
    "test_profiles.sh:Profiles"
    "test_client_startup.sh:Client Startup"
    "test_silent_output.sh:Silent Output"
    "test_env_sanitization.sh:Env Sanitization"
    "test_exec_strategy.sh:Exec Strategy"
    "test_trust_cli.sh:Trust CLI"
    "test_audit.sh:Audit Trail"
    "test_rollback.sh:Rollback"
    "test_setup.sh:Setup"
    "test_learn.sh:Learn Mode"
    "test_nix_paths.sh:Nix Paths"
)

TOTAL_SUITES=${#SUITES[@]}
SUITE_NAMES=()
SUITE_OUTPUT_FILES=()
SUITE_EXIT_FILES=()

# Per-suite timeout in seconds (catches hangs)
SUITE_TIMEOUT=120

# Max parallel suites. Override with NONO_TEST_JOBS=N.
# Default: nproc on Linux, sysctl on macOS, fallback 4.
if [[ -n "${NONO_TEST_JOBS:-}" ]]; then
    MAX_JOBS="$NONO_TEST_JOBS"
elif command -v nproc >/dev/null 2>&1; then
    MAX_JOBS=$(nproc)
elif command -v sysctl >/dev/null 2>&1; then
    MAX_JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
else
    MAX_JOBS=4
fi

echo -e "${BLUE}Running $TOTAL_SUITES test suites ($MAX_JOBS parallel)...${NC}"
echo ""

# Launch a suite in the background, writing output + exit code to files
launch_suite() {
    local script="$1"
    local output_file="$2"

    local exit_file="${output_file%.out}.exit"

    if command -v timeout >/dev/null 2>&1; then
        timeout "$SUITE_TIMEOUT" bash "$SCRIPT_DIR/integration/$script" > "$output_file" 2>&1
        rc=$?
        if [[ "$rc" -eq 124 ]]; then
            echo "" >> "$output_file"
            echo "SUITE TIMED OUT after ${SUITE_TIMEOUT}s" >> "$output_file"
        fi
        echo "$rc" > "$exit_file"
    else
        bash "$SCRIPT_DIR/integration/$script" > "$output_file" 2>&1; rc=$?
        echo "$rc" > "$exit_file"
    fi
}

PIDS=()

for entry in "${SUITES[@]}"; do
    script="${entry%%:*}"
    name="${entry#*:}"

    output_file="$RESULTS_DIR/${script%.sh}.out"
    exit_file="$RESULTS_DIR/${script%.sh}.exit"

    SUITE_NAMES+=("$name")
    SUITE_OUTPUT_FILES+=("$output_file")
    SUITE_EXIT_FILES+=("$exit_file")

    # Wait for a slot if we're at the concurrency limit
    while [[ ${#PIDS[@]} -ge $MAX_JOBS ]]; do
        # Wait for any one PID to finish, then compact the array
        NEW_PIDS=()
        for pid in "${PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                NEW_PIDS+=("$pid")
            else
                wait "$pid" 2>/dev/null || true
            fi
        done
        PIDS=("${NEW_PIDS[@]}")
        if [[ ${#PIDS[@]} -ge $MAX_JOBS ]]; then
            sleep 0.2
        fi
    done

    launch_suite "$script" "$output_file" &
    PIDS+=($!)
done

# Wait for remaining suites to finish
for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

# =============================================================================
# Print Results in Order
# =============================================================================

PASSED_SUITES=0
FAILED_SUITES=0
FAILED_NAMES=""

for i in "${!SUITE_NAMES[@]}"; do
    name="${SUITE_NAMES[$i]}"
    output_file="${SUITE_OUTPUT_FILES[$i]}"
    exit_file="${SUITE_EXIT_FILES[$i]}"

    exit_code=1
    if [[ -f "$exit_file" ]]; then
        exit_code=$(cat "$exit_file")
    fi

    echo ""
    echo -e "${BOLD}Suite: $name${NC}"
    echo "----------------------------------------"
    cat "$output_file"

    if [[ "$exit_code" -eq 0 ]]; then
        echo -e "${GREEN}Suite PASSED${NC}: $name"
        PASSED_SUITES=$((PASSED_SUITES + 1))
    else
        echo -e "${RED}Suite FAILED${NC}: $name"
        FAILED_SUITES=$((FAILED_SUITES + 1))
        FAILED_NAMES="$FAILED_NAMES  - $name\n"
    fi
done

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
