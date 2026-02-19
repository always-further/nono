#!/usr/bin/env bash
# Step 0: Reproduce Chrome/Playwright IOKit failure under Seatbelt
#
# Confirms that IOKit access is the actual blocker by running Playwright
# under two raw Seatbelt profiles — one without IOKit rules (should crash)
# and one with (should succeed).
#
# Prerequisites: @playwright/test installed with chromium browser
#   cd scripts && npm install @playwright/test && npx playwright install chromium

set -euo pipefail

# Resolve script directory so npx finds the local @playwright/test install
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

# Seatbelt profile matching nono's (deny default) baseline — everything
# a typical process needs EXCEPT IOKit. Intentionally permissive so that
# IOKit is the ONLY variable between the two tests.
PROFILE_WITHOUT_IOKIT='
(version 1)
(deny default)
(allow process-exec*)
(allow process-fork)
(allow process-info*)
(allow sysctl-read)
(allow mach-lookup)
(allow mach-register)
(allow mach-per-user-lookup)
(allow mach-task-name)
(allow mach-task-special-port*)
(allow ipc-posix-shm-read-data)
(allow ipc-posix-shm-write-data)
(allow ipc-posix-shm-write-create)
(allow signal)
(allow system-socket)
(allow system-fsctl)
(allow system-info)
(allow pseudo-tty)
(allow file-read*)
(allow file-write*)
(allow file-map-executable)
(allow file-ioctl)
(allow network*)
'

# Same profile WITH IOKit access added.
PROFILE_WITH_IOKIT="${PROFILE_WITHOUT_IOKIT}
(allow iokit-open)
(allow iokit-get-properties)
"

print_header() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  $1${RESET}"
    echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
    echo ""
}

print_result() {
    local exit_code=$1
    local expected=$2
    local label=$3

    if [ "$expected" = "fail" ]; then
        if [ "$exit_code" -ne 0 ]; then
            echo -e "${GREEN}[PASS]${RESET} $label — exited $exit_code (crash expected)${RESET}"
            return 0
        else
            echo -e "${RED}[UNEXPECTED]${RESET} $label — exited 0 (expected crash)${RESET}"
            return 1
        fi
    else
        if [ "$exit_code" -eq 0 ]; then
            echo -e "${GREEN}[PASS]${RESET} $label — exited 0 (success expected)${RESET}"
            return 0
        else
            echo -e "${RED}[FAIL]${RESET} $label — exited $exit_code (expected success)${RESET}"
            return 1
        fi
    fi
}

# ── Preflight ────────────────────────────────────────────────────────

if [[ "$(uname)" != "Darwin" ]]; then
    echo -e "${RED}Error: This script is macOS-only (requires sandbox-exec).${RESET}"
    exit 1
fi

if ! command -v node &>/dev/null; then
    echo -e "${RED}Error: node not found. Install Node.js first.${RESET}"
    exit 1
fi

LAUNCH_SCRIPT="$SCRIPT_DIR/launch-chromium.mjs"
if [ ! -f "$LAUNCH_SCRIPT" ]; then
    echo -e "${RED}Error: launch-chromium.mjs not found in $SCRIPT_DIR${RESET}"
    exit 1
fi

if [ ! -d "$SCRIPT_DIR/node_modules/playwright" ]; then
    echo -e "${RED}Error: playwright not installed. Run: cd scripts && npm install @playwright/test && npx playwright install chromium${RESET}"
    exit 1
fi

echo -e "${YELLOW}Tip: Monitor sandbox violations in another terminal with:${RESET}"
echo -e "${YELLOW}  log stream --predicate 'subsystem == \"com.apple.sandbox\" AND message CONTAINS \"iokit\"' --style compact${RESET}"
echo ""

# ── Test 1: WITHOUT IOKit (expect crash) ─────────────────────────────

print_header "Test 1: Seatbelt WITHOUT IOKit rules (expect crash)"

echo "Running: sandbox-exec ... node launch-chromium.mjs"
echo ""

set +e
sandbox-exec -p "$PROFILE_WITHOUT_IOKIT" \
    env NODE_PATH="$SCRIPT_DIR/node_modules" node "$LAUNCH_SCRIPT" 2>&1 \
    | head -50
EXIT_WITHOUT=$?
set -e

echo ""
test1_ok=0
print_result $EXIT_WITHOUT "fail" "Chrome WITHOUT IOKit" || test1_ok=1

# ── Test 2: WITH IOKit (expect success) ──────────────────────────────

print_header "Test 2: Seatbelt WITH IOKit rules (expect success)"

echo "Running: sandbox-exec ... node launch-chromium.mjs"
echo ""

set +e
sandbox-exec -p "$PROFILE_WITH_IOKIT" \
    env NODE_PATH="$SCRIPT_DIR/node_modules" node "$LAUNCH_SCRIPT" 2>&1 \
    | head -50
EXIT_WITH=$?
set -e

echo ""
test2_ok=0
print_result $EXIT_WITH "pass" "Chrome WITH IOKit" || test2_ok=1

# ── Summary ──────────────────────────────────────────────────────────

print_header "Summary"

echo "  Without IOKit: exit code $EXIT_WITHOUT (expected non-zero)"
echo "  With IOKit:    exit code $EXIT_WITH (expected 0)"
echo ""

if [ $test1_ok -eq 0 ] && [ $test2_ok -eq 0 ]; then
    echo -e "${GREEN}${BOLD}Conclusion: IOKit is confirmed as the blocker.${RESET}"
    echo "  Adding (allow iokit-open) + (allow iokit-get-properties) fixes Chrome."
    exit 0
elif [ $test1_ok -eq 0 ] && [ $test2_ok -ne 0 ]; then
    echo -e "${RED}${BOLD}Conclusion: Chrome crashes both with and without IOKit.${RESET}"
    echo "  There may be additional Seatbelt rules needed beyond IOKit."
    echo "  Check sandbox violations: log stream --predicate 'subsystem == \"com.apple.sandbox\"' --style compact"
    exit 1
elif [ $test1_ok -ne 0 ] && [ $test2_ok -eq 0 ]; then
    echo -e "${YELLOW}${BOLD}Conclusion: Chrome works even WITHOUT IOKit rules.${RESET}"
    echo "  IOKit may not be needed on this hardware/macOS version."
    echo "  The --allow-iokit flag would still be useful for other configurations."
    exit 0
else
    echo -e "${YELLOW}${BOLD}Conclusion: Unexpected results — review output above.${RESET}"
    exit 1
fi
