#!/bin/bash
# nono Nix Integration Test Runner
# Runs Nix-specific integration tests against Nix-installed programs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}======================================${NC}"
echo -e "${BOLD}  nono Nix Integration Tests${NC}"
echo -e "${BOLD}======================================${NC}"
echo ""

# Use pre-built binary (CI builds before running this script)
export NONO_BIN="${NONO_BIN:-$PROJECT_ROOT/target/release/nono}"
export PATH="$PROJECT_ROOT/target/release:$PATH"

if [[ ! -x "$NONO_BIN" ]]; then
    echo -e "${RED}ERROR: nono binary not found at $NONO_BIN${NC}"
    echo "Run 'cargo build --release' first"
    exit 1
fi

echo -e "Binary: ${GREEN}$NONO_BIN${NC}"
echo -e "Version: $("$NONO_BIN" --version 2>/dev/null || echo 'unknown')"
echo -e "Platform: $(uname -s) $(uname -m)"
echo ""

# Check Nix is available
if ! command -v nix-env >/dev/null 2>&1; then
    echo -e "${RED}ERROR: Nix is not installed${NC}"
    exit 1
fi

echo -e "Nix: $(nix --version 2>/dev/null || echo 'unknown')"
echo ""

chmod +x "$SCRIPT_DIR"/integration/test_nix_paths.sh
chmod +x "$SCRIPT_DIR"/lib/*.sh

echo -e "${BLUE}Running Nix path tests...${NC}"
echo ""

bash "$SCRIPT_DIR/integration/test_nix_paths.sh"
exit_code=$?

echo ""
if [[ "$exit_code" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All Nix integration tests passed!${NC}"
else
    echo -e "${RED}${BOLD}Nix integration tests failed.${NC}"
fi

exit "$exit_code"
