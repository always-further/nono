#!/bin/bash
# Run all integration tests and summarize results
set -uo pipefail

source ~/.cargo/env 2>/dev/null || true
cd ~/nono

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
FAILED_SUITES=""

for f in tests/integration/test_*.sh; do
    name=$(basename "$f")
    echo ""
    echo "============================================"
    echo "  $name"
    echo "============================================"
    output=$(bash "$f" 2>&1)
    exit_code=$?
    echo "$output"

    # Extract counts from the summary line
    passed=$(echo "$output" | grep -oP 'Passed:\s+\S*\K[0-9]+' || echo "0")
    failed=$(echo "$output" | grep -oP 'Failed:\s+\S*\K[0-9]+' || echo "0")
    skipped=$(echo "$output" | grep -oP 'Skipped:\s+\S*\K[0-9]+' || echo "0")

    TOTAL_PASS=$((TOTAL_PASS + passed))
    TOTAL_FAIL=$((TOTAL_FAIL + failed))
    TOTAL_SKIP=$((TOTAL_SKIP + skipped))

    if [[ "$failed" -gt 0 || "$exit_code" -ne 0 ]]; then
        FAILED_SUITES="$FAILED_SUITES $name"
    fi
done

echo ""
echo "============================================"
echo "  ALL SUITES SUMMARY"
echo "============================================"
echo "  Total passed:  $TOTAL_PASS"
echo "  Total failed:  $TOTAL_FAIL"
echo "  Total skipped: $TOTAL_SKIP"
if [[ -n "$FAILED_SUITES" ]]; then
    echo "  Failed suites:$FAILED_SUITES"
fi
echo "============================================"

[[ "$TOTAL_FAIL" -eq 0 ]]
