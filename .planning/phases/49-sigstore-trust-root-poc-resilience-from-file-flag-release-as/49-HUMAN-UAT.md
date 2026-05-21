---
status: partial
phase: 49-sigstore-trust-root-poc-resilience-from-file-flag-release-as
source: [49-VERIFICATION.md]
started: 2026-05-21T20:30:00Z
updated: 2026-05-21T20:30:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Cross-target clippy on x86_64-unknown-linux-gnu + x86_64-apple-darwin
expected: Both `cargo clippy --workspace --target <T> -- -D warnings -D clippy::unwrap_used` invocations exit 0. Decisive signal lives in post-merge live GH Actions Linux Clippy + macOS Clippy lanes on the head SHA (Windows dev host lacks the cross-toolchains for native-build deps aws-lc-sys + ring). Documented PARTIAL per CLAUDE.md § Cross-target clippy verification rule + `.planning/templates/cross-target-verify-checklist.md`.
result: [pending]

### 2. Live release-asset verification on the next tagged release (e.g., v2.6.0)
expected: After the next tag push: `gh release view <tag> --json assets | jq '.assets[].name'` lists `trusted_root.json`; `gh release download <tag> -p trusted_root.json && diff trusted_root.json crates/nono/tests/fixtures/trust-root-frozen.json` exits 0; `gh release download <tag> -p SHA256SUMS.txt && grep trusted_root.json SHA256SUMS.txt` exits 0. Manual-Only per VALIDATION.md.
result: [pending]

### 3. Live positive `.ps1` smoke-script Scenario 1 on a Windows host with built `nono.exe` on PATH
expected: `pwsh -NoProfile -File scripts/verify-trust-root-cached.ps1 crates/nono/tests/fixtures/trust-root-frozen.json` exits 0 and prints `PASS: ... cache is byte-identical (SHA-256: <hex>)`. Note: the `.sh` equivalent positive path was run post-merge on this Windows-host-with-Git-Bash and exited 0 (49-VERIFICATION.md confirms). Scenarios 2 + 3 of the `.ps1` already PASS live per 49-03-SUMMARY § Task 4. Manual-Only per VALIDATION.md.
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps
