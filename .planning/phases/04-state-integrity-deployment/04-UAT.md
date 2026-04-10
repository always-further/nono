---
status: complete
phase: 04-state-integrity-deployment
source: [04-01-SUMMARY.md, 04-02-SUMMARY.md, 04-03-SUMMARY.md]
started: 2026-04-05T00:00:00Z
updated: 2026-04-05T00:00:00Z
---

## Current Test

[testing complete]

## Tests

### 1. rollback list shows audit-only tag
expected: Run a supervised session where snapshot baseline capture fails (or simulate). Run `nono rollback list`. The session row shows `[audit-only]` or `[audit-only (capture failed)]` tag.
result: blocked
blocked_by: prior-phase
reason: "nono run on Windows requires nono-wfp-service to be running. Error: Failed to connect to nono-wfp-service: The system cannot find the file specified. (os error 2). Is it running?"

### 2. rollback list --json includes rollback_available and rollback_status
expected: Run `nono rollback list --json`. Each session object includes `"rollback_available": true/false` and `"rollback_status": "Available"/"Skipped"/"FailedWarningOnly"` fields (not just implicit booleans).
result: blocked
blocked_by: prior-phase
reason: "Requires nono run to create sessions first — blocked on nono-wfp-service not running"

### 3. rollback show warns on audit-only session
expected: Run `nono rollback show <id>` for an audit-only session. A warning header is emitted before the session details (e.g. "Warning: this session was captured in audit-only mode — no restore is available").
result: blocked
blocked_by: prior-phase
reason: "Requires nono run to create sessions first — blocked on nono-wfp-service not running"

### 4. rollback restore rejects audit-only session
expected: Run `nono rollback restore <id>` for an audit-only session. The command exits with a clear error message refusing the restore (not a panic or generic failure).
result: blocked
blocked_by: prior-phase
reason: "Requires nono run to create sessions first — blocked on nono-wfp-service not running"

### 5. partial restore surfaces per-file failures
expected: If a restore encounters a locked file, the error output names the specific locked/failed paths (via `NonoError::PartialRestore`) rather than silently succeeding or giving a generic error.
result: pass

### 6. older session.json deserializes without rollback_status field
expected: A `session.json` written by a pre-04-01 build (no `rollback_status` field) loads without error. `rollback list` and `rollback show` treat it as `Available` (the serde default).
result: pass

### 7. snapshot.rs compiles on non-Unix target
expected: `cargo build -p nono --target x86_64-pc-windows-msvc` (or cross-compile check) succeeds. The removed `use std::os::unix::fs::MetadataExt` no longer causes a Windows compile failure.
result: pass

### 8. WFP sweep summary format is correct
expected: Running `cargo test -p nono-cli --bin nono-wfp-service` passes all 18 tests. The `build_sweep_summary` output matches `"removed=N skipped=N failed=N"` format.
result: pass

### 9. Machine MSI includes EventLog source registration
expected: Running `scripts/validate-windows-msi-contract.ps1` on a machine-scope WXS passes its EventLog assertions (RegistryKey for `EventLog\Application\nono-wfp-service`, `EventMessageFile`, `TypesSupported` values present). User MSI asserts no EventLog registry keys.
result: pass

### 10. MSRV is 1.77 in workspace Cargo.toml
expected: `grep rust-version Cargo.toml` shows `rust-version = "1.77"`.
result: pass

### 11. Signing script fails closed without cert secret
expected: Running `scripts/sign-windows-artifacts.ps1` without `WINDOWS_SIGNING_CERT` env var set exits with a non-zero code and a clear error message before producing any artifact.
result: pass

### 12. Release workflow matrix includes Windows target
expected: `.github/workflows/release.yml` contains a `x86_64-pc-windows-msvc` entry in the build matrix with WiX install, dual MSI build, signing, two-layer verify, and upload steps — all gating upload.
result: pass

### 13. Signing script uses RFC 3161 /tr + /td sha256
expected: `scripts/sign-windows-artifacts.ps1` invokes signtool with `/tr http://timestamp.digicert.com /td sha256` (not legacy `/t`). The verify step uses `/pa /tw` so missing timestamps are hard failures.
result: pass

## Summary

total: 13
passed: 9
issues: 0
pending: 0
skipped: 0
blocked: 4

## Gaps

[none yet]
