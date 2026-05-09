---
status: partial
phase: 31-broker-process-architecture-shell-01
source: [31-VERIFICATION.md]
started: 2026-05-09T00:00:00Z
updated: 2026-05-09T00:00:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Re-run field acceptance harness on Windows test box
expected: Acceptance #1, #2, #3, #4 (or skipped), and #7 all PASS as recorded in 31-FIELD-SMOKE.md (2026-05-09 row); claude TUI renders correctly under broker dispatch; Set-Content write outside grant set raises UnauthorizedAccessException at OS level
result: [pending]
why_human: Acceptance gates #1-#4 + #7 are operator-attested per CONTEXT D-14 (single-box validation). The OUTCOME: SUCCESS flag in 31-FIELD-SMOKE.md is the operator's recorded verdict; the verifier cannot independently re-run the broker on a Windows test box from this environment.

### 2. Re-run `cargo test -p nono-cli --target x86_64-pc-windows-msvc broker_dispatch_tests` on Windows host
expected: 2 passed; 0 failed; 0 ignored — including the lifted `broker_launch_assigns_child_to_job_object` test asserting IsProcessInJob(broker_pid, job, &mut in_job) returns in_job != 0
result: [pending]
why_human: The Job Object containment test runs only on Windows targets with the broker pre-built. Operator must confirm the test still passes — OR the orchestrator must accept the 31-05-SUMMARY recorded result (2/2 PASS on 2026-05-09).

### 3. Confirm silent-SKIP behavior of `broker_launch_assigns_child_to_job_object` (REVIEW CR-04 secondary)
expected: Either (a) accept the SKIP-as-PASS shape because Plan 31-05 owns the runtime acceptance via field-test, OR (b) decide to add #[ignore] back so missing artifact does not show as PASS in unaware CI runs
result: [pending]
why_human: Policy decision: should the absence of a broker artifact in a CI/dev build fail the test or silently skip? Plan 31-05 designed it to skip; CR-04 flagged this as a false-PASS class. Decision is non-blocking for Phase 31 (the field-test runner has the artifact) but should be documented for v2.4 CI matrix expansion.

### 4. Triage REVIEW.md CR-01, CR-02, CR-03 dispositions
expected: Decide whether each REVIEW critical is (i) a Phase 31 BLOCKER requiring a follow-up plan before milestone close, (ii) a v2.4 follow-up entry, or (iii) accepted as-is via VERIFICATION override
result: [pending]
why_human: These are real defects in the shipped code but do NOT invalidate any Phase 31 must-have truth — they affect downstream FFI consumers (CR-01) or theoretical broker invocation paths that the production cascade never reaches (CR-02, CR-03). Phase 31's PTY+supervised acceptance criteria are unaffected. The operator/maintainer should decide handling.

## Summary

total: 4
passed: 0
issues: 0
pending: 4
skipped: 0
blocked: 0

## Gaps
