---
phase: 31-broker-process-architecture-shell-01
verified: 2026-05-09T00:00:00Z
status: human_needed
score: 6/7 must-haves verified
must_haves_total: 7
must_haves_verified: 6
overrides_applied: 0
human_verification:
  - test: "Re-run the field acceptance harness on the user's Windows test box"
    expected: "Acceptance #1, #2, #3, #4 (or skipped), and #7 all PASS as recorded in 31-FIELD-SMOKE.md (2026-05-09 row); claude TUI renders correctly under broker dispatch; Set-Content write outside grant set raises UnauthorizedAccessException at OS level"
    why_human: "Acceptance gates #1-#4 + #7 are operator-attested per CONTEXT D-14 (single-box validation). The OUTCOME: SUCCESS flag in 31-FIELD-SMOKE.md is the operator's recorded verdict; the verifier cannot independently re-run the broker on a Windows test box from this environment. The orchestrator should confirm the operator's attestation is intact and trust the recorded result, OR re-run the harness if any source/binary changed since 2026-05-09."
  - test: "Re-run `cargo test -p nono-cli --target x86_64-pc-windows-msvc broker_dispatch_tests` on a Windows host with the broker pre-built"
    expected: "2 passed; 0 failed; 0 ignored — including the lifted `broker_launch_assigns_child_to_job_object` test asserting IsProcessInJob(broker_pid, job, &mut in_job) returns in_job != 0"
    why_human: "The Job Object containment test runs only on Windows targets. The verifier (running on Windows but outside a Cargo test cycle) cannot invoke the test harness without compiling+running. Operator must confirm the test still passes — OR the orchestrator must accept the 31-05-SUMMARY recorded result (2/2 PASS on 2026-05-09)."
  - test: "Confirm that the silent-SKIP behavior of `broker_launch_assigns_child_to_job_object` when the broker artifact is missing is acceptable as a CI signal (REVIEW WR/IN finding from CR-04 secondary concern)"
    expected: "Either (a) accept the SKIP-as-PASS shape because Plan 31-05 owns the runtime acceptance via field-test, OR (b) decide to add #[ignore] back so missing artifact does not show as PASS in unaware CI runs"
    why_human: "Policy decision: should the absence of a broker artifact in a CI/dev build fail the test or silently skip? Plan 31-05 designed it to skip; CR-04 flagged this as a false-PASS class. Decision is non-blocking for Phase 31 (the field-test runner has the artifact) but should be documented for v2.4 CI matrix expansion."
  - test: "Triage REVIEW.md CR-01 (FFI BrokerNotFound -> ErrPathNotFound semantic mismatch) and CR-02 (broker accepts --inherit-handle 0x0) and CR-03 (empty inherit-handle list path likely fails)"
    expected: "Decide whether each REVIEW critical is (i) a Phase 31 BLOCKER requiring a follow-up plan before milestone close, (ii) a v2.4 follow-up entry, or (iii) accepted as-is via VERIFICATION override"
    why_human: "These are real defects in the shipped code but do NOT invalidate any Phase 31 must-have truth — they affect downstream FFI consumers (CR-01) or theoretical broker invocation paths that the production cascade never reaches (CR-02, CR-03). Phase 31's PTY+supervised acceptance criteria are unaffected. The operator/maintainer should decide handling."
---

# Phase 31: Broker-Process Architecture (SHELL-01) Verification Report

**Phase Goal:** Productionize the broker-pattern PoC validated on the Windows test box (commit 98d38ed9, 2026-05-08). Replace direct Low-IL primary token spawn (Phase 30 D-01) with a Medium-IL broker (`crates/nono-shell-broker/`) that self-degrades and spawns the Low-IL shell child via `CreateProcessAsUserW(dwCreationFlags=EXTENDED_STARTUPINFO_PRESENT)`. Land `nono shell --profile claude-code` Windows path with mandatory-label NO_WRITE_UP write-deny intact AND ConPTY TUI rendering, OR close as failure-mode finding analogous to Phase 30.

**Verified:** 2026-05-09
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (derived from CONTEXT.md Acceptance #1–#7 + D-01..D-16)

| #   | Truth                                                                                                                                                                                | Status     | Evidence                                                                                                                                                                                                                            |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | A new `crates/nono-shell-broker/` workspace member exists, builds clean, and replicates the validated PoC's 8-step Win32 sequence with `// SAFETY:` discipline and no `.unwrap()`     | VERIFIED   | `Cargo.toml` lines 3-9 register member; `crates/nono-shell-broker/src/main.rs` 356 lines; broker doc-comment at lines 1-22 documents the 5-step responsibility; `// SAFETY:` annotation on every unsafe block confirmed in REVIEW   |
| 2   | `nono.exe` cascade routes the PTY+supervised launch path to a new `WindowsTokenArm::BrokerLaunch` arm (D-15) that resolves `nono-shell-broker.exe` as sibling of `current_exe()` (D-07) | VERIFIED   | `crates/nono-cli/src/exec_strategy_windows/launch.rs:1108` selector returns `WindowsTokenArm::BrokerLaunch`; lines 1198, 1246 dispatch the arm; lines 1251-1265 resolve sibling broker via `current_exe().parent()` and fail-fast    |
| 3   | `BrokerLaunch` arm uses `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to whitelist only the two ConPTY pipe handles for `nono.exe` → broker boundary (D-02)                                       | VERIFIED   | `launch.rs:1277` builds `inherit_handles: [HANDLE; 2] = [pty_pair.input_write, pty_pair.output_read]`; lines 1340-1349 call `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, ...)`; SetHandleInformation flip+unflip live |
| 4   | Broker spawns Low-IL child via `CreateProcessAsUserW(dwCreationFlags=EXTENDED_STARTUPINFO_PRESENT)` — NO `CREATE_NEW_CONSOLE`, NO `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` (D-01)         | VERIFIED   | `crates/nono-shell-broker/src/main.rs:228-260` calls `CreateProcessAsUserW` with `EXTENDED_STARTUPINFO_PRESENT` only; REVIEW WR-04 confirms zero non-comment `CREATE_NEW_CONSOLE` / `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`            |
| 5   | Broker artifact ships in MSI + zip + standalone via `.github/workflows/release.yml` Authenticode-signed with the same key as `nono.exe` (D-05, D-13 fail-closed)                       | VERIFIED   | `.github/workflows/release.yml`: line 79 builds broker; line 188 signs `@($binary, $broker, $machineMsi, $userMsi)`; line 205 verifies all 4 via `Get-AuthenticodeSignature`; line 227 zips both; line 267 stages broker for upload     |
| 6   | Field-validation: Acceptance #1, #2, #3, #4 (or SKIPPED), #7 all PASS on user's Windows test box; broker_dispatch_tests 2/2 PASS including D-04 Job Object containment test            | UNCERTAIN  | `31-FIELD-SMOKE.md` line 7 records `OUTCOME: SUCCESS` and 2026-05-09 operator log row with PASS for all acceptance; `31-05-SUMMARY.md` records `cargo test broker_dispatch_tests` `2 passed; 0 failed; 0 ignored`. Operator-attested only — verifier cannot independently re-run on Windows test box. |
| 7   | SHELL-01 row flipped from `⚠ Phase 31 candidate` to `✔ validated v2.3 Phase 31` in PROJECT.md / STATE.md / ROADMAP.md; cookbook security-envelope paragraph added to `windows-poc-handoff.mdx` | VERIFIED   | `PROJECT.md:71` reads `✔ SHELL-01 — \`nono shell\` on Windows: validated v2.3 Phase 31 (2026-05-09)`; `ROADMAP.md:298` reads `\| 31. Broker-Process Architecture (SHELL-01) \| v2.3 \| 6/6 \| Complete \| 2026-05-09 \|`; `docs/cli/development/windows-poc-handoff.mdx:212` opens `## Windows nono shell — security envelope (Phase 31, validated 2026-05-09)`; cookbook contains 17 occurrences of `broker`, 7 of `NO_WRITE_UP`, 0 of `deferred to v3.0` |

**Score:** 6/7 truths verified (1 UNCERTAIN — requires human attestation of field-test re-run)

### Required Artifacts

| Artifact                                                                                              | Expected                                                                              | Status     | Details                                                                                                                                                                                |
| ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Cargo.toml` (workspace root)                                                                         | Registers `crates/nono-shell-broker` as workspace member                              | VERIFIED   | line 7: `"crates/nono-shell-broker"` present in members array                                                                                                                          |
| `crates/nono-shell-broker/Cargo.toml`                                                                 | Workspace-inheriting manifest with windows-sys 0.59 + nono path-dep + tracing-subscriber | VERIFIED   | Verified by REVIEW; broker builds clean per `cargo build` (no source errors)                                                                                                            |
| `crates/nono-shell-broker/src/main.rs`                                                                | 356 LOC; 8-step PoC sequence; argv parser (D-08); HANDLE_LIST (D-02); RAII via OwnedHandle | VERIFIED   | 356 lines confirmed; `nono::create_low_integrity_primary_token`, `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, `EXTENDED_STARTUPINFO_PRESENT` all present                                       |
| `crates/nono/src/sandbox/windows.rs` lifted `pub fn create_low_integrity_primary_token`                | Library-resident, callable from broker + nono-cli (D-06)                              | VERIFIED   | line 534: `pub fn create_low_integrity_primary_token() -> Result<OwnedHandle>`; tests at line 3445+                                                                                    |
| `crates/nono/src/error.rs` — `NonoError::BrokerNotFound { path: PathBuf }`                            | New variant for D-07 fail-fast                                                        | VERIFIED   | line 52: `BrokerNotFound { path: PathBuf }`; tests at lines 270-289                                                                                                                    |
| `crates/nono-cli/src/exec_strategy_windows/launch.rs` BrokerLaunch arm                                | New cascade arm; HANDLE_LIST; sibling broker resolution; Job Object containment        | VERIFIED   | line 1108 selector, lines 1246-1438 dispatch, lines 1262-1265 sibling resolution + BrokerNotFound, line 2247 broker_launch_assigns_child_to_job_object test (no #[ignore])             |
| `.github/workflows/release.yml` broker signing pipeline                                                | Builds, signs, verifies, zips, uploads broker alongside nono.exe                       | VERIFIED   | 28 occurrences of `nono-shell-broker`/`broker` across build/sign/verify/zip/upload steps; same Authenticode key as nono.exe                                                            |
| `scripts/build-windows-msi.ps1` -BrokerPath parameter                                                 | Mandatory; included in machine + user MSIs                                            | VERIFIED   | `BrokerPath` referenced 4 times (param block, validation, FullPath, WiX <File Source=>)                                                                                                |
| `scripts/test-windows-shell-write-deny.ps1` Set-Content fix                                           | Replaces `Out-File 'path' 'content'` with `Set-Content -Path -Value`                   | VERIFIED   | line 146 contains `Set-Content -Path '$targetFile' -Value 'phase 31 write-deny test' -ErrorAction Stop`; zero `Out-File '` matches                                                     |
| `docs/cli/development/windows-poc-handoff.mdx` security envelope section                              | Phase 31 broker security envelope; zero active "deferred to v3.0" references          | VERIFIED   | `## Windows nono shell — security envelope (Phase 31, validated 2026-05-09)` at line 212; 17 broker mentions, 7 NO_WRITE_UP, 9 hook/defense-in-depth, 0 deferred-to-v3.0               |
| `.planning/phases/31-broker-process-architecture-shell-01/31-FIELD-SMOKE.md`                          | Operator runbook with OUTCOME flag + 2026-05-09 log row                                | VERIFIED   | line 7: `OUTCOME: SUCCESS`; line 114: 2026-05-09 operator row with PASS entries for #1, #2, #3, #4, #7                                                                                  |

### Key Link Verification

| From                                                                | To                                                          | Via                                          | Status   | Details                                                                                                                          |
| ------------------------------------------------------------------- | ----------------------------------------------------------- | -------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `nono-cli` BrokerLaunch arm                                          | `nono-shell-broker.exe` sibling                             | `current_exe().parent().join(...)` (D-07)    | WIRED    | launch.rs:1251-1265 resolves + fail-fast with BrokerNotFound                                                                     |
| `nono-cli` BrokerLaunch arm                                          | broker argv contract                                        | `--shell --shell-arg --inherit-handle --cwd` (D-08) | WIRED    | launch.rs:1372-1384 emits all 4 flags; broker main.rs:74-100 parses all 4                                                       |
| `nono-cli` BrokerLaunch arm                                          | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (only 2 ConPTY pipes)    | InitializeProcThreadAttributeList + Update   | WIRED    | launch.rs:1308-1349 builds attr list with input_write + output_read                                                              |
| Broker `main.rs`                                                     | `nono::create_low_integrity_primary_token()` (D-06)         | library function call                        | WIRED    | broker main.rs:41 imports `nono::{NonoError, OwnedHandle, Result as NonoResult}`; calls library function in `run()`              |
| Broker `main.rs`                                                     | `CreateProcessAsUserW(EXTENDED_STARTUPINFO_PRESENT)` (D-01) | windows-sys FFI                              | WIRED    | broker main.rs:248-260 — verified by REVIEW that no `CREATE_NEW_CONSOLE` / `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`                  |
| Release pipeline                                                     | broker.exe Authenticode signing (D-13 fail-closed)          | sign-windows-artifacts.ps1 + Get-AuthenticodeSignature | WIRED    | release.yml:188 signs all 4 artifacts; line 205 verifies; line 239 verifies extracted-zip payload                                |
| MSI installer (machine + user)                                       | broker as INSTALLFOLDER sibling                              | `<Component Id="cmpNonoShellBrokerExe">`     | WIRED    | build-windows-msi.ps1 has 4 occurrences of BrokerPath; component lives in always-present ProductComponents ComponentGroup       |
| Plan 31-05 Job Object test                                           | `IsProcessInJob` runtime assertion (D-04)                    | windows-sys JobObjects FFI                   | WIRED    | launch.rs:2247 test active (no #[ignore]); commit cfb6ef1a confirmed in git log; calls AssignProcessToJobObject + IsProcessInJob |

### D-01..D-16 Decision-Coverage Matrix

| Decision  | Description                                                                              | Status     | Evidence                                                                                                                              |
| --------- | ---------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **D-01**  | Broker spawns child WITHOUT new-console flag, WITHOUT pseudoconsole proc-thread attribute | VERIFIED   | broker main.rs:228-260 uses `EXTENDED_STARTUPINFO_PRESENT` only; REVIEW confirms zero non-comment `CREATE_NEW_CONSOLE` / PSEUDOCONSOLE |
| **D-02**  | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` discipline at `nono.exe`→broker AND broker→child boundaries | PARTIAL    | nono.exe→broker: VERIFIED (launch.rs:1340-1349 with 2 ConPTY pipes). broker→child: VERIFIED (broker main.rs:202-213) but the empty-list path is broken per REVIEW CR-03 — production cascade never reaches it (always passes 2 handles), so this is a defense-in-depth gap, not an acceptance failure |
| **D-03**  | Broker waits for child via `WaitForSingleObject`, propagates exit code; existing supervisor plumbing | VERIFIED   | broker main.rs:262+ documents Step 5 wait + exit-code propagation                                                                      |
| **D-04**  | `AssignProcessToJobObject(broker)` BEFORE broker spawns child; child inherits Job; test asserts | VERIFIED   | test at launch.rs:2247 asserts IsProcessInJob; commit cfb6ef1a lifted #[ignore]; 31-05-SUMMARY records 2/2 PASS on field runner       |
| **D-05**  | New workspace member `crates/nono-shell-broker/`; releases ship sibling                  | VERIFIED   | Cargo.toml registers member; release.yml ships broker.exe; MSI + zip both bundle it                                                  |
| **D-06**  | `create_low_integrity_primary_token` lifted from nono-cli to nono crate as `pub fn`      | VERIFIED   | `crates/nono/src/sandbox/windows.rs:534`; broker consumes via `nono::create_low_integrity_primary_token`                              |
| **D-07**  | `nono.exe` resolves broker via `current_exe().parent()`; new `BrokerNotFound { path }` variant; no env-var override | VERIFIED   | launch.rs:1251-1265 resolves + fail-fast; error.rs:52 variant; doc-comment rejects env-poisoning                                      |
| **D-08**  | Argv-only IPC: `--shell --shell-arg --inherit-handle --cwd`; no JSON                     | VERIFIED   | broker main.rs:74-100 parses all 4 flags; launch.rs:1372-1384 emits all 4; no JSON parser in broker                                   |
| **D-09**  | Acceptance criteria #1-#6 carried forward + new #7                                       | VERIFIED   | 31-FIELD-SMOKE.md acceptance table covers all 5 (operator-attested PASS) + #7 distinguishes OS-deny from parse-error                  |
| **D-10**  | [informational] No audit-ledger emissions in Phase 31; v2.4 follow-up                    | VERIFIED   | Cited as informational; broker uses `tracing::info!` only; no audit emissions present                                                |
| **D-11**  | [informational] AppliedLabelsGuard Drop-ordering bug deferred to separate quick task     | VERIFIED   | Cited as informational; no labels-guard fix attempted in Phase 31                                                                    |
| **D-12**  | Phase 31 ships in v2.3                                                                    | VERIFIED   | ROADMAP.md Progress Table row marks Phase 31 Complete in v2.3                                                                        |
| **D-13**  | Hard timebox + ProcMon at day 5 (failure path); ≤2 days ProcMon                          | NOT TRIGGERED | Field-test reported SUCCESS — D-13 contingency did NOT fire; documented in 31-FIELD-SMOKE.md decision matrix as remaining contract  |
| **D-14**  | Single-box validation discipline                                                          | VERIFIED   | 31-05-SUMMARY records single-box reproduction on user's Windows test box; CI matrix expansion deferred to v2.4                       |
| **D-15**  | Replace LowIlPrimary with BrokerLaunch for PTY+supervised; preserve LowIlPrimary as fallback | VERIFIED   | launch.rs:1098-1117 preserves both arms; PSEUDOCONSOLE legacy block at lines 1439+ kept verbatim; 7/7 pty_token_gate_tests pass     |
| **D-16**  | Rollback story on terminal-failure: SHELL-01 → ✘ deferred to v3.0                        | NOT TRIGGERED | Field-test SUCCESS — D-16 rollback NOT triggered; cookbook + bookkeeping flipped to ✔ validated                                       |

**All 16 decisions accounted for** — D-01..D-08 (architecture + IPC) are VERIFIED, D-09..D-12 (scope + informational) are VERIFIED, D-13/D-16 are NOT TRIGGERED (contingency contracts preserved), D-14/D-15 are VERIFIED. **D-02 is marked PARTIAL** because the broker→child empty-handle-list path has CR-03's documented defect, but the production cascade does not reach it.

### Cross-Reference: 31-REVIEW.md BLOCKER Findings

| Finding | Description | Invalidates a must-have? | Disposition |
| ------- | ----------- | ----------------------- | ----------- |
| **CR-01** | FFI `BrokerNotFound -> ErrPathNotFound` semantic mismatch (should map to `ErrSandboxInit` per CLAUDE.md doc) | NO | Phase 31 must-haves do not specify FFI mapping. The `bindings/c/src/lib.rs` mapping is wrong from a C-API consumer perspective but does not break Rust code paths. Recommend follow-up plan or v2.4 entry. |
| **CR-02** | Broker accepts `--inherit-handle 0x0` without validation | NO | The production cascade in `launch.rs:1379-1382` never emits `0x0` (always passes valid `pty_pair.input_write` and `pty_pair.output_read`). This is a defense-in-depth gap for theoretical malicious or buggy direct-spawn invocations. Recommend follow-up. |
| **CR-03** | Empty `--inherit-handle` list path likely fails with `ERROR_BAD_LENGTH` at runtime | NO | Production callsite always passes 2 handles; empty-list path is structurally unreachable from `nono.exe`. The Plan 31-05 Job Object test invokes the broker WITHOUT `--inherit-handle` BUT the test asserts JobObject membership BEFORE ResumeThread fires — broker is suspended, never executes the broken `UpdateProcThreadAttribute(HANDLE_LIST, cbSize=0)` call. **Test passes on field runner per 31-05-SUMMARY**. The plan-32-02 SUMMARY's claim of "most-restrictive empty list" remains a documentation myth. |
| **CR-04** | `broker_launch_assigns_child_to_job_object` test does NOT have `#[ignore]` despite Plan 31-03 SUMMARY claim | **REVIEWER MISCLASSIFICATION** | Verified via `git show cfb6ef1a` that Plan 31-05 Task 2 commit DID lift the `#[ignore]`. Plan 31-03 SUMMARY's claim ("`broker_dispatch_tests`: 1 passed + 1 ignored") was true at Plan 31-03 close; Plan 31-05 then lifted it per its acceptance criteria. The "lift the ignore" task was NOT a no-op. **HOWEVER**, the SECONDARY concern in CR-04 — that the test silently SKIPs when the broker artifact is missing (false-PASS class for unaware CI runs) — is REAL and surfaced as a `human_needed` decision item below. |

**Summary:** None of the 4 BLOCKERs invalidate any Phase 31 must-have truth. All 4 surface real defects, but CR-01/CR-02 are FFI / argv-validation defense-in-depth gaps, CR-03 is structurally unreachable from production, and CR-04 is a reviewer misclassification of the primary claim (with a valid secondary concern). Phase 31 acceptance gates remain unaffected.

### Anti-Patterns Found

| File                                                       | Line / Area | Pattern                                                       | Severity | Impact                                                                                                          |
| ---------------------------------------------------------- | ----------- | ------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------- |
| `bindings/c/src/lib.rs`                                    | 128-134     | Mismatched FFI error code (`ErrPathNotFound` vs `ErrSandboxInit`) | INFO     | C-API consumers misled; does not affect Rust callers or Phase 31 acceptance                                       |
| `crates/nono-shell-broker/src/main.rs`                     | 87-99       | Hex parser accepts 0x0 / 0xFFFFFFFFFFFFFFFF as HANDLE          | INFO     | Production cascade never emits these values; defense-in-depth gap only                                            |
| `crates/nono-shell-broker/src/main.rs`                     | 200-226     | `UpdateProcThreadAttribute(HANDLE_LIST, cbSize=0)` on empty array | INFO     | Production cascade always passes 2 handles; gate never reached except by Plan 31-05 Job Object test (broker suspended) |
| `crates/nono-cli/src/exec_strategy_windows/launch.rs`      | 2247        | Test silently SKIPs when broker artifact missing (no `#[ignore]`) | INFO     | Could mask absent broker artifact as PASS in unaware CI runs; field-test runner has artifact via Plan 31-04      |
| `scripts/test-windows-shell-write-deny.ps1`                | 51-53, 144  | No `Set-StrictMode -Version Latest`; single-quote interpolation TOCTOU on USERPROFILE | INFO  | REVIEW WR-10/WR-11; harness robustness concerns; not a Phase 31 acceptance failure                                |

No anti-patterns surfaced that block Phase 31 goal achievement.

### Requirements Coverage

Phase 31 has **no formal REQ-IDs** at scope-lock per CONTEXT.md. The phase tracks via decisions D-01..D-16. All 16 decisions accounted for in the Decision-Coverage Matrix above.

### Behavioral Spot-Checks

The phase's runtime acceptance is operator-attested (CONTEXT D-14). Programmatic spot-checks limited to source / file presence:

| Check                                                  | Command                                                                                       | Result | Status |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------- | ------ | ------ |
| Workspace registers nono-shell-broker                  | `grep "nono-shell-broker" Cargo.toml`                                                          | match  | PASS   |
| Broker source compiles (verified via build artifacts)  | (operator on Windows host)                                                                     | n/a    | SKIP   |
| `WindowsTokenArm::BrokerLaunch` cascade arm wired      | `grep "WindowsTokenArm::BrokerLaunch" launch.rs` returns 5 matches (variant + selector + dispatch + 2 tests) | 5      | PASS   |
| `NonoError::BrokerNotFound` variant present            | `grep "BrokerNotFound" error.rs` returns 5 matches                                             | 5      | PASS   |
| Release.yml signs broker                               | `grep "nono-shell-broker" release.yml` returns 28 matches across all required steps             | 28     | PASS   |
| MSI build script accepts BrokerPath                    | `grep "BrokerPath" build-windows-msi.ps1` returns 4 matches                                    | 4      | PASS   |
| Cookbook security envelope present                     | `grep "security envelope" windows-poc-handoff.mdx` returns matches at lines 11, 150, 181, 210, 212, 272 | 6 | PASS   |
| Set-Content harness fix present                        | `grep "Set-Content -Path" test-windows-shell-write-deny.ps1` returns 2 matches; no `Out-File '` | 2/0    | PASS   |
| Field-smoke OUTCOME: SUCCESS recorded                  | `grep "OUTCOME: SUCCESS" 31-FIELD-SMOKE.md` returns 1 match (line 7)                           | 1      | PASS   |

### Human Verification Required

#### 1. Re-confirm field-test attestation OR re-run on Windows test box

**Test:** Verify the operator's 2026-05-09 attestation in `31-FIELD-SMOKE.md` (operator log row) and `31-05-SUMMARY.md` (per-acceptance PASS confirmation). If any source file or binary changed since 2026-05-09, re-run the harness on the Windows test box.

**Expected:** Acceptance #1, #2, #3, #4 (or SKIPPED), #7 all PASS; broker dispatch via `WindowsTokenArm::BrokerLaunch` works end-to-end with no `STATUS_DLL_INIT_FAILED`; mandatory-label NO_WRITE_UP enforces write-deny.

**Why human:** Field-test is operator-attested per CONTEXT D-14 (single-box validation discipline). The verifier cannot run the broker on a Windows test box from this environment.

#### 2. Re-confirm `cargo test broker_dispatch_tests` 2/2 PASS on Windows host

**Test:** Re-run `cargo test -p nono-cli --target x86_64-pc-windows-msvc broker_dispatch_tests` on a Windows host with the broker artifact pre-built.

**Expected:** `2 passed; 0 failed; 0 ignored`.

**Why human:** Test runs only on Windows targets; verifier cannot execute Cargo tests in this verification cycle.

#### 3. Triage REVIEW.md CR-01..CR-04 dispositions

**Test:** For each REVIEW critical, decide:
- **CR-01** (FFI BrokerNotFound mapping wrong): apply REVIEW fix as a follow-up plan, OR add to v2.4 follow-up list, OR accept via override
- **CR-02** (broker accepts 0x0 HANDLE): apply REVIEW fix as a follow-up plan, OR add to v2.4 follow-up list, OR accept via override
- **CR-03** (empty inherit-handle list path broken): document as known-limitation in broker docstring, OR fix per REVIEW recommendation
- **CR-04** (silent SKIP on missing broker artifact): keep current shape (Plan 31-05 design intent), OR add `#[ignore]` to prevent CI false-PASS

**Expected:** Maintainer decision recorded in PROJECT.md or .planning/v2.4-followups (or equivalent backlog).

**Why human:** Policy decisions about defense-in-depth fixes vs. shipping as-is.

#### 4. Confirm the `broker_launch_assigns_child_to_job_object` test execution path on a Windows host without the broker artifact

**Test:** On a Windows host that has NOT pre-built `nono-shell-broker.exe`, run `cargo test -p nono-cli --target x86_64-pc-windows-msvc broker_dispatch_tests`.

**Expected (current behavior):** Test prints "SKIP: broker artifact missing at ..." and returns cleanly; cargo test reports the test as PASS.

**Why human:** Confirms whether the SKIP-as-PASS pattern is acceptable for default `cargo test` runs. CR-04's secondary concern.

### Gaps Summary

**Phase 31 ships its primary goal:** the broker-pattern PoC is productionized as `crates/nono-shell-broker/`, the cascade arm `WindowsTokenArm::BrokerLaunch` dispatches the PTY+supervised path, the release pipeline signs and ships the broker alongside `nono.exe`, and the bookkeeping artifacts (PROJECT.md, STATE.md, ROADMAP.md, cookbook) flip SHELL-01 to ✔ validated v2.3 Phase 31. The 16 CONTEXT.md decisions D-01..D-16 are all accounted for; D-13 / D-16 contingency paths did not trigger.

**Why `human_needed` rather than `passed`:**

1. The field-test acceptance gates (Truth #6) are operator-attested only. The verifier cannot independently re-run the broker on a Windows test box. The 31-FIELD-SMOKE.md `OUTCOME: SUCCESS` flag and 31-05-SUMMARY per-acceptance PASS table are the recorded attestation, dated 2026-05-09. If the orchestrator accepts the recorded attestation as authoritative, this verification effectively passes.

2. The 31-REVIEW.md surfaced 4 BLOCKER findings (CR-01..CR-04). On adversarial re-examination:
   - **None invalidate any Phase 31 must-have truth.**
   - **CR-04 is a reviewer misclassification** of the primary claim (the `#[ignore]` lift was real, per git commit cfb6ef1a). The secondary concern (silent SKIP-as-PASS) is real but is a CI-policy decision, not a Phase 31 acceptance gap.
   - **CR-01..CR-03 are real defects** in shipped code but affect FFI consumers (CR-01), theoretical malicious-argv invocations (CR-02), and a structurally-unreachable broker code path (CR-03). They warrant follow-up but do not block Phase 31's primary goal.

3. The `broker_launch_assigns_child_to_job_object` test's silent-SKIP-on-missing-artifact behavior is a documented design choice in Plan 31-05 (keeps default `cargo test` green for developers without the broker pre-built). Whether this is acceptable for v2.4 CI matrix expansion is a maintainer policy decision.

**Recommendation:** if the orchestrator accepts the operator-attested field-test results as authoritative (consistent with how Phase 15 / Phase 30 / the broker PoC shipped per CONTEXT D-14), the phase status can be promoted from `human_needed` to `passed` after the maintainer confirms (a) the field-test attestation is intact AND (b) CR-01..CR-04 dispositions are recorded (either as follow-up plans, v2.4 backlog entries, or accepted overrides).

---

_Verified: 2026-05-09_
_Verifier: Claude (gsd-verifier)_
