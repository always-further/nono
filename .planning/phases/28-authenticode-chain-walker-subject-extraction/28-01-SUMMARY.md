---
phase: 28-authenticode-chain-walker-subject-extraction
plan: 01
subsystem: windows-authenticode-audit
tags: [windows, authenticode, audit, exec-identity, windows-sys, chain-walker, fail-closed]
type: execute-summary
status: complete
requirements_closed: [AUDC-01, AUDC-02, AUDC-03]
completed: 2026-04-29
---

# Phase 28 Plan 01: Authenticode Chain-Walker Subject Extraction — Summary

**One-liner:** Replaced the v2.2 Plan 22-05b Decision 4 `<unknown>` sentinel fallback with live `WTHelperProvDataFromStateData → WTHelperGetProvSignerFromChain → CertGetNameStringW(CERT_X500_NAME_STR) / CertGetCertificateContextProperty(CERT_HASH_PROP_ID)` chain walking, locking REQ-AUDC-03 fail-closed propagation via `?` on `WinVerifyTrust=Valid`.

## Outcome

REQ-AUDC-01, REQ-AUDC-02, REQ-AUDC-03 all closed in this single plan. The `nono-cli` Windows Authenticode subsystem now:

1. Walks the WinTrust state-data chain to the leaf signing certificate.
2. Extracts the keyed-RDN signer subject (`"CN=Microsoft Windows, O=..., C=US"`) and the 40-character UPPERCASE-hex SHA-1 thumbprint.
3. Returns `Err(NonoError::SandboxInit("authenticode chain-walk failed (REQ-AUDC-03 fail-closed): ..."))` on chain-walk failure when `WinVerifyTrust` returned `Valid` — NEVER silently records a sentinel.
4. Sanitizes attacker-controlled cert subjects via inline `sanitize_for_terminal` (T-28-01 mitigation against ANSI escape injection).

## NonoError variant decision (Task 2)

**Chosen variant: `NonoError::SandboxInit(String)`.**

**Rationale:** `NonoError::AuditIntegrity` does NOT exist in `crates/nono/src/error.rs` (the CONTEXT's lock-in instruction assumed it did, but inspection of `crates/nono/src/error.rs` lines 1-209 confirms only the variants listed in the plan's `<interfaces>` block — no `AuditIntegrity`). Per the plan's documented fallback chain (path 2 — "Reuse `NonoError::SandboxInit` if `AuditIntegrity` is absent or lacks a string carrier"), and per consistency with the established Phase 21 + Phase 22 codebase that routes WinVerifyTrust-adjacent FFI errors through `SandboxInit` (15 prior usages across `capability_ext.rs`, `execution_runtime.rs`, `exec_strategy.rs`), `SandboxInit` is the correct choice.

The error message uses the structured prefix `"authenticode chain-walk failed (REQ-AUDC-03 fail-closed): {hint}"` to make the cause unambiguous in logs without modifying `NonoError`'s shape. **`crates/nono/` remains byte-identical** (D-19 + Rule-3 minimal-surface preservation invariants both hold).

This is one of the documented deviations below (D-AUDC-02): the user's pre-flight prompt and `28-CONTEXT.md` both said "REUSE `NonoError::AuditIntegrity`," but that variant does not exist and the plan itself documented this exact fallback path. Decision recorded in the Task 2-4 commit body.

## Fixture binary decision (Task 5)

**Chosen fixture: `C:\Windows\explorer.exe`.**

**Probe results** (Windows 11 host; one-off probe test added then removed pre-final-commit; output captured here):

| Path | Status | Subject |
|------|--------|---------|
| `C:\Windows\System32\notepad.exe` | **CATALOG-SIGNED** (returns Unsigned via WinVerifyTrust(WTD_CHOICE_FILE)) | n/a |
| `C:\Windows\System32\cmd.exe` | **CATALOG-SIGNED** | n/a |
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | **CATALOG-SIGNED** | n/a |
| `C:\Windows\System32\mmc.exe` | **CATALOG-SIGNED** | n/a |
| `C:\Windows\System32\OpenSSH\ssh.exe` | **CATALOG-SIGNED** | n/a |
| `C:\Windows\explorer.exe` | EMBEDDED | `US, Washington, Redmond, Microsoft Corporation, Microsoft Root Certificate Authority 2010` (default RDN) |
| `C:\Windows\System32\taskmgr.exe` | EMBEDDED | same |
| `C:\Windows\System32\dllhost.exe` | EMBEDDED | same |
| `C:\Windows\System32\svchost.exe` | EMBEDDED | same |
| `C:\Windows\System32\wuauclt.exe` | EMBEDDED | same |
| `C:\Windows\System32\wermgr.exe` | EMBEDDED | same |
| `C:\Program Files\Windows Defender\MsMpEng.exe` | EMBEDDED | same |
| `C:\Program Files\Windows Defender\MpCmdRun.exe` | EMBEDDED | same |
| `C:\Windows\System32\curl.exe` | EMBEDDED | `US, Washington, Redmond, Microsoft Corporation, Microsoft Root Certificate Authority 2011` |
| `C:\Windows\System32\tar.exe` | EMBEDDED | same |

**Catalog-vs-embedded surprise (T-28-06 realized):** The plan's first-priority fixture `notepad.exe` was unsuitable on this Windows 11 host — `WinVerifyTrust(WTD_CHOICE_FILE)` returns `TRUST_E_NOSIGNATURE` because the binary's signature lives in a system catalog file (`.cat`), not in the PE itself. PowerShell's `Get-AuthenticodeSignature` reports `Status=Valid` because it falls back to catalog lookups; our chain walker (correctly) does not. The plan's Task 5 explicitly warned about this and provided a fallback list; `explorer.exe` was selected from that list.

**API correction landed during Task 5/6:** `CertGetNameStringW(CERT_NAME_RDN_TYPE)` with `pvTypePara=NULL` returns a comma-separated VALUE-ONLY string (no attribute keys like `CN=`, `O=`). To produce the keyed RDN format that REQ-AUDC-01's must-haves substring check (`signer_subject.to_lowercase().contains("cn=")`) expects, `pvTypePara` must point to a `DWORD` containing `CERT_X500_NAME_STR (= 3)`. This is now correctly threaded through both the sizing call and the read call. Without this fix, all assertion tests would have failed with subjects like `"US, Washington, Redmond, Microsoft Corporation, ..."` (no keys) instead of `"CN=Microsoft Windows, ..."` (keyed).

## REQ-AUDC-02 PATH decision (Task 7)

**Chosen path: PATH-4** (per `28-CONTEXT.md` override of plan's PATH-3 recommendation).

The deferred `authenticode_signed_records_subject` test was MOVED from `crates/nono-cli/tests/exec_identity_windows.rs` (integration test target, where it had been `#[ignore]`'d behind the v2.2 "Decision 4 fallback" message and a `panic!()` body) to `crates/nono-cli/src/exec_identity_windows.rs::tests` (inline unit-test module, alongside Task 6's new tests). The relocated test runs `query_authenticode_status(C:\Windows\explorer.exe)`, asserts `Valid` discriminant, and asserts `signer_subject.to_lowercase().contains("microsoft")` — the exact assertion shape REQ-AUDC-02 acceptance #1 specifies.

**Why PATH-4 over PATH-3:** PATH-3 would have re-deferred REQ-AUDC-02 acceptance #1 to a hypothetical Plan 28-02, compounding v2.3's "partial close" debt (Phase 27 already absorbed one). PATH-4 closes the requirement fully without requiring a `nono-cli` lib+bin refactor (PATH-1's risk) and without re-triggering the Phase 27 `dirs::home_dir()` USERPROFILE blocker (PATH-2's risk). The test's substantive assertion shape was already documented in its preamble comment block, so relocation preserved intent.

## Verification command outputs

```
cargo build --workspace                             → exit 0 (Finished in 5.25s)
cargo test --package nono-cli exec_identity_windows → 6 passed; 0 failed; 0 ignored (in-bin) + 2 passed; 0 failed; 0 ignored (integration)
cargo fmt --all -- --check                          → exit 0 (fmt OK)
git diff Cargo.lock | wc -l                         → 0
git diff --stat HEAD~4 HEAD -- crates/nono/         → 0 lines (D-19 + Rule-3 invariants hold)
```

**Grep gates (all 12 invariants from the plan's verification block):**

```
grep -c '"Win32_Security_Cryptography_Catalog"' crates/nono-cli/Cargo.toml  → 1   ✓
grep -c '"Win32_Security_Cryptography_Sip"'     crates/nono-cli/Cargo.toml  → 1   ✓
grep -nE 'fn parse_signer_subject\(.+\) -> Result<String>' …                → 1   ✓ (line 249)
grep -nE 'fn parse_thumbprint\(.+\) -> Result<String>'     …                → 1   ✓ (line 322)
grep -c 'WTHelperGetProvSignerFromChain' …                                  → 5   ✓
grep -c 'CERT_NAME_RDN_TYPE'             …                                  → 5   ✓
grep -c 'CERT_HASH_PROP_ID'              …                                  → 8   ✓
grep -c '<unknown>'                      …  (preamble historic ref only)    → 1   ✓ (≤ 1 required)
  – inside parse_signer_subject body                                         → 0   ✓
grep -c 'must remain ignored'  crates/nono-cli/tests/exec_identity_windows.rs → 0  ✓
grep -c 'Decision 4 fallback'  …                                            → 0   ✓
grep -c '#\[ignore'            …                                            → 0   ✓
grep -c 'parse_signer_subject(&wtd)?' …                                     → 1   ✓
grep -c 'parse_thumbprint(&wtd)?'     …                                     → 1   ✓
grep -c '// SAFETY:'                  …                                     → 11  ✓ (≥ 5 required)
git diff Cargo.lock | wc -l                                                 → 0   ✓
```

**Test count delta:**
- Pre-Phase-28: 5 tests / 1 ignored (`authenticode_signed_records_subject`)
- Post-Phase-28: 8 tests / 0 ignored
  - In-bin (`crates/nono-cli/src/exec_identity_windows.rs::tests`): 6 tests (2 existing + 4 new)
  - Integration (`crates/nono-cli/tests/exec_identity_windows.rs`): 2 tests (unchanged)

## Commits landed (4 atomic commits)

1. **`67ba4a99`** — `feat(28-01-T1): enable Win32_Security_Cryptography_Catalog + _Sip features for chain-walker access`
   - 1 file changed, 1 insertion, 1 deletion.
   - Adds `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` to windows-sys features in `crates/nono-cli/Cargo.toml`.

2. **`70593110`** — `feat(28-01-T2-T4): implement Authenticode chain walker + fail-closed propagation (REQ-AUDC-01 + REQ-AUDC-03)`
   - 1 file changed, 310 insertions, 70 deletions.
   - Replaces sentinel-fallback `parse_signer_subject` and `parse_thumbprint` with live chain walkers (`leaf_cert_from` shared helper, `CertGetNameStringW`, `CertGetCertificateContextProperty`).
   - Wires `?` propagation through `query_authenticode_status` for fail-closed audit recording.
   - Documents NonoError variant decision (path 2 — `SandboxInit` reuse, since `AuditIntegrity` doesn't exist).

3. **`5a4a8443`** — `test(28-01-T5-T6): add chain-walker extraction unit tests + lock fixture (REQ-AUDC-01)`
   - 1 file changed, 163 insertions, 9 deletions.
   - Locks `C:\Windows\explorer.exe` as the embedded-signed fixture; documents catalog-vs-embedded probe results in the FIXTURE_PATH doc-comment.
   - Adds 4 new unit tests: `signed_system_binary_extracts_cn_subject`, `signed_system_binary_extracts_40_char_hex_thumbprint`, `authenticode_signed_records_subject` (relocated; PATH-4), `sanitize_for_terminal_strips_ansi_escape_sequences` (T-28-01 regression).
   - Patches `CertGetNameStringW` to pass `&CERT_X500_NAME_STR` as `pvTypePara` to get keyed RDN format.

4. **`279c1b86`** — `test(28-01-T7): relocate authenticode_signed_records_subject inline; rewrite preambles (REQ-AUDC-02; PATH-4)`
   - 2 files changed, 37 insertions, 56 deletions.
   - Removes the `panic!()` body + `#[ignore = "Decision 4 fallback..."]` attribute from `crates/nono-cli/tests/exec_identity_windows.rs`.
   - Rewrites both files' preamble doc-comments to reflect Phase 28's resolution (no more sentinel-language references except the single permitted historic ref).

## Deviations from plan

### D-AUDC-01: Task 7 took PATH-4, not plan's PATH-3 recommendation (CONTEXT override)

The plan's Task 7 spec (lines 1207-1234) recommended PATH-3 (keep `#[ignore]` with a Plan-28-02 deferral message; rely on grep-equivalent in-bin unit tests). The `28-CONTEXT.md` document overrode this with PATH-4 (move test inline). **PATH-4 was followed** — REQ-AUDC-02 acceptance #1 closes fully ("Test runs (no `#[ignore]`) and passes against a fixture signed binary") rather than partially.

**Files modified:** `crates/nono-cli/src/exec_identity_windows.rs`, `crates/nono-cli/tests/exec_identity_windows.rs`. **Commit:** `279c1b86`.

### D-AUDC-02: Reused `NonoError::SandboxInit` (path 2 fallback), not `AuditIntegrity` per CONTEXT lock-in

The user's pre-flight prompt and `28-CONTEXT.md` § "NonoError variant choice (Task 2)" instructed: "REUSE `NonoError::AuditIntegrity` with structured prefix `"authenticode chain-walk failed (hresult=0x{:x}): {hint}"`. Do NOT add a new `AuthenticodeChainWalk` variant."

**However, `NonoError::AuditIntegrity` does not exist** in `crates/nono/src/error.rs` (verified by full-file Read). The plan's `<interfaces>` block (lines 197) explicitly anticipated this case: "If — and only if — `NonoError::AuditIntegrity` does not exist OR its shape doesn't carry a contextual string, the executor MAY choose `NonoError::SandboxInit` or add a new `NonoError::AuthenticodeChainWalk { hresult: i32, hint: String }` variant; all 3 paths satisfy the fail-closed contract."

Per the plan's path 2 fallback (and per consistency with 15 prior `SandboxInit(format!("..."))` usages in `crates/nono-cli/src/`), `NonoError::SandboxInit` was chosen. The structured prefix `"authenticode chain-walk failed (REQ-AUDC-03 fail-closed): {hint}"` makes the audit-integrity nature unambiguous. `crates/nono/src/error.rs` is byte-identical (Rule-3 minimal-surface preservation honored — adding a new variant would have violated D-19).

**Files modified:** `crates/nono-cli/src/exec_identity_windows.rs` (helper `authenticode_chain_walk_error`). **Commit:** `70593110`.

### D-AUDC-03: Fixture switched from notepad.exe to explorer.exe (catalog-vs-embedded surprise)

The user's prompt directed: "Use `C:\Windows\System32\notepad.exe` as the primary fixture; if the plan suggests `powershell.exe` as an alternate due to catalog-vs-embedded signing concerns, prefer `notepad.exe` first and fall back only if testing reveals catalog-signing breaks the chain-walker."

Testing revealed catalog-signing breaks the chain-walker for `notepad.exe` on this Windows 11 host (probe results above). **Fallback to `explorer.exe` was triggered** — it is reliably embedded-signed across Windows 10/11 SKUs. This is exactly the contingency the plan + user prompt anticipated.

**Files modified:** `crates/nono-cli/src/exec_identity_windows.rs` (FIXTURE_PATH constant). **Commit:** `5a4a8443`.

### D-AUDC-04 (Rule 1 - Bug fix during implementation): CertGetNameStringW pvTypePara

The plan's Task 3 Step 2 (lines 519-527) showed `CertGetNameStringW(leaf_cert, CERT_NAME_RDN_TYPE, 0, std::ptr::null_mut(), buf_ptr, buf_len)` with NULL `pvTypePara`. Initial implementation followed the plan literally and the new tests failed with subjects in the form `"US, Washington, Redmond, Microsoft Corporation, ..."` (no `CN=` / `O=` / `C=` keys) — the must-haves substring check `signer_subject.to_lowercase().contains("cn=")` failed.

**Investigation:** Microsoft's `CertGetNameStringW` documentation specifies that for `CERT_NAME_RDN_TYPE`, `pvTypePara` is treated as a `*const DWORD` pointing to a `CERT_STRING_TYPE` flag controlling RDN serialization format. NULL produces value-only output; `CERT_X500_NAME_STR (= 3)` produces the keyed format we need.

**Fix:** Both `CertGetNameStringW` calls now thread `&CERT_X500_NAME_STR` as `pvTypePara`. All assertion tests pass. `windows-sys` 0.59 exposes `CERT_X500_NAME_STR` under `Win32::Security::Cryptography` (the existing feature gate), so no additional Cargo.toml change was needed.

**Files modified:** `crates/nono-cli/src/exec_identity_windows.rs` (parse_signer_subject body + import). **Commit:** `5a4a8443`.

## Catalog-signed-binary handling

Detailed probe-and-fallback story above (see "Fixture binary decision"). Summary: of 16 probed Windows-shipped binaries, 5 are catalog-signed (notepad.exe, cmd.exe, powershell.exe, mmc.exe, OpenSSH/ssh.exe), 9 are embedded-signed (explorer.exe, taskmgr.exe, dllhost.exe, svchost.exe, wuauclt.exe, wermgr.exe, MsMpEng.exe, MpCmdRun.exe, curl.exe, tar.exe). The `FIXTURE_PATH` constant doc-comment in `exec_identity_windows.rs` documents this distinction and lists the embedded-signed fallback candidates so future SKU regressions can switch fixtures without a probe.

The test pair includes a graceful skip at the top (`if !path.exists() { return; }`) so a Windows SKU lacking `explorer.exe` (e.g., Nano Server) silently passes without spurious failures.

## Behavior change note (REQ-AUDC-03 fail-closed)

**Pre-Phase-28 behavior:** Callers seeing `AuthenticodeStatus::Valid { signer_subject: "<unknown>", thumbprint: "" }` on `WinVerifyTrust=Valid` whenever the chain walkers were unreachable.

**Post-Phase-28 behavior:** Callers see EITHER:
- `AuthenticodeStatus::Valid { signer_subject: <real RDN>, thumbprint: <40-char hex> }` (success path), OR
- `Err(NonoError::SandboxInit("authenticode chain-walk failed (REQ-AUDC-03 fail-closed): ..."))` on chain-walk failure when `WinVerifyTrust` returned 0.

**This is intentional** per REQ-AUDC-03 acceptance #2. Users currently seeing `<unknown>` on `Valid` signatures pre-Phase-28 will see `NonoError::SandboxInit` errors post-Phase-28. Operators relying on the `<unknown>` sentinel as a "soft warning" must update their handling — chain-walk failure on a `Valid` signature is now a structural inconsistency that fails closed (T-28-02 mitigation: prevents attacker-stripped leaf cert from disappearing into the audit ledger as "looked fine").

## Cross-platform parity confirmation

- `cargo build --workspace` exits 0 on Windows host (Windows 11). The `cfg(target_os = "windows")`-gated module compiles cleanly with the new feature flags + chain-walker code.
- Linux/macOS targets: the entire `exec_identity_windows.rs` module compiles to nothing on non-Windows targets via the `#![cfg(target_os = "windows")]` gate at line 47. The new `Win32_Security_Cryptography_Catalog` + `_Sip` features in `Cargo.toml` are inside the `[target.'cfg(target_os = "windows")'.dependencies]` block, so they are inert on non-Windows. **Cross-platform sanity check via `cargo check --target x86_64-unknown-linux-gnu` was not run** (cross-toolchain unavailable on this Windows host without `cross` Docker setup); D-21 invariance is enforced structurally by the existing `cfg(target_os = "windows")` gate which Phase 28 did not modify.

## Deferred Issues

- **Pre-existing clippy errors in `crates/nono/src/manifest.rs:103`** (`clippy::collapsible_match`): exist before Phase 28 began (verified by `git stash` + clippy run). They are in the `nono` crate, which Phase 28 must NOT modify (D-19 byte-identical preservation). Logged in `.planning/phases/28-authenticode-chain-walker-subject-extraction/deferred-items.md` for a future maintenance pass.
- **Tampered-cert-chain regression test** (REQ-AUDC-03 fail-closed coverage on a "Valid + chain-walk-fails" fixture): out of scope per plan (no programmable test fixture exists without FFI mocking). Code review of the two `?` operators in `query_authenticode_status` is the authoritative evidence.

## TDD Gate Compliance

This plan is `tdd: false` per frontmatter; no formal RED/GREEN/REFACTOR gating required. However, the implementation followed an empirical RED → GREEN cycle naturally:

1. RED: Initial test runs against `notepad.exe` produced `Unsigned` (catalog-signed surprise) — and after fixture swap, against `explorer.exe` produced subjects without `CN=` keys (CertGetNameStringW pvTypePara surprise).
2. GREEN: Fixture swap + `CERT_X500_NAME_STR` threading → all 6 unit tests pass.
3. REFACTOR: Removed the temporary `_probe_embedded_signed_candidates` test; tightened `<unknown>` doc-comment references to ≤ 1.

## Self-Check: PASSED

**Files claimed created/modified:**
- ✓ `crates/nono-cli/Cargo.toml` (modified) — `git log --oneline | grep 67ba4a99` confirms.
- ✓ `crates/nono-cli/src/exec_identity_windows.rs` (modified) — `git log --oneline | grep 70593110\|5a4a8443\|279c1b86` confirms 3 commits touched it.
- ✓ `crates/nono-cli/tests/exec_identity_windows.rs` (modified) — `git log --oneline | grep 279c1b86` confirms.
- ✓ `.planning/phases/28-authenticode-chain-walker-subject-extraction/deferred-items.md` (created) — Logged.
- ✓ `.planning/phases/28-authenticode-chain-walker-subject-extraction/28-01-SUMMARY.md` (this file) — Created.

**Commits claimed exist:**
- ✓ `67ba4a99` — `feat(28-01-T1): ...`
- ✓ `70593110` — `feat(28-01-T2-T4): ...`
- ✓ `5a4a8443` — `test(28-01-T5-T6): ...`
- ✓ `279c1b86` — `test(28-01-T7): ...`

**Invariants confirmed:**
- ✓ D-19 byte-identical: `git diff --stat HEAD~4 HEAD -- crates/nono/` returns 0 lines.
- ✓ D-21 Windows-invariance: all changes are inside `#![cfg(target_os = "windows")]`-gated module.
- ✓ Cargo.lock byte-identical: `git diff Cargo.lock | wc -l` returns 0.
- ✓ Test pass: 6/6 in-bin unit tests + 2/2 integration tests pass.
- ✓ All 12+ grep gates from `28-CONTEXT.md` and the plan's verification block pass.
