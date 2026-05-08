# Phase 31: Broker-Process Architecture (SHELL-01) - Context

**Gathered:** 2026-05-08
**Status:** Ready for planning
**Driver:** Phase 30 closed 2026-05-08 as failure-mode finding (`STATUS_DLL_INIT_FAILED 0xC0000142` localized to CSRSS console-subsystem ALPC denial during KernelBase.dll DllMain at Low-IL on the direct `CreateProcessAsUserW` path). Same-day broker-process PoC (`quick-260508-m99`) PASSED on Windows test box: Low-IL PowerShell child inherits Medium-IL broker's console, KernelBase short-circuits CSRSS attach, child survives DllMain and exhibits correct mandatory-label NO_WRITE_UP enforcement. RESEARCH.md Assumption A1 empirically validated. SHELL-01 promoted from `✘ v3.0 deferral` to `⚠ Phase 31 candidate`.

<domain>
## Phase Boundary

Lift the validated broker-process pattern (PoC `quick-260508-m99`, 2026-05-08) into a production `nono-shell-broker.exe` Win32 binary that `nono.exe` spawns instead of directly creating a Low-IL child via the cascade arm `WindowsTokenArm::LowIlPrimary`. The broker is a Medium-IL intermediary that owns nothing more than the steps proven by the PoC: hold the inherited console, duplicate its own token, lower the duplicate to Low-IL, and `CreateProcessAsUserW` the actual shell with `dwCreationFlags=0` so the Low-IL child inherits the broker's console (KernelBase skips CSRSS attach when console handle is inherited).

Phase delivers a working `nono shell --profile <name>` Windows path with mandatory-label NO_WRITE_UP write-deny intact AND ConPTY TUI rendering — OR closes as a failure-mode finding analogous to Phase 30 with SHELL-01 reverting to v3.0 deferral.

**In scope:**
- New `crates/nono-shell-broker/` workspace member implementing the Medium-IL→Low-IL spawn pattern from the PoC, hardened to production discipline (no `.unwrap()`, `// SAFETY:` annotations, `NonoError` propagation, `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` discipline).
- Lift `create_low_integrity_primary_token()` from `nono-cli/src/exec_strategy_windows/launch.rs` (currently `pub(super)`) into `crates/nono/src/sandbox/windows.rs` as `pub fn` so both `nono-cli` and `nono-shell-broker` consume one source of truth.
- `launch.rs` cascade-arm rework: replace `WindowsTokenArm::LowIlPrimary` with `WindowsTokenArm::BrokerLaunch` for the PTY+supervised path; rewrite `pty_token_gate_tests` (6/6) to assert `BrokerLaunch` dispatch; delete the orphaned `LowIlPrimary` arm + `low_integrity_primary_token_sets_low_il` test if no production path requires Low-IL spawn outside the broker (planner verifies before deletion lands).
- ConPTY ownership: `nono.exe` calls `CreatePseudoConsole`, spawns broker WITHOUT `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` (broker just inherits the console + ConPTY pipe handles via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`); broker spawns Low-IL child also WITHOUT the attribute. Mirrors PoC plain-inheritance shape verbatim. Sidesteps RESEARCH.md A2 (HPCON cross-process validity).
- Job Object containment: `nono.exe` calls `AssignProcessToJobObject(broker)` BEFORE broker spawns child; child inherits Job membership automatically; `JOB_OBJECT_LIMIT_*BREAKAWAY*` flags must remain unset; one assertion test verifies child PID is in Job Object after spawn.
- Broker IPC shape: argv-only launch config (shell path, shell args, cwd, inheritable handle hex values); env propagated via `SetEnvironmentVariable` on broker before spawn; CapabilitySet/Profile NOT passed to broker (labels applied supervisor-side per RESEARCH §3a).
- Broker location resolution: `std::env::current_exe()` + parent dir; fail-fast with `NonoError::BrokerNotFound` if `nono-shell-broker.exe` missing as sibling.
- Broker lifetime: broker calls `WaitForSingleObject` on child, exits with child's exit code; `nono.exe` monitors broker PID via existing `WindowsSupervisedChild` plumbing.
- Wave-0 harness fix: `Out-File` → `Set-Content` in the write-deny test (RESEARCH Open Q3 / `30-WAVE-2-PROCMON.md` false-PASS bug). Blocks Acceptance #7 verification.
- Field-test reproduction of Phase 30 acceptance #1–#6 + new #7 (corrected `Set-Content` write-deny) on the user's Windows test box.
- PROJECT.md SHELL-01 row update (`⚠ Phase 31 candidate` → `✔ validated v2.3 Phase 31`) and cookbook (`docs/cli/development/windows-poc-handoff.mdx`) security-envelope rewrite — both happen at Phase 31 close on the success path.
- Cross-compile + signed-binary release pipelines extended to ship `nono-shell-broker.exe` alongside `nono.exe`.

**Out of scope:**
- Audit-ledger emissions for broker spawn / child spawn / write-deny events (D-10 — deferred to v2.4 follow-up: "Wire shell-launch events into audit ledger for parity with AIPC capability_decision emissions").
- AppliedLabelsGuard Drop-ordering bug (Phase 30 D-09 — separate quick task `nono-labels-guard-leak`; Phase 31 field-test will see "label guard: skipping apply + revert" warnings on 9 leaked paths and treats them as expected).
- AIPC-grandchild verification as a phase acceptance gate (D-09 — smoke-tested informally at most; not blocking).
- CI matrix expansion (Windows 10 22H2 / Windows 11 23H2 / Server 2022 — D-14 deferred to v2.4 follow-up).
- AppContainer (option 6a, RESEARCH §7a — ~15-25d; v3.0 candidate).
- Kernel mini-filter driver for FS deny enforcement (option 6e, RESEARCH §8 — v3.0 territory).
- `nono shell --integrity <Untrusted|Low|Medium>` user-controlled IL (Phase 30 deferred — v2.4+ ergonomic improvement).
- `nono shell` on Linux/macOS (different mechanisms — Landlock/Seatbelt; separate work).
- Phase 30's `claude-code-hook-not-firing` debug session (separate concern; Phase 30 D-08).
- Pivoting to `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` in the broker's `CreateProcessAsUserW` call (D-01 alternative — would need a separate mini-PoC; explicitly NOT chosen).

**Acceptance:**
1. `.\nono.exe shell --profile claude-code --allow-cwd` on Windows 10/11 launches a sandboxed shell (no 0xC0000142, no silent exit) via the broker dispatch arm. Verified on the user's test box.
2. `claude` runs inside the sandboxed shell with full TUI rendering (alternate screen buffer, cursor positioning, raw-mode input) — Phase 30 D-05 carried forward.
3. From inside the sandboxed shell, `Set-Content -Path -Value` (or any direct write) to a path outside the grant set fails with "Access is denied" at OS level (mandatory-label NO_WRITE_UP enforcement, NOT just hook-level interception) — Phase 30 D-06 carried forward.
4. From inside the sandboxed shell, reads of granted paths (e.g. `~/.claude\claude.json`) still succeed — Phase 30 unchanged.
5. PROJECT.md SHELL-01 entry updated from `⚠ Phase 31 candidate` to `✔ validated v2.3 Phase 31` — Phase 30 #5 carried forward.
6. Cookbook (`docs/cli/development/windows-poc-handoff.mdx`) describes the security envelope honestly: which token shape (broker→Low-IL-child), what's enforced at OS level (mandatory-label NO_WRITE_UP), what relies on the Claude Code hook (defense-in-depth) — Phase 30 #6 carried forward.
7. Harness `Out-File` → `Set-Content` fix verified by passing the corrected write-deny test in the live broker shell — new for Phase 31.

**Failure mode (explicit):** if integration field-test fails on TUI rendering with Low-IL child surviving DllMain (sub-A2 failure), allocate ≤2 days of ProcMon localization. If unresolved by day 5 of phase work, halt phase, write a Phase 31 paused finding, replan: either (a) split into 31a [broker mechanism] + 31b [ConPTY-with-broker resolution] or (b) descope to pipe-stdio fallback (Phase 30 D-05 unlock required — user re-decides). On full timebox-failure with no viable path, SHELL-01 reverts to ✘ v3.0 deferral; cookbook reverts to Phase 30 final-state language; v2.3 closes without SHELL-01.

</domain>

<decisions>
## Implementation Decisions

### ConPTY ownership architecture
- **D-01:** `nono.exe` allocates HPCON via `CreatePseudoConsole`. Broker is spawned WITHOUT `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` — it just inherits the console + ConPTY pipe handles. Broker spawns the Low-IL child also WITHOUT the attribute. Mirrors the PoC's plain-inheritance shape verbatim. Sidesteps RESEARCH.md A2 (HPCON cross-process validity); the path that may re-trigger `ConClntInitialize` at Low-IL (`PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` in broker's `CreateProcessAsUserW`) is explicitly NOT used.
- **D-02:** `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` discipline on every `CreateProcess*` call across the chain. nono→broker spawn explicitly lists ONLY the inherited console + ConPTY handles; broker→child spawn lists ONLY the console handles. Capability pipe (Phase 11) and any other supervisor handles are NEVER inheritable past `nono.exe`. Adds ~30 LOC across `launch.rs` + broker but eliminates the capability-pipe handle-leak class entirely.
- **D-03:** Broker waits for child via `WaitForSingleObject`, then `ExitProcess(child_exit_code)`. `nono.exe` monitors broker PID via existing `WindowsSupervisedChild` plumbing — no new IPC. Adds one process layer to the supervision tree (nono→broker→child); broker is a thin shim. Existing `AssignProcessToJobObject` + capability-pipe lifecycle unchanged.
- **D-04:** `nono.exe` calls `AssignProcessToJobObject(broker)` BEFORE broker spawns child. Standard Win32 behavior: child inherits Job Object membership automatically. `JOBOBJECT_EXTENDED_LIMIT_INFORMATION.LimitFlags` must NOT include `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` or `JOB_OBJECT_LIMIT_BREAKAWAY_OK` — RESEARCH §4d. One assertion test verifies the child PID is in the Job Object after spawn.

### Broker binary placement + token-helper lift
- **D-05:** New workspace member `crates/nono-shell-broker/` with own `Cargo.toml` and `[[bin]]`. Releases ship `nono-shell-broker.exe` as a sibling of `nono.exe`. ~200-350 LOC `main.rs` per RESEARCH §3a estimate. Cross-compile + signed-binary release pipelines must add the new artifact (Linux/macOS broker stub builds compile but are not shipped — Windows-only by construction).
- **D-06:** `create_low_integrity_primary_token()` moves from `nono-cli/src/exec_strategy_windows/launch.rs` (`pub(super)`) to `crates/nono/src/sandbox/windows.rs` as `pub fn create_low_integrity_primary_token() -> nono::Result<HANDLE>`. Lives alongside `try_set_mandatory_label` and `low_integrity_label_and_mask`. Both `nono-cli` and `nono-shell-broker` depend on the `nono` crate. Library boundary preserved as long as the function stays parameterless and policy-free. ~50 LOC moved.
- **D-07:** `nono.exe` resolves broker path as `std::env::current_exe()` parent + `nono-shell-broker.exe` (or platform equivalent). Fail-fast with a new `NonoError::BrokerNotFound { path: PathBuf }` variant if missing. No env-var override surface (rejected — env-poisoning attack). Mirrors how the proxy is located today.
- **D-08:** Launch parameters passed to broker via argv only — flat command-line args (`--shell <path> --shell-arg <arg> ... --inherit-handle <hex> --cwd <path>`). Inheritable handles reach broker via OS-level handle inheritance (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` from D-02). Env propagated via `SetEnvironmentVariable` on broker before spawn. No JSON parsing surface in broker. Profile/CapabilitySet NOT passed (RESEARCH §3a — labels applied supervisor-side BEFORE broker is spawned).

### Phase 31 scope boundary
- **D-09:** Acceptance criteria = Phase 30's #1–#6 carried forward verbatim + new #7 (corrected `Set-Content` write-deny test passes in live broker shell). AIPC-grandchild verification (Phase 18 / AIPC-01 functioning under broker) is NOT a phase acceptance gate — smoke-tested informally at most.
- **D-10 [informational]:** No audit-ledger emissions in Phase 31. Broker spawn / Low-IL child creation logged via `tracing` (`info!`/`debug!`) only. AuditEventPayload extension for shell launches stays out of scope — would expand Phase 23's wire-shape and force a new RejectStage-equivalent design call. v2.4 follow-up: "Wire shell-launch events into audit ledger for parity with AIPC capability_decision emissions." [informational tag: scope-boundary deferral — no plan task implements this in Phase 31; tracked as v2.4 follow-up only.]
- **D-11 [informational]:** AppliedLabelsGuard Drop-ordering bug (Phase 30 D-09 — 9 leaked Low-IL labels observed on test box) stays as separate quick task `nono-labels-guard-leak`. Phase 31 is the broker lift; mixing in a Drop-lifecycle bug in `AppliedLabelsGuard` expands scope unrelated to the broker pattern. Phase 31 field-test treats label warnings as expected; not a Phase 31 failure indicator. [informational tag: scope-boundary deferral — Phase 31 field-test treats label warnings as expected; the fix lives in a separate quick task, not in any Phase 31 plan.]
- **D-12:** Phase 31 ships in v2.3. STATE.md milestone status flips back from `milestone_complete` to `in_flight` at phase start. v2.3 closes via `/gsd-complete-milestone v2.3` once Phase 31 + Phase 25 / 26 / 27 follow-ups land. PROJECT.md text already lists SHELL-01 (Phase 31, ~7 days) as remaining v2.3 work alongside REQ-RESL-NIX-01..03, REQ-PKGS-01, REQ-PKGS-04, REQ-AAH-01.

### Failure-mode response if A2 (sub-shape) fails
- **D-13:** Hard timebox + ProcMon at day 5. If integration field-test fails on TUI rendering with Low-IL child surviving DllMain, allocate ≤2 days of ProcMon localization. If unresolved by day 5 of phase work, halt phase, write a Phase 31 paused finding, replan: either (a) split into 31a [broker mechanism] + 31b [ConPTY-with-broker resolution] or (b) descope to pipe-stdio fallback (Phase 30 D-05 unlock required — user re-decides). No silent slip past the timebox.
- **D-14:** Single-box validation on the user's Windows test box. Match PoC validation discipline. Phase 31 ships when the user reproduces Acceptance #1–#7 on the same test box. CI matrix expansion (Windows 10 22H2 / Windows 11 23H2 / Server 2022) is a v2.4 follow-up. Aligns with how Phase 15 / Phase 30 / the broker PoC shipped.
- **D-15:** Replace `WindowsTokenArm::LowIlPrimary` with new `WindowsTokenArm::BrokerLaunch` variant for the PTY+supervised path. Delete the orphaned `LowIlPrimary` arm + `low_integrity_primary_token_sets_low_il` test once planner verifies no production path requires Low-IL spawn outside the broker (Direct/legacy paths). Rewrite `pty_token_gate_tests` (6/6) to assert `BrokerLaunch` dispatch instead of `LowIlPrimary`. If the planner finds a Direct path that still needs Low-IL spawn, re-evaluate D-15 — keep `LowIlPrimary` as a fallback arm and only rewrite the PTY-supervised tests.
- **D-16:** Rollback story on Phase 31 timebox-failure with no viable path: SHELL-01 reverts to `✘ v3.0 deferral`. Cookbook reverts to Phase 30 final-state language ("`nono run -- claude` (non-TUI) on Windows; `nono shell` on Linux/macOS for TUI"). PROJECT.md flips SHELL-01 from `⚠ Phase 31 candidate` back to `✘ deferred to v3.0` (kernel mini-filter territory). Phase 31 closes as failure-mode finding analogous to Phase 30. v2.3 closes WITHOUT SHELL-01.

### Claude's Discretion
- Wave structure: planner discretion. Natural shape from RESEARCH §5 effort table is Wave 0 = harness fix + Phase 30 token-arm code retirement; Wave 1 = `crates/nono-shell-broker/` scaffolding + token-helper library lift; Wave 2 = `launch.rs` `BrokerLaunch` cascade arm + handle-list discipline + Job Object wiring; Wave 3 = field-test + cookbook + SHELL-01 bookkeeping flip.
- Exact `WindowsTokenArm::BrokerLaunch` enum variant placement and matcher arm position in `select_windows_token_arm` — planner picks based on existing arm ordering in `launch.rs`.
- Whether to pre-emit the broker `--smoke` self-test mode that runs the PoC mechanism standalone for CI — could be added if planner sees value; not required for acceptance.
- Whether `crates/nono-shell-broker/` should include a `#[cfg(not(windows))]` stub `main()` that prints "Windows-only binary" (PoC pattern) or refuse to compile on non-Windows. Planner picks.
- Tracing/log routing inside the broker: whether broker emits structured tracing to its own stderr (which `nono.exe` could capture) or to a file. Planner picks based on existing `nono.exe` log-file routing.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### PoC validation (primary input — A1 empirically validated)
- `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/SUMMARY.md` — PoC field-test result (PASS), verbatim test-box output, diagnostic evidence table, architecture diagram of `outer PowerShell → poc-broker → Low-IL child`, and explicit "broker MUST be Medium-IL" guidance.
- `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/src/main.rs` — 196-line reference implementation. Production lift hardens this against `// SAFETY:` discipline (already done in commit `9282cd34`), no `.unwrap()`, `NonoError` propagation. Steps 1–8 of `main()` are the production sequence.
- `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/Cargo.toml` — windows-sys 0.59 feature list (`Win32_System_SystemServices`, `Win32_System_Threading`, `Win32_Security`, `Win32_Foundation`, `Win32_System_Console`). Production crate must match.
- `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/README.md` — user-runnable build/run/verify instructions; reference for the production smoke harness.

### Scoping research (consume verbatim)
- `.planning/quick/260508-lqh-scope-phase-31-broker-process-implementa/RESEARCH.md` — 370-line Phase 31 scoping document. Contains: §1 mechanism viability (A1, A2, MIC enforcement), §2 reference implementations (Microsoft canonical broker, Chromium broker/target, Microsoft Q&A 2022 — broker pattern user-confirmed), §3 implementation shape (broker crate location, `launch.rs` cascade-arm changes, capability pipe SDDL preservation, supervision model), §4 threat model (broker attack surface, handle-leak risk, Job Object containment), §5 effort estimate (7 days base / 7-9 days realistic), §6 PoC scope (now complete), §7 alternatives (AppContainer / pipe-stdio / Linux-only / multi-platform-honest demo), §8 decision matrix, Assumptions Log (A1 ✓ A2 ⚠ A3 ⚠ A4 ✓ A5 ⚠), Open Questions (Q1 PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE in broker — D-01 sidesteps; Q2 token-helper location — D-06 answers; Q3 harness `Out-File` fix — Wave-0 task).

### Phase 30 carry-forwards
- `.planning/phases/30-windows-nono-shell-architecture/30-CONTEXT.md` — locked decisions D-01..D-10. Phase 31 carries forward D-05 (TUI required), D-06 (OS-level write-deny required), D-08 (claude-code-hook-not-firing out of scope), D-09 (AppliedLabelsGuard leak out of scope), D-10 (SHELL-01 bookkeeping in scope). D-01..D-04 (Low-IL primary token + Wave 2 ProcMon) are SUPERSEDED by Phase 31's broker pattern but the Phase 30 ProcMon evidence is the failure-mode reference.
- `.planning/phases/30-windows-nono-shell-architecture/30-WAVE-2-PROCMON.md` — Phase 30 ProcMon investigation. Documents: (a) the CSRSS ALPC denial root cause (the failure mode Phase 31 bypasses), (b) the `Out-File` PowerShell invalid-syntax bug that causes the harness to always exit 42 (false PASS) — Phase 31 Wave-0 fix is `Set-Content -Path -Value`. RESEARCH Open Q3.
- `.planning/phases/30-windows-nono-shell-architecture/30-RESEARCH.md` §"Validation Architecture" — input to Phase 31 VALIDATION.md regeneration.
- `.planning/debug/resolved/nono-shell-status-dll-init-failed.md` — Phase 30 debug session, includes "Postscript: broker-pattern PoC validated A1 same-day (2026-05-08)". Reference for the failure→PoC narrative.

### Code under change
- `crates/nono-cli/src/exec_strategy_windows/launch.rs:1023-1077` — `create_low_integrity_primary_token`. Source for D-06 lift to `crates/nono/src/sandbox/windows.rs`.
- `crates/nono-cli/src/exec_strategy_windows/launch.rs:1114-1349` — `spawn_windows_child`. Token-arm cascade. D-15 replaces `WindowsTokenArm::LowIlPrimary` with `BrokerLaunch` for the PTY+supervised path. New cascade arm calls `CreateProcessW(broker.exe, args)` instead of `CreateProcessAsUserW(low_il_token, ...)`.
- `crates/nono-cli/src/exec_strategy_windows/launch.rs` — `select_windows_token_arm` helper. New `BrokerLaunch` arm dispatch logic.
- `crates/nono-cli/src/exec_strategy_windows/restricted_token.rs:34-121` — `create_restricted_token_with_sid`. Reference only (not modified). Comment block at lines 82-93 documents WRITE_RESTRICTED's actual semantics.
- `crates/nono-cli/src/supervised_runtime.rs:95-111` — `should_allocate_pty()` Windows arm. Phase 30 gate; unchanged by Phase 31.
- `crates/nono/src/sandbox/windows.rs:35-44, 56-73, 470-650` — Windows sandbox `apply()`, `try_set_mandatory_label`, mode→mask mapping. D-06 destination for `create_low_integrity_primary_token`. Mandatory-label NO_WRITE_UP enforcement Phase 31 verifies via Acceptance #3.
- `crates/nono/src/error.rs` — D-07 adds `NonoError::BrokerNotFound { path: PathBuf }` variant.
- `crates/nono-cli/src/pty_proxy/` — `pty_proxy::open_pty()` ConPTY allocation. D-01 keeps this unchanged (`nono.exe` continues to own HPCON; broker just inherits handles).
- Tests: `pty_token_gate_tests` (6/6 — Phase 30) and `low_integrity_primary_token_sets_low_il` (Phase 30) — D-15 rewrite/delete targets.

### Bookkeeping under change at phase close
- `.planning/PROJECT.md` — SHELL-01 row flip: `⚠ Phase 31 candidate` → `✔ validated v2.3 Phase 31` on success path; `⚠ Phase 31 candidate` → `✘ deferred to v3.0` on failure path (D-16).
- `.planning/STATE.md` — milestone status flips from `milestone_complete` back to `in_flight` at phase start (D-12); session continuity entries.
- `.planning/ROADMAP.md` — Phase 31 entry currently has placeholder Goal `[To be planned]` and `Requirements: TBD`. Plan-phase output updates these to the goal statement above + lists Phase 31 plans.

### Cookbook under update at phase close
- `docs/cli/development/windows-poc-handoff.mdx` — POC cookbook. Phase 30's commit `0c69bd4b` recommended `nono shell --profile claude-code` as the TUI host on Windows; current state (post-Phase 30 close) reverted that to "deferred to v3.0." Phase 31 close on success path flips it back to recommended with the broker-process security envelope description (Acceptance #6).

### External (Microsoft docs — researcher should pull as needed)
- Microsoft Learn: `SetTokenInformation` — https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-settokeninformation
- Microsoft MSDN: "Designing Applications to Run at a Low Integrity Level" — https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v=msdn.10) — canonical `CreateLowProcess` reference.
- Microsoft Learn Q&A: "CreatePseudoConsole with reduced integrity level" — https://learn.microsoft.com/en-us/answers/questions/1040676/createpseudoconsole-with-reduced-integrity-level — broker pattern user-confirmed.
- Microsoft: Mandatory Integrity Control overview (NO_WRITE_UP / NO_READ_UP rules) — for Acceptance #3 enforcement narrative in cookbook.
- Microsoft: `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` documentation — for D-02 implementation.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `create_low_integrity_primary_token()` at `crates/nono-cli/src/exec_strategy_windows/launch.rs:1023-1077` — PoC validated. D-06 lifts to `crates/nono/src/sandbox/windows.rs`. Drops integrity to Low via `WinLowLabelSid`. Uses `DuplicateTokenEx(SecurityAnonymous, TokenPrimary)` per Phase 30 CR-01 hygiene fix.
- `try_set_mandatory_label` and `low_integrity_label_and_mask` in `crates/nono/src/sandbox/windows.rs` — per-path Low-IL labels with mode-derived NO_WRITE_UP / NO_READ_UP masks. Acceptance #3 verifies these fire correctly when the subject is the broker's Low-IL child.
- `pty_proxy::open_pty()` at `crates/nono-cli/src/pty_proxy/` — ConPTY allocation. Unchanged by Phase 31 (D-01). `nono.exe` continues to own HPCON.
- `is_windows_detached_launch()` at `launch.rs:1402-1410` — gate helper for Phase 15 detached path. Pattern to mirror — Phase 31 adds a `pty_present_and_supervised` (or similar) gate for the new `BrokerLaunch` arm.
- `WindowsSupervisorRuntime::initialize` `start_control_pipe_server` (Phase 11 + commit `938887f` SDDL fix) — capability pipe. RESEARCH §3c: no SDDL changes needed because the Low-IL child only talks to `nono.exe` via ConPTY, not the capability pipe. Broker is Medium-IL and has no problem accessing the capability pipe (broker doesn't actually need to — D-08 keeps Profile out of broker).
- PoC binary `poc-broker/src/main.rs` — production reference for the 8-step sequence (`AllocConsole` + `OpenProcessToken` + `DuplicateTokenEx` + `CreateWellKnownSid(WinLowLabelSid)` + `SetTokenInformation(TokenIntegrityLevel)` + `CreateProcessAsUserW(dwCreationFlags=0)` + wait + cleanup).

### Established Patterns
- **Token-arm cascade** (`launch.rs:1140-1160`): existing 4-arm `if/else if` over `is_windows_detached_launch`, `config.session_sid`, `should_use_low_integrity_windows_launch`. D-15 inserts a 5th arm for `BrokerLaunch` and removes the `LowIlPrimary` arm (or downgrades it to fallback if Direct path needs it).
- **Phase 15 direction-b waiver documentation** (STATE.md key-decisions block + cookbook section + commit body) — Phase 31's security-envelope cookbook update (Acceptance #6) follows this template.
- **`AppliedLabelsGuard` RAII** (sandbox label apply + revert) — Phase 31 doesn't touch this; just verifies it still fires correctly under broker→Low-IL-child shape. Phase 30 D-09 leak is a separate concern.
- **`spawn_windows_child` config struct** — Phase 31's broker dispatch reuses the existing `LaunchPlan` / `PreparedSandbox` plumbing; broker just becomes the new launch target instead of `powershell.exe` directly.
- **PoC `// SAFETY:` discipline** — Phase 30 commit `9282cd34` annotated PoC unsafe blocks; production broker must match.

### Integration Points
- `exec_strategy_windows::execute_supervised` calls `spawn_windows_child(config, ..., pty=Some(pty_pair), ...)`. Token-arm selection happens inside `spawn_windows_child`. D-15 edit is fully contained in that function plus the new `BrokerLaunch` dispatch path.
- `WindowsSupervisorRuntime::initialize` starts the control pipe server BEFORE the token-cascade-edit point. Capability-pipe SDDL fix (`938887f`) admits Low-IL clients; broker is Medium-IL so no SDDL change needed (RESEARCH §3c).
- `WindowsSupervisedChild` plumbing — D-03 keeps this monitoring the broker PID instead of the shell PID directly. Need to verify exit-code propagation through broker→nono is byte-equivalent to current child→nono.
- Cross-compile pipeline: Cargo workspace `[workspace] members` currently lists `crates/nono`, `crates/nono-cli`, `crates/nono-proxy`, `bindings/c`. D-05 adds `crates/nono-shell-broker`. Release builds need a Windows-target step for the broker artifact; Linux/macOS builds need to handle the broker as a non-shipping `#[cfg(not(windows))]` stub or skip entirely.
- Signed-binary attestation pipeline (referenced in PROJECT.md AUDC-03 / Phase 22 work) — `nono-shell-broker.exe` needs to be signed with the same key as `nono.exe` for Authenticode chain-walker (Phase 28) verification. Planner must add the new artifact to the signing list.

</code_context>

<specifics>
## Specific Ideas

- The PoC binary at `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/src/main.rs` is the closest-to-correct starting point for Phase 31's broker `main.rs`. The 8-step sequence and Win32 import structure transfer verbatim. Production hardening adds: argv parsing (D-08), inheritable handle list resolution (D-02), error type plumbing (`NonoError` instead of `eprintln!` + `process::exit`), `// SAFETY:` annotations (already in PoC post-commit `9282cd34`).
- The user's test box has prior Low-IL labels leaked on 9 user-home paths (`prior_rid="0x1000"`) — Phase 30 D-09 territory. Phase 31 field-test will see "label guard: skipping apply + revert" warnings on those paths; this is expected (D-11) and not a Phase 31 failure indicator. The `nono-labels-guard-leak` quick task will clean these post-Phase 31.
- RESEARCH.md A2 (HPCON cross-process validity) is sidestepped by D-01 but if the planner discovers it actually matters for some sub-path (e.g., conhost handshake races), D-13 timebox + ProcMon + replan kicks in.
- RESEARCH.md effort estimate of 7 days base / 7-9 realistic was BEFORE D-15 token-arm cleanup, D-08 argv design, and D-07 broker location resolution were locked. These are within the estimate; no upward revision needed.
- Phase 30's `30-FIELD-SMOKE.md` is the harness reference. Phase 31 reuses it with the `Out-File` → `Set-Content` fix per RESEARCH Open Q3.

</specifics>

<deferred>
## Deferred Ideas

- **v2.4 follow-up: shell-launch audit-ledger emissions** — wire broker-spawn / child-spawn / write-deny events into the audit ledger for parity with Phase 23's AIPC `capability_decision` emissions. Out of scope for Phase 31 (D-10) because it would expand AuditEventPayload's wire-shape and force a new RejectStage-equivalent design call.
- **v2.4 follow-up: AppliedLabelsGuard Drop-ordering bug fix** — separate quick task with suggested slug `nono-labels-guard-leak`. 9 leaked Low-IL labels observed on user's test box from prior nono crashes. Phase 30 D-09 already deferred this; Phase 31 maintains the deferral (D-11).
- **v2.4 follow-up: CI matrix expansion** — Windows 10 22H2 / Windows 11 23H2 / Server 2022 GitHub Actions runs of the field-smoke harness (D-14). ~2d for harness automation + flakiness debugging.
- **v2.4 follow-up: AIPC-grandchild verification under broker** — smoke test that Phase 18 handle brokering still works for a Claude Code grandchild of the broker shell. Phase 31 doesn't gate on this (D-09); v2.4 deferred task adds an explicit harness.
- **v2.4 ergonomic: `nono shell --integrity <Untrusted|Low|Medium>`** — user-controlled IL once Phase 31 establishes Low-IL default works. Phase 30-deferred carry-forward.
- **v3.0: AppContainer-based isolation for `nono shell`** — strictly stronger than mandatory-label-only enforcement; available since Windows 8. Out of scope for Phase 31 because AppContainer requires app capability sets, capability-aware ACLs, and likely breaks legacy shell apps (cmd, PowerShell 5.1). RESEARCH §7a — 15-25 days.
- **v3.0: Kernel mini-filter driver for FS deny enforcement** — Phase 6b territory. Would unblock real read-deny on Windows. RESEARCH §8 — 30+ days.
- **v3.0: AppContainer profile for the Claude Code child specifically** — narrower scope variant of AppContainer.
- **`nono shell` Linux/macOS broker port** — different mechanisms (Landlock/Seatbelt). Out of scope; separate work if needed.
- **Phase 30 retained code retirement** — if D-15 finds the Direct path also needs `LowIlPrimary` and we keep the arm, a future task should document a clean retirement plan once Direct-path Low-IL spawn is deprecated.
- **Broker `--smoke` self-test mode** — broker could expose a `--smoke` arg that runs the PoC mechanism standalone for CI without launching a real shell. Could be added in Phase 31 if planner sees value (Claude's Discretion); not required for acceptance.

### Reviewed Todos (not folded)
None — no todos matched this phase's scope per `gsd-sdk query todo.match-phase`.

</deferred>

---

*Phase: 31-broker-process-architecture-shell-01*
*Context gathered: 2026-05-08*
