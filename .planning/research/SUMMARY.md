# Project Research Summary

**Project:** nono — Windows Gap Closure (v2.0)
**Domain:** OS-enforced capability-based sandboxing — Windows CLI parity with Unix
**Researched:** 2026-04-06
**Confidence:** HIGH

## Executive Summary

nono v2.0 on Windows is an integration milestone, not a greenfield build. The v1.0 foundation (Job Objects, WFP block-all backend, named-pipe supervisor IPC, rollback, MSI packaging) is confirmed complete. Seven feature gaps remain between the Windows and Unix implementations; five are addressable in v2.0 using the existing `windows-sys 0.59` dependency surface. The work is almost entirely additive: removing `UnsupportedPlatform` guards, wiring scaffolded code that already exists, extending a struct with new fields, and adding one new ETW-consumer file. The single Cargo.toml change across all five phases is adding the `Win32_System_Diagnostics_Etw` feature flag to `windows-sys` for Phase D.

The recommended build order places quick-win stubs (Phase A) first to validate the entry-point guard removal pattern before Phase B layers ConPTY complexity on top. Phases C (WFP port/proxy) and D (ETW learn) are fully independent and can run in parallel with A. Phase E (runtime capability expansion) is a stretch goal backed by existing named-pipe IPC and can be picked up at any time. Gap 6b (kernel-level runtime file-open interception) is structurally deferred to v3.0; it requires a signed kernel minifilter driver and is out of scope for this milestone.

The primary implementation risks are concentrated in three areas: ConPTY process-attribute-list wiring (Phase B), WFP filter weight ordering (Phase C), and ETW NT-to-Win32 path translation (Phase D). Each has a well-understood prevention strategy documented in `PITFALLS.md`. The one open architectural decision — `ferrisetw` vs direct `windows-sys` ETW bindings — must be resolved at the start of Phase D and documented in the D-01 plan.

## Key Findings

### Recommended Stack

The existing `windows-sys 0.59` feature set covers every required API surface for Phases A, B, C, and E. No new crates are needed. For Phase D (ETW learn), adding the `Win32_System_Diagnostics_Etw` feature flag to the existing `windows-sys` entry in `nono-cli/Cargo.toml` is sufficient for a direct implementation. `ferrisetw` is a viable alternative (Apache-2.0, higher-level safe API) but carries maintenance risk from its 2023 last-release date. The decision must be made and documented in D-01 before writing any ETW code.

Minimum Windows build requirement is 17763 (Windows 10 1809) for both ConPTY (Phase B) and ETW kernel providers (Phase D). A shared `RtlGetVersion` helper checking `dwBuildNumber >= 17763` can gate both. All other phases run on any Windows 10 build.

**Stack additions (one line each):**
- `windows-sys 0.59` feature `Win32_System_Diagnostics_Etw` — ETW consumer API for `nono learn` (Phase D only; the sole Cargo.toml change across all phases)
- `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute` / `DeleteProcThreadAttributeList` / `ResizePseudoConsole` — new `use` imports within already-present `Win32_System_Threading` + `Win32_System_Console` feature flags; required for Phase B ConPTY wiring
- `RtlGetVersion` (ntdll) — runtime Windows build version check; already accessible via `Win32_System_SystemServices` (baseline present)

**What NOT to add:**
- `portable-pty` — conflicts with existing `pty_proxy_windows.rs` ConPTY implementation
- `windows-wfp` — conflicts with existing direct `windows-sys` WFP implementation in `nono-wfp-service`
- `tokio::net::windows::named_pipe` — would require rewriting the existing synchronous named-pipe supervisor
- `ferrisetw` — evaluate and decide in D-01; do not adopt without an explicit documented decision

### Expected Features

**Table stakes — users expect these; currently hard-error with `UnsupportedPlatform`:**
- `nono wrap` on Windows — Direct strategy via Job Object; supervisor stays alive as owner (no exec-replace); help text must document this behavioral difference from Unix
- `nono logs <session>` — shared session record format already compiles on Windows; stub is a one-liner replacement
- `nono inspect <session>` — same as logs; pure JSON file read from `~/.config/nono/sessions/`
- `nono prune` — session housekeeping; must port `reject_if_sandboxed()` check to prevent a sandboxed agent from deleting sibling session state
- `nono shell` on Windows — ConPTY scaffolding (`pty_proxy_windows.rs`) exists; needs wiring into supervised launch with `STARTUPINFOEXW`, resize, and Ctrl-C forwarding

**Differentiators — exceed stub state with meaningful capability improvements:**
- Port-level WFP filtering (`--allow-port`) — IPC contract fields (`tcp_connect_ports`, etc.) already exist but are rejected in `compile_network_policy`; Phase C removes rejections and wires the service-side filter builder
- Proxy credential injection (`--proxy-only`) — `HTTPS_PROXY` env injection + WFP loopback permit; `ProxyFiltering` currently in unsupported list in `classify_supervisor_support`
- `nono learn` via ETW — path discovery for profile building; closes the last developer-tooling gap; requires admin privilege and NT-to-Win32 path translation
- Runtime capability expansion (stretch) — named-pipe IPC channel already exists; adds `RequestCapability` message variant + session token auth + user approval prompt

**Explicit deferred (document in product docs):**
- Gap 6b: runtime file-open interception — requires a signed kernel minifilter driver; no user-mode workaround is acceptable; v3.0 scope

**Per-phase feature mapping:**
| Phase | Table Stakes | Differentiators |
|-------|-------------|-----------------|
| A | `nono wrap`, `logs`, `inspect`, `prune` | — |
| B | `nono shell` | — |
| C | — | Port-level filtering, proxy injection |
| D | — | `nono learn` |
| E (stretch) | — | Runtime capability expansion |

### Architecture Approach

All five phases operate within the existing `crates/nono-cli/src/exec_strategy_windows/` module tree and its adjacent files. No existing architectural boundaries are crossed; the library-vs-CLI split is preserved throughout. Phase A modifies stubs and removes guards in existing files (no new files). Phase B adds one new file (`conpty.rs`). Phase C extends an existing struct and the external `nono-wfp-service` binary. Phase D adds one new file (`learn_etw.rs`). Phase E adds one new file in the core library (`supervisor/sdk_windows.rs`) and extends the `SupervisorMessage` enum.

**Modified files by phase:**

| Phase | Modified | New |
|-------|----------|-----|
| A | `session_commands_windows.rs`, `app_runtime.rs`, `output.rs` | — |
| B | `launch.rs`, `supervisor.rs`, `app_runtime.rs` | `exec_strategy_windows/conpty.rs` |
| C | `windows_wfp_contract.rs`, `network.rs`, `network_policy.rs`, `exec_strategy_windows/mod.rs`, `nono-wfp-service` (external) | — |
| D | `learn.rs`, `learn_runtime.rs` | `learn_etw.rs` |
| E | `supervisor/types.rs`, `exec_strategy_windows/supervisor.rs`, `exec_strategy_windows/mod.rs`, `sandbox/windows.rs` | `supervisor/sdk_windows.rs` |

**Key architectural invariants that must not be broken:**
- `apply_process_handle_to_containment` (Job Object assignment) must be called before `ResumeThread` for all child spawn paths including ConPTY (Phase B)
- WFP filter weight ordering: permit filters must carry a higher `FWP_UINT64` weight than the block-all filter (Phase C)
- `SupervisorMessage::RequestCapability` added in Phase E must be serialization-compatible with existing Unix consumers; use `#[serde(other)]` or equivalent unknown-variant skip on the enum before merging
- `HPCON` must be closed only after child process exit; `ConPtyHost` RAII drop must be sequenced after `WaitForSingleObject` (Phase B)

### Critical Pitfalls

Top risks across all phases. Full analysis in `.planning/research/PITFALLS.md`.

1. **ConPTY `STARTUPINFOEXW` not used (Phase B-01, Critical)** — `CreatePseudoConsole` does not automatically wire to the child without `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` in `lpAttributeList`. Requires `InitializeProcThreadAttributeList` → `UpdateProcThreadAttribute` → `CREATE_EXTENDED_STARTUPINFO_PRESENT`. Missing any step silently falls back to parent console inheritance with no obvious error. Detection: `GetLastError()` returns `ERROR_INVALID_PARAMETER` (0x57) after `CreateProcessW`.

2. **WFP per-port permit weight below block-all (Phase C-03, Critical)** — `FWP_EMPTY` auto-weighting assigns lower weight to filters installed after block-all. Block-all fires first; allowlisted ports are silently blocked. Use explicit `FWP_UINT64` weights with permit > block-all. Integration test must attempt a real TCP connection, not just check filter presence.

3. **ETW NT-to-Win32 path reconstruction (Phase D-02, Critical)** — Kernel-File ETW events emit `\Device\HarddiskVolume3\...` paths. Learn output must emit Win32 `C:\...` paths to match Unix format. Build a volume-map table at trace startup using `GetLogicalDriveStringsW` + `QueryDosDeviceW`; translate on every event.

4. **ConPTY runtime build version check missing (Phase B-01, Critical)** — `windows-sys` links `CreatePseudoConsole` at compile time; calling it on a pre-1809 build causes an access violation before sandbox enforcement starts (fail-open window). Use `RtlGetVersion` to check `dwBuildNumber >= 17763` before any ConPTY call; return `UnsupportedPlatform` with a clear message. Never silently fall back to non-PTY.

5. **ETW admin check absent — silent empty output (Phase D-01, Critical)** — `StartTraceW` returns `ERROR_ACCESS_DENIED` (5) without admin. If unchecked, `nono learn` exits 0 with empty output; generated profiles allow nothing. Call `is_admin_process()` (already in `exec_strategy_windows/mod.rs`) before any ETW API; return a hard error, not a warning.

6. **Session token logged at trace level (Phase E, Critical)** — `NONO_SESSION_TOKEN` in any `debug!` or `trace!` call lets any log reader impersonate the sandboxed child. Token must never appear at any log level. Use constant-time comparison from `nono-proxy/src/token.rs`; never use `==`.

7. **Low-Integrity child cannot write to supervisor pipe (Phases A/B/E, Moderate)** — The supervisor named pipe SDDL lacks a Mandatory Label ACE for Low Integrity writes. Sandboxed children (Low Integrity) silently fail to connect. For any pipe the child must write to, add `S:(ML;;NW;;;LW)` to the SDDL. Verify in Phase A; ensure Phase E does not regress.

## Implications for Roadmap

The phase structure from `WINDOWS-V2-ROADMAP.md` is confirmed by research. The ordering is driven by code dependencies and risk management.

### Phase A: Quick Wins (Gap 2 + Gap 7)
**Rationale:** No new infrastructure; removes guards and implements stubs using already-complete shared session primitives. Validates the `validate_preview_entry_point` removal pattern that Phase B reuses. Zero-risk entry point for the milestone.
**Delivers:** `nono wrap`, `nono logs`, `nono inspect`, `nono prune` functional on Windows.
**Addresses:** WRAP-01, SESS-01 requirements.
**Avoids:** Must port `reject_if_sandboxed()` check to `run_prune` (Pitfall 15 surface); must add `nono wrap` behavioral-difference help text (Pitfall 12).

### Phase B: ConPTY Shell (Gap 1)
**Rationale:** Depends on Phase A to establish the entry-point guard removal pattern. Concentrated complexity in process-attribute-list wiring and I/O relay; doing this after A validates the same code path with a simpler change reduces risk of compounding errors.
**Delivers:** `nono shell` with ConPTY, Job Object + WFP enforcement, terminal resize, Ctrl-C forwarding.
**Addresses:** SHELL-01 requirement.
**Avoids:** Pitfalls 1 (STARTUPINFOEXW), 2 (runtime version check), 3 (conhost outside Job Object), 4 (Ctrl-C kills supervisor), 18 (handle close ordering).

### Phase C: WFP Port-Level + Proxy Filtering (Gap 4 + Gap 5)
**Rationale:** Independent of A and B; can run in parallel. Grouped to share a single IPC protocol version bump (v1 → v2). Two separate bumps would require two coordinated `nono-wfp-service` deployments.
**Delivers:** `--allow-port`, `--proxy-only` flags functional on Windows; `ProxyFiltering` removed from unsupported list.
**Addresses:** PORT-01, PROXY-01 requirements.
**Avoids:** Pitfalls 5 (permit weight ordering), 6 (proxy port weight ordering), 14 (version mismatch silent degradation — check `protocol_version` in response), 16 (orphan filters — covered by existing startup sweep if filter naming convention is followed).

### Phase D: ETW-Based Learn Command (Gap 3)
**Rationale:** Fully independent of all other phases. Largest single feature (L complexity). Sequenced after A–C for priority (interactive UX before dev tooling) but can be worked at any time.
**Delivers:** `nono learn` on Windows emitting LearnResult JSON compatible with Unix backends.
**Addresses:** LEARN-01 requirement.
**Avoids:** Pitfalls 7 (admin check), 8 (PID filter race — use `CREATE_SUSPENDED` + resume after trace is active), 9 (NT path reconstruction), 17 (ferrisetw maintenance — decide in D-01), 19 (kernel-network field schema version differences — use TDH runtime schema lookup, not hardcoded offsets).

### Phase E: Runtime Capability Expansion (Gap 6a, Stretch)
**Rationale:** Independent of all other phases; named-pipe IPC channel exists from v1.0. `WindowsSupervisorDenyAllApprovalBackend` provides a safe fail-closed default while this phase is absent or deferred.
**Delivers:** Sandboxed agents can request additional capabilities; supervisor prompts user for approval; session token authentication.
**Addresses:** TRUST-01 requirement.
**Avoids:** Pitfalls 10 (session token escalation — constant-time comparison, never log token), 11 (replay attack — `seen_request_ids` HashSet, same cap as Unix), 15 (Low-Integrity pipe write SDDL — `S:(ML;;NW;;;LW)`).

### Phase Ordering Rationale

- **A before B** is a required soft dependency: Phase A validates `app_runtime.rs` guard removal on a simple path before Phase B adds `STARTUPINFOEXW` complexity to the same files.
- **A, C, D in parallel** is safe: they touch disjoint files with no shared mutable state.
- **C internal ordering is strict:** C-01 (protocol version bump in both `windows_wfp_contract.rs` and `nono-wfp-service`) must be merged as an atomic unit before C-02 and C-03 proceed. Client and service must never be at different protocol versions in a deployed build.
- **E is truly independent** but touches `crates/nono/src/supervisor/types.rs` (core library, shared with Unix). Any `SupervisorMessage` enum change must maintain serde compatibility for existing Unix consumers before it merges to main.

### Research Flags

Phases needing deeper research during plan writing:
- **Phase D (D-01):** ETW library decision (`ferrisetw` vs `windows-sys` direct) must be resolved before any code is written. Check `ferrisetw` crates.io for current version and open issues at D-01 start. Also verify that the `Win32_System_Diagnostics_Etw` feature flag in `windows-sys 0.59` compiles cleanly before committing to the implementation approach.
- **Phase E (E-01):** Read `crates/nono/src/supervisor/socket_windows.rs` `create_named_pipe` SDDL before planning. If `S:(ML;;NW;;;LW)` is absent, E-01 must add it before implementing the child-side SDK; this changes the scope of the plan.

Phases with standard, well-documented patterns (skip research-phase):
- **Phase A:** Pure stub replacement using already-working cross-platform session primitives. No research needed.
- **Phase B:** ConPTY wiring is MSDN-documented with a deterministic step sequence. `pty_proxy_windows.rs` scaffold exists. `PITFALLS.md` has the complete prevention checklist.
- **Phase C:** WFP filter construction follows the existing v1.0 filter pattern; only the condition type changes (`FWP_UINT16` port vs SID-based). `PITFALLS.md` has the weight-ordering invariant.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All API surfaces verified via direct `Cargo.toml` and source inspection; only ETW feature flag is MEDIUM (verify compiles on Phase D start) |
| Features | HIGH | Derived from direct codebase inspection of stub status, guard locations, and IPC contract field state |
| Architecture | HIGH | All integration points traced to specific file and function; `nono-wfp-service` changes bounded and described at API level |
| Pitfalls | HIGH | Grounded in codebase source (SDDL contents, guard locations, IPC struct fields); Windows API behavior (ConPTY version requirement, ETW admin requirement, WFP weight ordering) is from stable MSDN-documented behavior |

**Overall confidence:** HIGH

### Gaps to Address

- **`ferrisetw` current version and maintenance status** — last confirmed release is 0.3.x from 2023. Check crates.io at D-01 start. If no release activity and open issues are unresolved, default to direct `windows-sys` ETW bindings. Document the decision in the D-01 plan.
- **`windows-sys 0.59` `Win32_System_Diagnostics_Etw` feature flag** — existence confirmed from crate structure knowledge (MEDIUM confidence). Run a build with the flag added before committing the D-01 plan.
- **Low-Integrity pipe SDDL** — `socket_windows.rs` `create_named_pipe` SDDL must be confirmed to include `S:(ML;;NW;;;LW)` before Phase E is planned. Resolve in E-01 codebase read.
- **`nono-wfp-service` deployment coordination** — the C-01 plan must specify how the updated service binary is built, packaged, and deployed atomically with the CLI change. This is an operational question but must be resolved in C-01 before any code is written.

## Sources

### Primary (HIGH confidence)
- `crates/nono-cli/Cargo.toml` — confirmed `windows-sys 0.59` feature list
- `crates/nono-cli/src/pty_proxy_windows.rs` — ConPTY scaffold state confirmed
- `crates/nono-cli/src/exec_strategy_windows/launch.rs` — `spawn_windows_child`, Job Object lifecycle
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` — named-pipe IPC pattern, control pipe message handler
- `crates/nono-cli/src/windows_wfp_contract.rs` — WFP IPC contract, port fields present but rejected in `compile_network_policy`
- `crates/nono-cli/src/session_commands_windows.rs` — stub locations confirmed
- `crates/nono/src/sandbox/windows.rs` — `WindowsPreviewEntryPoint` guard locations
- `crates/nono/src/supervisor/types.rs` — `SupervisorMessage` enum
- `.planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/WINDOWS-V2-ROADMAP.md` — gap coverage table, phase structure, open questions
- MSDN: `CreatePseudoConsole` minimum build 17763; ETW provider GUIDs; WFP filter weight ordering; `RtlGetVersion` vs `GetVersionEx`

### Secondary (MEDIUM confidence)
- `windows-sys 0.59` crate structure — `Win32_System_Diagnostics_Etw` feature existence (matches `windows` crate module tree; verify on Phase D start before committing plan)
- ETW `Microsoft-Windows-Kernel-File` field schema stability on Windows 10 1809+ (stable per knowledge cutoff August 2025; validate via TDH at runtime rather than hardcoding offsets)

### Tertiary (LOW confidence)
- `ferrisetw` version and maintenance status — last confirmed 0.3.x from 2023; crates.io check required at D-01

---
*Research completed: 2026-04-06*
*Ready for roadmap: yes*
