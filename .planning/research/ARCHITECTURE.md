# Architecture: Windows Gap Closure Integration

**Project:** nono — Windows v2.0 Gap Closure
**Researched:** 2026-04-06
**Confidence:** HIGH — all integration points derived from direct source inspection

---

## Overview

This document maps the five new feature areas (Phase A–E) onto the existing
nono module tree. For each feature it identifies: which files are modified vs
newly created, the exact call graph entry point, and the security implications
of each integration. A build-order summary closes the document.

The existing Windows execution surface is:

```
crates/nono-cli/src/
  exec_strategy_windows/
    mod.rs            — ExecConfig, ExecStrategy, execute_direct, execute_supervised
    launch.rs         — spawn_windows_child, ProcessContainment, Job Object lifecycle
    network.rs        — WFP/netsh backend selection, NetworkEnforcementGuard
    supervisor.rs     — WindowsSupervisorRuntime, named-pipe control/data pipes
    restricted_token.rs — Low-Integrity SID, session SID token
  session_commands_windows.rs  — run_ps, run_stop, run_detach, run_attach (DONE)
                                 run_logs, run_inspect, run_prune (STUBS)
  windows_wfp_contract.rs      — WfpRuntimeActivationRequest/Response, protocol v1
  session.rs                   — SessionRecord, session_log_path, list_sessions (cross-platform)
  learn.rs                     — #[cfg(any(linux,macos))] only; Windows branch absent
  pty_proxy_windows.rs         — Windows PtyPair shim (currently wraps ConPTY placeholders)

crates/nono/src/supervisor/
  types.rs     — SupervisorMessage, CapabilityRequest, ApprovalDecision
  socket.rs    — SupervisorSocket pair
  socket_windows.rs
```

The WFP back-end service (`nono-wfp-service`) is a separate installed Windows
service binary not present as a crate in `crates/`. The IPC contract between
nono-cli and that service is `WfpRuntimeActivationRequest` carried over a
named pipe, currently at protocol version 1.

---

## Phase A: Quick Wins — `nono wrap` and Session Log Commands

### What Changes

**Modified (existing files only — no new files needed):**

| File | Change |
|------|--------|
| `crates/nono-cli/src/session_commands_windows.rs` | Replace the three `unsupported()` stubs (`run_logs`, `run_inspect`, `run_prune`) with real implementations mirroring the Unix `session_commands.rs` logic. |
| `crates/nono-cli/src/app_runtime.rs` | Remove or relax the `UnsupportedPlatform` guard that blocks `nono wrap` on Windows. The guard currently prevents `execute_direct` from being reached in the Direct strategy path. |
| `crates/nono-cli/src/output.rs` | Add a Windows-specific note to the `wrap` help text explaining the process model difference: supervisor stays alive as Job Object owner; no exec-replace occurs. |

No new files are required. All primitives already exist:
- `session::list_sessions()`, `session::load_session()`, `session::session_log_path()`, and `session::session_events_path()` are cross-platform and have no Unix-specific imports.
- `execute_direct()` in `exec_strategy_windows/mod.rs` is fully implemented; only the entry-point guard at the `app_runtime` layer blocks it.

### Integration Points

`run_logs` on Windows:
`session_commands_windows::run_logs` → `session::load_session` → `session::session_events_path` → file I/O → stdout.

`run_inspect` on Windows:
`session_commands_windows::run_inspect` → `session::load_session` → JSON/text format to stdout.

`run_prune` on Windows:
`session_commands_windows::run_prune` → `session::list_sessions` → delete session JSON + log files.

`nono wrap` on Windows:
`app_runtime` → `execute_direct(config, session_id)` → `prepare_live_windows_launch` → `spawn_windows_child` → Job Object poll loop.

### Security Implications

- The three session commands read from `~/.config/nono/sessions/` and must reject calls originating from inside a sandbox. Port `reject_if_sandboxed()` (checks `NONO_CAP_FILE` env var) from `session_commands.rs` to the Windows file. Without this check, a sandboxed agent running `nono prune` could delete session state for other running supervisors.
- `nono wrap` on Windows keeps the CLI alive as the Job Object owner. When the CLI exits, all child processes in the Job Object are killed via `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. This is a structural guarantee equivalent to the Unix model — not weaker.

### Windows Build Requirement

Windows 10 v1607+ (Job Objects with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` available since Windows 8). No new minimum version introduced.

---

## Phase B: ConPTY Shell — `nono shell` on Windows

### What Changes

**Modified:**

| File | Change |
|------|--------|
| `crates/nono-cli/src/exec_strategy_windows/launch.rs` | Add a ConPTY-aware branch to `spawn_windows_child`. When `pty.is_some()` on Windows the current code wires PTY handles into `STARTUPINFOW`. This must be replaced with `STARTUPINFOEXW` + `InitializeProcThreadAttributeList` + `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` for a ConPTY child. |
| `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` | Extend `WindowsSupervisorRuntime` to hold a ConPTY handle (`HPCON`). Wire `ResizePseudoConsole` into a console-resize watcher thread. Ensure `HPCON` is closed only after the child process has exited. |
| `crates/nono-cli/src/app_runtime.rs` | Remove or relax the `validate_preview_entry_point(Shell)` guard that currently rejects `nono shell` on Windows. Gate on a runtime Windows build version check (see below). |

**New files:**

| File | Purpose |
|------|---------|
| `crates/nono-cli/src/exec_strategy_windows/conpty.rs` | `ConPtyHost` struct: wraps `CreatePseudoConsole`, `ResizePseudoConsole`, `ClosePseudoConsole`. Manages the anonymous pipe pair that bridges ConPTY to the supervisor I/O relay. RAII drop closes `HPCON`. Returns a `PtyPair` compatible with the existing `pty_output_read`/`pty_input_write` fields consulted by `supervisor.rs`. |

`pty_proxy_windows.rs` currently provides a `PtyPair` shim with `output_read` and `input_write` handle fields. The `ConPtyHost` fills these fields via `CreatePipe` pairs connected to the ConPTY; the rest of the supervisor I/O relay (`start_logging`, `start_data_pipe_server`) continues unchanged.

### Call Graph

```
app_runtime::run_shell (Windows)
  └─ execution_runtime::run_supervised (Windows path)
       └─ conpty::ConPtyHost::create(cols, rows)   [NEW]
            ├─ CreatePseudoConsole(...)
            └─ returns PtyPair { output_read, input_write, hpcon }
       └─ execute_supervised(config, supervisor, pty_pair=Some(..), ...)
            └─ WindowsSupervisorRuntime::initialize(supervisor, pty=Some(..))
                 ├─ start_logging()          — reads ConPTY output pipe, writes to log + data pipe
                 ├─ start_data_pipe_server() — relay to named data pipe for attach clients
                 └─ start_resize_watcher()   [NEW — calls ResizePseudoConsole]
            └─ spawn_windows_child(..., pty=Some(..))   [MODIFIED]
                 └─ CreateProcessW with STARTUPINFOEXW + PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
                 └─ apply_process_handle_to_containment (Job Object)  [unchanged]
                 └─ ResumeThread [unchanged]
```

### Security Implications

- `CreatePseudoConsole` is only available on Windows 10 build 17763 (1809) and later. A runtime `RtlGetVersion` check must be performed before any ConPTY call. If the build is older the command must return `NonoError::UnsupportedPlatform` with a clear minimum-version message — no silent fallback to a non-PTY path.
- The ConPTY child process must still be assigned to the Job Object (via `apply_process_handle_to_containment`) before `ResumeThread`. The ConPTY spawning path does not bypass this requirement.
- `HPCON` must be closed only after the child process has exited. Closing it prematurely terminates all processes whose console is attached to the ConPTY. The RAII `ConPtyHost` drop must be sequenced after `WaitForSingleObject` on the child process handle.
- WFP enforcement applies to the ConPTY-hosted child via the same SID/Job Object path as non-ConPTY children — no special handling required.

### Windows Build Requirement

Minimum: Windows 10 build 17763 (version 1809). `CreatePseudoConsole` and `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` are not present in earlier builds. `windows-sys` exposes these under `Win32::System::Console`. A runtime version check via `RtlGetVersion` (ntdll) must gate entry before any ConPTY API call.

---

## Phase C: WFP Port-Level and Proxy Filtering

### What Changes

**Modified:**

| File | Change |
|------|--------|
| `crates/nono-cli/src/windows_wfp_contract.rs` | Bump `WFP_RUNTIME_PROTOCOL_VERSION` from 1 to 2. Add fields to `WfpRuntimeActivationRequest`: `port_connect_allowlist: Vec<u16>`, `port_bind_allowlist: Vec<u16>`, `localhost_port_allowlist: Vec<u16>`, `proxy_port: Option<u16>`. v1 clients omitting new fields deserialize to empty vecs/None (fail-secure: no permit filters installed). |
| `crates/nono-cli/src/exec_strategy_windows/network.rs` | In `prepare_network_enforcement`, translate `CapabilitySet` port fields into the new `WfpRuntimeActivationRequest` fields before sending to the WFP service. |
| `crates/nono-cli/src/network_policy.rs` | In `compile_network_policy`, stop emitting `ProxyFiltering` as an unsupported shape. Wire `--allow-port`, `--proxy-only` CLI flags into the port allowlist fields. |
| `crates/nono-cli/src/exec_strategy_windows/mod.rs` | Verify that `ExecConfig.env_vars` already carries `HTTPS_PROXY`/`NONO_PROXY_TOKEN` from `proxy_runtime`; confirm these propagate through `build_child_env` (they do — injected via `config.env_vars`). |
| `nono-wfp-service` (external binary) | Deserialize extended request fields. Add WFP filter construction: per-port `FWPM_FILTER0` permit entries at weight higher than block-all. For proxy, add a `127.0.0.1:<proxy_port>` permit filter before block-all. |

**No new CLI-side files.** All new logic lives in the WFP service or extends existing structs.

### Integration Points

```
CLI: nono run --allow-port 8080
  └─ network_policy::compile_network_policy
       └─ WfpRuntimeActivationRequest {
              protocol_version: 2,
              port_connect_allowlist: [8080],
              proxy_port: None, ... }
            └─ named pipe → nono-wfp-service
                 └─ FwpmFilterAdd0(permit TCP connect to port 8080,
                                   weight > block-all filter weight)

CLI: nono run --proxy-only
  └─ proxy_runtime::start_proxy → proxy_port (e.g. 8877)
  └─ WfpRuntimeActivationRequest {
         protocol_version: 2,
         proxy_port: Some(8877),
         network_mode: "block", ... }
       └─ named pipe → nono-wfp-service
            └─ FwpmFilterAdd0(permit 127.0.0.1:8877, weight > block-all)
            └─ FwpmFilterAdd0(block all other outbound TCP)
  └─ ExecConfig.env_vars already includes
         ("HTTPS_PROXY", "http://127.0.0.1:8877"),
         ("NONO_PROXY_TOKEN", "...")
```

### Security Implications

- **WFP filter weight ordering is a security invariant.** Permit filters (per-port, proxy) must have a higher numeric weight than the block-all filter. If installed at equal or lower weights, the block-all can win by undefined ordering and silently block the proxy route — the agent's network calls fail but appear to be network errors, not a sandbox denial.
- **Protocol version mismatch is a fail-secure event.** If the installed nono-wfp-service speaks protocol v1 and the CLI sends v2, the service deserializes with empty port lists — no permit filters are installed before the block-all rule. All outbound traffic is denied. This is fail-secure but breaks user workflows. The CLI must check `WfpRuntimeActivationResponse.protocol_version` and return a clear error if the service version is too old.
- **Proxy credential injection via `HTTPS_PROXY` is only as strong as WFP enforcement.** If WFP is not running (service stopped), the proxy env var is set but nothing prevents the child from bypassing it. The existing `probe_bfe_service_status()` check in `exec_strategy_windows/mod.rs` must be called before credential injection, and must treat a stopped BFE as a fatal error.

### Windows Build Requirement

No new minimum version beyond the existing WFP requirement (Windows 10). `FWPM_FILTER0` and related WFP APIs are available on all targeted Windows 10/11 builds.

---

## Phase D: ETW-Based Learn Command

### What Changes

**Modified:**

| File | Change |
|------|--------|
| `crates/nono-cli/src/learn.rs` | Add `#[cfg(target_os = "windows")]` dispatch block alongside the existing Linux/macOS blocks. Call `learn_etw::run_learn_windows`. The `LearnResult` struct and `NetworkConnectionSummary` are already cross-platform (no `#[cfg]` on the types themselves). |
| `crates/nono-cli/src/learn_runtime.rs` | Ensure the runtime dispatch reaches the Windows ETW implementation rather than returning `UnsupportedPlatform`. |

**New files:**

| File | Purpose |
|------|---------|
| `crates/nono-cli/src/learn_etw.rs` | ETW consumer session: start real-time session (`StartTraceW`), enable `Microsoft-Windows-Kernel-File` (GUID `EDD08927-9CC4-4E65-B970-C2560FB5C289`) and `Microsoft-Windows-Kernel-Network` providers, filter events by child PID at session-enable time (`EVENT_FILTER_DESCRIPTOR`), decode `FileIo/Create`, `FileIo/Read`, `FileIo/Write`, `TcpIp/Connect`, `TcpIp/Accept`, produce `LearnResult`. |

The ETW implementation has two mutually exclusive library options for the binding layer (see Open Questions in WINDOWS-V2-ROADMAP.md):
- `ferrisetw` crate: higher-level Rust API, Apache-2.0, last release 2023 (maintenance risk).
- `windows-sys` direct: more code, zero external dependency risk, guaranteed by the existing dependency already in `Cargo.toml`.

Both produce the same `LearnResult` from the same ETW event stream. The decision must be documented in the D-01 plan and recorded in the phase summary.

### Call Graph

```
nono learn <cmd>
  └─ learn_runtime::run_learn
       └─ [cfg(windows)] learn_etw::run_learn_windows(args)
            ├─ is_admin_process()      [already in exec_strategy_windows/mod.rs — reuse]
            │    └─ if false → NonoError::UnsupportedPlatform(
            │                     "nono learn on Windows requires administrator privileges")
            ├─ spawn child process (Command::new, not inside sandbox)
            ├─ StartTraceW(session_name, EVENT_TRACE_REAL_TIME_MODE)
            ├─ EnableTraceEx2(KernelFile GUID,
            │                 EVENT_FILTER_DESCRIPTOR { PID = child.id() })
            ├─ EnableTraceEx2(KernelNetwork GUID,
            │                 EVENT_FILTER_DESCRIPTOR { PID = child.id() })
            ├─ ProcessTrace → event callback → decode → LearnResult accumulator
            └─ StopTrace → return LearnResult
```

### Security Implications

- ETW requires admin privilege on Windows. `is_admin_process()` is already implemented in `exec_strategy_windows/mod.rs` and must be called before any ETW API. Without it, `StartTraceW` returns `ERROR_ACCESS_DENIED` with no user-visible context.
- ETW providers are observe-only. No event handler can block a file open. `nono learn` is for profile generation, not runtime enforcement — this is correct behavior and must be documented.
- **The PID filter must be applied at session-enable time, not in the callback.** Filtering only in the callback still receives all kernel-mode events for the entire system, causing excessive memory pressure and risking information disclosure from other processes' file access patterns. Use `EVENT_FILTER_DESCRIPTOR` with `EVENT_FILTER_TYPE_PID` in the `EnableTraceEx2` call.
- ETW event buffers are allocated in kernel memory. Failure to stop the trace session (`StopTrace`) on error or panic leaks a named session until reboot. Wrap the trace session handle in an RAII guard that calls `StopTrace` on drop.

### Windows Build Requirement

`EnableTraceEx2` with PID filtering is available on Windows 7 SP1+. All targeted Windows 10/11 builds include this. The `Microsoft-Windows-Kernel-File` provider GUID event schema must be validated against Windows 10 1809+ (the D-03 plan flags this explicitly).

---

## Phase E: Runtime Capability Expansion (Stretch)

### What Changes

**Modified:**

| File | Change |
|------|--------|
| `crates/nono/src/supervisor/types.rs` | Add `RequestCapability { request: CapabilityRequest, session_token: String }` variant to `SupervisorMessage`. This is a core library change shared with Unix platforms — must be serialization-compatible (add as a new enum variant; existing deserializers receiving unknown variants should skip gracefully). |
| `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` | Extend the control pipe message handler in `start_control_pipe_server` to deserialize `RequestCapability` messages and route them through `TerminalApproval`. Add session token validation before routing; deny immediately on missing or invalid token. |
| `crates/nono-cli/src/exec_strategy_windows/mod.rs` | Replace `WindowsSupervisorDenyAllApprovalBackend` with a real `TerminalApprovalBackend` when capability expansion is enabled. The deny-all backend must remain the default when the feature is disabled. |
| `crates/nono/src/sandbox/windows.rs` | Remove the `extensions_enabled()` hard block that currently rejects capability expansion on Windows regardless of configuration. |

**New files:**

| File | Purpose |
|------|---------|
| `crates/nono/src/supervisor/sdk_windows.rs` | Child-side SDK: reads `NONO_SUPERVISOR_PIPE` env var, connects to the supervisor named pipe, writes a length-prefixed JSON `SupervisorMessage::RequestCapability`. Thin; no tokio required. |

### Call Graph

```
Sandboxed child (Low Integrity process):
  writes SupervisorMessage::RequestCapability { session_token, request } to named pipe
    └─ supervisor.rs: start_control_pipe_server background thread
         ├─ session_token validation
         │    ├─ invalid token → SupervisorResponse::Decision { Denied, reason: "invalid token" }
         │    └─ duplicate request_id → SupervisorResponse::Decision { Denied, reason: "replay" }
         └─ TerminalApproval::prompt_user(request)
              ├─ user approves → SupervisorResponse::Decision { Granted, grant: Some(..) }
              └─ user denies  → SupervisorResponse::Decision { Denied }
```

The existing control pipe already handles `Terminate` and `Detach`. `RequestCapability` extends the same pipe without a new transport — the length-prefixed JSON framing already supports arbitrary `SupervisorMessage` variants.

### Security Implications

- **Session token is the only authentication mechanism.** The token must be generated at session start (using a cryptographically random source, e.g. `rand::rng().fill`), injected into the child env (`NONO_SESSION_TOKEN`), and never written to tracing output at any log level. If logged, any process that can read logs can impersonate the child.
- **Replay protection on `request_id`.** The existing `seen_request_ids: HashSet<String>` logic in `handle_windows_supervisor_message` already rejects duplicate request IDs. This must remain active for `RequestCapability` messages.
- **`WindowsSupervisorDenyAllApprovalBackend` must remain the default** when this feature is disabled or when the session was started without extension support. The fail-secure invariant holds regardless of whether the child sends capability requests.
- **Named pipe SDDL and Low Integrity access.** The current control pipe SDDL is `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)` — full access for SYSTEM, Built-in Administrators, and Owner. The child process runs at Low Integrity level; it may not be able to connect to a pipe that lacks a Low-Integrity write ACE. Verify that `CreateProcessAsUserW` with a Low-Integrity token can still write to the control pipe. If not, add `(A;;GW;;;LW)` (write-only for Low Integrity label) — scoped to write-only to prevent the child from reading supervisor control data back out of the pipe.

### Windows Build Requirement

Named pipes with `PIPE_REJECT_REMOTE_CLIENTS` are available on Windows Vista+. Session token injection requires no new APIs. No new minimum version beyond Phase A.

---

## Component Boundaries Summary

```
crates/nono/src/
  supervisor/types.rs           — Modified (Phase E): add RequestCapability variant
  supervisor/sdk_windows.rs     — NEW (Phase E): child-side capability request SDK
  sandbox/windows.rs            — Modified (Phase E): remove extensions_enabled() block

crates/nono-cli/src/
  session_commands_windows.rs   — Modified (Phase A): implement run_logs/inspect/prune stubs
  learn.rs                      — Modified (Phase D): add #[cfg(windows)] dispatch
  learn_etw.rs                  — NEW (Phase D): ETW consumer session
  app_runtime.rs                — Modified (Phase A, B): remove wrap/shell entry-point guards
  network_policy.rs             — Modified (Phase C): emit port allowlist fields
  windows_wfp_contract.rs       — Modified (Phase C): bump protocol version, add fields
  exec_strategy_windows/
    mod.rs                      — Modified (Phase C, E): port wiring, capability backend swap
    launch.rs                   — Modified (Phase B): ConPTY STARTUPINFOEXW branch
    supervisor.rs               — Modified (Phase B, E): ConPTY resize, RequestCapability routing
    network.rs                  — Modified (Phase C): translate port fields into WFP request
    conpty.rs                   — NEW (Phase B): ConPtyHost RAII wrapper

nono-wfp-service (external)     — Modified (Phase C): port/proxy WFP filter construction
```

---

## Build Order and Dependencies

```
Phase A (wrap + session logs)     — no deps, start immediately
Phase C (WFP port + proxy)        — no deps, parallel with A
Phase D (ETW learn)               — no deps, parallel with A and C
Phase B (ConPTY shell)            — depends on Phase A (entry-point guard pattern validated first)
Phase E (runtime caps, stretch)   — independent of A–D
```

**Phase A before Phase B is a soft dependency.** Phase A validates the entry-point guard removal pattern (`validate_preview_entry_point`, `UnsupportedPlatform` blocks in `app_runtime.rs`) before Phase B layers ConPTY complexity on top of the same code path. They can be parallelized with explicit coordination, but sequential reduces risk.

**Phase C must coordinate a single IPC version bump.** Phase C-01 (protocol bump in `windows_wfp_contract.rs`) must be merged before C-02 (proxy) and C-03 (port). The nono-wfp-service and `windows_wfp_contract.rs` must be updated atomically — they cannot be at different protocol versions in a deployed build.

**Phase D is fully independent.** It only touches `learn.rs`, `learn_etw.rs`, and `learn_runtime.rs`. It can be worked in any order relative to A–C and E.

**Phase E is independent** but its IPC changes to `crates/nono/src/supervisor/types.rs` touch the core library shared with Unix platforms. The new `SupervisorMessage::RequestCapability` variant must be serialization-compatible with existing Unix consumers. Ensure serde `#[serde(other)]` or an equivalent unknown-variant skip is in place on the `SupervisorMessage` enum before merging the types change.

---

## Security-Critical Integration Points (Summary Table)

| Integration Point | Phase | Risk | Mitigation |
|-------------------|-------|------|------------|
| `run_prune` without sandbox check | A | Sandboxed agent deletes other sessions | Port `reject_if_sandboxed()` check from Unix |
| `nono wrap` behavioral difference | A | Documentation gap (not security) | Help text must explain no exec-replace on Windows |
| ConPTY min-version check | B | Crash or wrong behavior on pre-1809 Windows 10 | Runtime `RtlGetVersion` gate; return `UnsupportedPlatform` |
| `HPCON` lifetime vs child lifetime | B | Premature close terminates ConPTY child | RAII `ConPtyHost` drop sequenced after child `WaitForSingleObject` |
| ConPTY child Job Object assignment | B | Child escapes containment | `apply_process_handle_to_containment` called before `ResumeThread` |
| WFP filter weight ordering | C | Block-all defeats permit filters silently | Permit weight > block weight; validated in integration tests |
| WFP protocol version mismatch | C | Missing permit filters (fail-secure, breaks proxy) | CLI checks response `protocol_version`; errors clearly on mismatch |
| BFE down with proxy credentials injected | C | Credentials set but WFP not enforcing | `probe_bfe_service_status()` must be fatal before credential injection |
| ETW PID filter placement | D | Info disclosure from other processes | `EVENT_FILTER_DESCRIPTOR` at enable time, not callback |
| ETW admin check | D | Silent `ERROR_ACCESS_DENIED` from `StartTraceW` | `is_admin_process()` before any ETW API call |
| ETW session handle leak on panic | D | Named session lingers until reboot | RAII wrapper calls `StopTrace` on drop |
| Session token in tracing output | E | Impersonation by log reader | Token must not appear in any log level |
| Low-Integrity child pipe write access | E | `RequestCapability` silently dropped | Verify SDDL allows Low-Integrity write; add `(A;;GW;;;LW)` if needed |
| Replay via duplicate `request_id` | E | Repeated capability grant | `seen_request_ids` HashSet must cover `RequestCapability` |
| `extensions_enabled()` hard block removal | E | Capability expansion active without feature flag | Gate on explicit `extensions_enabled()` check, not blanket removal |

---

## Sources

All findings are from direct source inspection of:
- `crates/nono-cli/src/exec_strategy_windows/mod.rs`
- `crates/nono-cli/src/exec_strategy_windows/launch.rs`
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs`
- `crates/nono-cli/src/exec_strategy_windows/network.rs`
- `crates/nono-cli/src/session_commands_windows.rs`
- `crates/nono-cli/src/session_commands.rs`
- `crates/nono-cli/src/windows_wfp_contract.rs`
- `crates/nono-cli/src/learn.rs`
- `crates/nono-cli/src/main.rs`
- `crates/nono/src/supervisor/types.rs`
- `.planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/WINDOWS-V2-ROADMAP.md`
- `.planning/PROJECT.md`
