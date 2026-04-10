# Windows Gap Closure — Research

**Researched:** 2026-04-06
**Domain:** Windows platform parity — PTY, syscall tracing, proxy, WFP port filtering, trust workflow, session commands
**Confidence:** HIGH (source code read directly; no training-data speculation)

## Summary

The v1.0 Windows milestone delivered `nono run` with Job Objects + WFP enforcement, rollback, ps/stop, attach/detach over named pipes, and automated MSI signing. Seven feature areas remain structurally incomplete or intentionally deferred. This document assesses each gap: what blocks it today, what the implementation path looks like, and how complex it is.

The clearest finding: **`nono shell` is closer than the "intentionally unavailable" label implies** — `pty_proxy_windows.rs` already wraps `CreatePseudoConsole` and the supervisor already accepts a `PtyPair`. The real gap is wiring ConPTY resize events, enforcement validation, and the interactive terminal I/O loop. Proxy filtering and port-level WFP filtering are both unlocked by the WFP sublayer work already in place — they are incremental additions, not structural rewrites. `nono learn` requires either shipping Procmon or adopting ETW, which is the only truly new platform dependency.

**Primary recommendation:** Close gaps in this order: (1) port-level WFP filtering — lowest risk, highest value; (2) proxy filtering — re-uses existing proxy server, just needs Windows enforcement guard; (3) session log commands — trivially unblocked; (4) `nono shell`/`wrap` — ConPTY scaffold exists; (5) trust workflow — depends on file-open mediation not yet designed; (6) `nono learn` — longest lead time, most uncertain.

---

## Gap 1: `nono shell` — Interactive Shell Host

### Current state

`validate_preview_entry_point(WindowsPreviewEntryPoint::Shell, ...)` always returns `UnsupportedPlatform`. The CLI help says "intentionally unavailable."

However, `pty_proxy_windows.rs` already implements `open_pty()` using `CreatePseudoConsole` (ConPTY, available Windows 10 1809+). The supervisor's `execute_supervised` accepts `pty_pair: Option<pty_proxy::PtyPair>` on Windows. The scaffolding exists; it is just not activated for the Shell entry point.

### What is actually missing

1. **Terminal resize propagation** — `ClosePseudoConsole`/`ResizePseudoConsole` calls must be wired to `SIGWINCH`-equivalent Windows console resize events. On Unix this happens via `ioctl(TIOCSWINSZ)`. On Windows the equivalent is `ResizePseudoConsole(hpcon, newSize)` triggered by a `SetConsoleWindowInfo` or `ReadConsoleInput` event loop.
2. **Shell binary resolution** — `nono shell` launches `$SHELL` on Unix. On Windows there is no `$SHELL` env var; the default should be `cmd.exe` or `powershell.exe`. The CLI `--shell` flag will need a Windows-aware default.
3. **Enforcement validation** — `validate_preview_entry_point(Shell)` must be updated to allow execution when the sandbox policy is within the Windows-supported subset (directory grants, WFP blocking) rather than always failing.
4. **STARTUPINFOEX with ConPTY** — `CreateProcessW` must be called with `EXTENDED_STARTUPINFO_PRESENT` and a `STARTUPINFOEXW` that has the `HPCON` attribute set via `UpdateProcThreadAttribute`. The existing `spawn_windows_child` in `launch.rs` may need a ConPTY-aware code path.
5. **I/O proxy loop** — A thread must pump `output_read` (from ConPTY) to stdout, and stdin to `input_write`. The Windows `supervisor.rs` event loop currently routes I/O through the named-pipe data channel; that channel needs to become the ConPTY pipe, or a separate I/O relay thread is added.

### Technical path

- Remove the hard block in `validate_preview_entry_point(Shell)` (guarded by Windows-supported shape check).
- Add a ConPTY-aware branch in `spawn_windows_child` (pass `STARTUPINFOEXW` with `HPCON` attribute).
- Add I/O relay thread in `supervisor.rs` (stdout pump + stdin feed).
- Wire `ResizePseudoConsole` to a console resize watcher thread.
- Default `--shell` to `powershell.exe` on Windows when not set.

### Complexity: M

The pieces are mostly written. The work is wiring them together correctly and handling edge cases (resize, raw-mode stdin, Ctrl-C passthrough).

### Dependencies

None on other gaps. Can be done in isolation.

### Risk

- **Enforcement gap:** ConPTY does not automatically apply sandbox policy to the child shell process — the existing Job Object + WFP path handles that. Verify that `spawn_windows_child` correctly attaches the ConPTY process to the Job Object.
- **Minimum Windows version:** `CreatePseudoConsole` requires Windows 10 1809 (build 17763). Document this and fail closed on older builds. The existing `windows-sys` import already references `HPCON`, so the build requirement is already present.
- **Security boundary:** The ConPTY host (supervisor process) has an open write pipe into the child's console. This is the same model as Unix PTY; no new attack surface beyond what Unix already has.

---

## Gap 2: `nono wrap` — One-Way Apply Mode

### Current state

Same hard block as Shell: `validate_preview_entry_point(Wrap)` always returns `UnsupportedPlatform`.

### What is actually missing

`nono wrap` on Unix does `fork()`, applies the sandbox in the child via `restrict_self()`, then `exec`s the target program. The child is fully sandboxed. There is no supervisor loop; the CLI exits after `exec`.

On Windows, there is no `fork`/`exec` split. The Windows backend uses `CreateProcess` (suspended) + Job Object + optional WFP activation. This is equivalent to the Unix Monitor strategy, not Wrap. The semantic difference: on Unix Wrap applies once and the CLI process is replaced. On Windows the CLI must stay alive as the Job Object owner (or transfer ownership).

The implementation path is to:
1. Map `wrap` to the `Direct` execution strategy on Windows (same as `run` without supervisor features).
2. Update `validate_preview_entry_point(Wrap)` to allow non-interactive commands within the Windows-supported shape.
3. Document that Windows `wrap` does not `exec`-replace the CLI process (it stays alive as a Job Object owner) — this is a behavioral difference, not a security difference.

### Complexity: S

The sandbox enforcement path is identical to `nono run`. The only work is: remove the hard block, add the behavioral-difference note to the help text, and route `wrap` through `execute_direct` or `execute_supervised` as appropriate.

### Dependencies

None. If Gap 1 (ConPTY) is wanted for interactive wrap targets, that adds M complexity. For non-interactive targets wrap is independent.

### Risk: LOW

The security properties are equivalent to `nono run`. The behavioral difference (no `exec`-replace) is purely UX.

---

## Gap 3: `nono learn` — Syscall-Based Path Discovery

### Current state

`learn.rs` is `#[cfg(any(target_os = "linux", target_os = "macos"))]` throughout. Windows builds compile but `run_learn()` would route to an unimplemented stub (the CLI prompts and exits; there is no Windows tracing backend).

### What is actually missing

The Unix backends are external-process invocations:
- Linux: `strace -e trace=file,network -f <command>`
- macOS: `fs_usage -w -f filesys <pid>` + `nettop`

Windows has no built-in equivalent that can be invoked as a subprocess. The options are:

| Approach | Description | Rust crate | Notes |
|----------|-------------|------------|-------|
| **ETW (Event Tracing for Windows)** | Kernel-mode event provider; `Microsoft-Windows-Kernel-File` provider delivers file I/O events; `Microsoft-Windows-Kernel-Network` delivers TCP events | `ferrisetw` (GitHub: n4r1b/ferrisetw) | Requires admin for some providers; session setup is non-trivial |
| **Detours / API hook (user-mode)** | Inject a DLL that hooks `NtOpenFile`, `NtCreateFile`, `connect()` | none (would need FFI) | Antivirus false positives; DLL injection is an attack pattern |
| **Procmon via ETW** | Sysinternals Process Monitor uses ETW internally; `Procmon.exe /Quiet /BackingFile ...` can capture events and export to CSV | none — subprocess invocation only | Requires Procmon.exe in PATH or bundled; redistributable terms unclear |
| **`Dbghelp`/Debug Port** | Attach as a debugger, single-step NtCreateFile calls | none | Extraordinarily slow; incompatible with programs that detect debuggers |

**Recommended approach:** ETW via `ferrisetw`.

The `Microsoft-Windows-Kernel-File` provider (GUID `EDD08927-9CC4-4E65-B970-C2560FB5C289`) delivers `FileIo/Create`, `FileIo/Read`, `FileIo/Write` events with full path. The `Microsoft-Windows-Kernel-Network` provider delivers `TcpIp/Connect`, `TcpIp/Accept` events. These can be filtered by PID after spawning the child.

`ferrisetw` is a Rust crate that wraps the ETW Consumer and Provider APIs. It requires building a real-time ETW consumer session in the same process. The main limitation: some kernel providers require admin (`SeSystemProfilePrivilege`), which `nono learn` already warns about on macOS (`sudo`). Windows learn mode would carry the same requirement.

### Complexity: L

ETW session setup, event filtering by PID, path reconstruction from kernel events, and the `ferrisetw` integration represent ~500–800 lines of new platform-specific code. The output format (paths, access modes) must match what the Unix backends produce.

### Dependencies

None on other gaps. But requires admin privilege, which affects UX.

### Risk: MEDIUM

- ETW provider names/GUIDs are stable (documented in MSDN) but event field layouts can vary across Windows versions.
- `ferrisetw` is a community crate (last release 2023); audit required before adoption.
- Admin requirement is a UX regression vs. Linux (strace is non-root on modern kernels).

---

## Gap 4: Proxy Filtering / Credential Injection

### Current state

`classify_supervisor_support` always pushes `ProxyFiltering` to `unsupported` when `context.proxy_filtering` is true. `preview_runtime_status` adds `"proxy network restrictions"` to failure reasons when `NetworkMode::ProxyOnly`.

The proxy server itself (`crates/nono-proxy/`) is platform-agnostic TCP — `TcpListener::bind("127.0.0.1:0")`, tokio async. It compiles and runs on Windows.

The block is architectural, not a proxy-server issue: on Unix, ProxyOnly mode works because the sandbox (Landlock/Seatbelt) can block all outbound traffic except to `127.0.0.1:<port>`. On Windows with WFP, the equivalent is to add a WFP filter that allows TCP to `127.0.0.1:<proxy_port>` and blocks everything else. WFP already does this for the Blocked mode (blocks all outbound). ProxyOnly just needs a more specific filter: allow `127.0.0.1:<port>`, block everything else.

### What is actually missing

1. **WFP filter for ProxyOnly mode** — The `WfpRuntimeActivationRequest` struct sent over the named pipe to `nono-wfp-service` currently only encodes blocked/allow-all. It needs a `ProxyOnly { port: u16 }` variant. The service must translate this to a WFP permit filter for `127.0.0.1:<port>` before the block-all filter at lower weight.
2. **Remove the `classify_supervisor_support` block** — Once the WFP enforcement path supports ProxyOnly, remove `ProxyFiltering` from `unsupported`.
3. **ENV var injection** — The proxy's `HTTPS_PROXY`/`NONO_PROXY_TOKEN` env vars must be passed to the child. The Windows exec path already accepts `env_vars` in `ExecConfig` and passes them to `CreateProcess`. This is already wired.
4. **Credential store** — The proxy server loads credentials from the system keyring via `keyring` crate. This is platform-agnostic and works on Windows (uses Windows Credential Manager). No new work.

### Complexity: M

The proxy server is ready. The new work is: (a) extend `WfpRuntimeActivationRequest` with a ProxyOnly variant, (b) add the WFP allow-localhost-port filter in the service, (c) remove the supervisor support block, (d) add integration tests.

### Dependencies

Requires WFP service IPC (already in place from Phase 6). Independent of all other gaps.

### Risk: LOW-MEDIUM

WFP filter ordering must be correct: the per-SID localhost-permit filter must have higher weight than the block-all filter. This is the same pattern used for domain allowlists on Unix; the WFP equivalent is straightforward but must be tested for filter weight collisions.

---

## Gap 5: Port-Level Network Filtering

### Current state

`compile_network_policy` detects `tcp_connect_ports`, `tcp_bind_ports`, `localhost_ports` and pushes each to `unsupported`. The capabilities are parsed from CLI flags but rejected at launch.

WFP is already in place as the network enforcement backend. Port-level filtering is a new filter type, not a new backend.

### What is actually missing

Three variants, each mapping to WFP filter primitives:

| Capability | WFP Layer | Filter Condition |
|------------|-----------|-----------------|
| `PortConnectAllowlist` | `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` | `FWPM_CONDITION_IP_REMOTE_PORT == port` |
| `PortBindAllowlist` | `FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4/V6` | `FWPM_CONDITION_IP_LOCAL_PORT == port` |
| `LocalhostPortAllowlist` | `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` | `FWPM_CONDITION_IP_REMOTE_ADDRESS == 127.0.0.1 AND FWPM_CONDITION_IP_REMOTE_PORT == port` |

The WFP activation request must carry port lists. The service adds permit filters for each port before the block-all filter.

Implementation steps:
1. Extend `WfpRuntimeActivationRequest` with `port_connect_allowlist: Vec<u16>`, `port_bind_allowlist: Vec<u16>`, `localhost_port_allowlist: Vec<u16>`.
2. In `nono-wfp-service`, translate each port to a WFP `FWPM_FILTER0` with the appropriate layer and conditions.
3. Remove the `unsupported` entries from `compile_network_policy` once enforcement is available.

### Complexity: M

WFP filter construction for port conditions is documented and follows the same pattern as the existing SID-based filters. The main complexity is testing on real Windows with multiple port rules and verifying that the filter weight ordering produces the expected allow/deny behavior.

### Dependencies

Directly related to Gap 4 (both extend `WfpRuntimeActivationRequest`). Should be done in the same milestone as proxy filtering to avoid multiple IPC contract bumps.

### Risk: LOW

WFP port filtering is well-documented MSDN territory. The filter conditions used are standard `FWP_UINT16` match conditions.

---

## Gap 6: Trust Workflow / Runtime Capability Expansion

### Current state

Two distinct problems:

**A. `extensions_enabled()` / RuntimeCapabilityExpansion**

`caps.extensions_enabled()` triggers `UnsupportedPlatform` in `sandbox/windows.rs:apply()`. The `WindowsSupervisorDenyAllApprovalBackend` exists as a placeholder that denies all expansion requests.

On Unix, `extensions_enabled()` means the supervisor IPC loop (Unix socket) intercepts `NONO_REQUEST_CAPABILITY` signals from the child. The child sends a JSON message over the socket; the supervisor evaluates it, prompts the user via `TerminalApproval`, and either grants or denies. The granted capability is injected into the running Landlock/Seatbelt policy (where possible) or the next session.

On Windows, the supervisor already has a named-pipe control channel. The IPC transport exists. What is missing:
- A protocol message type for capability requests (the `nono::supervisor::SupervisorMessage` enum would need a `RequestCapability` variant routed from the child).
- A mechanism for the sandboxed child to emit the request (currently the child process has no way to communicate back to the supervisor except exit).
- `TerminalApproval` integration on the Windows supervisor loop.

**B. `RuntimeTrustInterception`**

`trust_intercept_windows.rs` documents the precise blocker: "Windows supervised child processes do not have an attached file-open mediation channel for runtime interception." On Unix, the supervisor intercepts `open()` calls via ptrace or seccomp-BPF + `SIGSYS` to mediate file access in real-time. No equivalent exists on Windows without a kernel-mode driver.

Pre-exec trust verification (scanning instruction files before launch) **already works on Windows**. Only runtime interception (blocking file opens as they happen) is unsupported.

### Technical path

**For RuntimeCapabilityExpansion (Medium complexity):**
1. Add `RequestCapability { request: CapabilityRequest }` to `SupervisorMessage`.
2. Provide a child-side SDK or environment variable mechanism for the agent to send capability requests (e.g., write a JSON message to a well-known named pipe the supervisor exposes).
3. Implement `TerminalApproval` routing in the Windows supervisor event loop.
4. Remove the `extensions_enabled()` hard block once the IPC path is functional.

**For RuntimeTrustInterception (XL complexity or skip):**
Real-time file-open interception on Windows requires one of:
- A kernel-mode minifilter driver (e.g., using the Windows Filter Manager, `FltMgr`). This is how endpoint security products implement file-open interception. Requires a signed kernel driver.
- User-mode API hooking (Detours-style). Unreliable and incompatible with security products.
- ETW + action (ETW is observe-only; you cannot block an operation from an ETW handler).

A signed kernel minifilter driver is out of scope for the near term. The pragmatic approach: accept that pre-exec trust verification is the Windows trust model and mark `RuntimeTrustInterception` as intentionally unsupported with a clear reason.

### Complexity

- RuntimeCapabilityExpansion: M (named-pipe IPC extension, no kernel work)
- RuntimeTrustInterception: XL (kernel driver) or intentionally deferred

### Dependencies

RuntimeCapabilityExpansion depends on the named-pipe supervisor IPC already in place. Independent of other gaps.

### Risk

- **RuntimeCapabilityExpansion:** The IPC message must be authenticated (the child could be compromised and send fraudulent capability requests). The existing named-pipe supervisor already has a session token. The child must present the session token with each capability request.
- **RuntimeTrustInterception:** If deferred, the product documentation must clearly state "pre-exec verification only on Windows."

---

## Gap 7: Session Log Commands (`nono logs`, `nono inspect`, `nono prune`)

### Current state

`session_commands_windows.rs` has:
```rust
pub fn run_logs(_args: &LogsArgs) -> Result<()> { unsupported("logs") }
pub fn run_inspect(_args: &InspectArgs) -> Result<()> { unsupported("inspect") }
pub fn run_prune(_args: &PruneArgs) -> Result<()> { unsupported("prune") }
```

The `unsupported()` helper returns `UnsupportedPlatform("Windows `{command}` is not available yet. Detached session management still depends on Unix-specific PTY and signal handling.")`.

This message is misleading. Looking at what these commands actually do on Unix:
- `logs`: reads the session log file from the session record path.
- `inspect`: prints structured session metadata from the session record.
- `prune`: removes exited session records and their log files.

None of these require PTY or Unix-specific anything. The session records are JSON files written to `~/.config/nono/sessions/`. The session log files are written by the supervisor. Both paths already work on Windows — `session::list_sessions()` and `session::load_session()` are called in `run_ps` and `run_stop` which **do** work on Windows.

### Technical path

Implement `run_logs`, `run_inspect`, `run_prune` in `session_commands_windows.rs` identically to the Unix implementations. The only dependency is the session record format, which is already shared.

The current blocker note is copy-paste from the PTY-dependent commands (`detach`, `attach` over Unix socket). It does not apply to logs/inspect/prune.

### Complexity: S

These are three ~20-line functions that read session records and log files. The Unix implementations in `session_commands.rs` can be copied with minimal adaptation.

### Dependencies: None

### Risk: NONE

Reading session records does not touch any security-sensitive surface.

---

## Dependency Map

```
Gap 7 (logs/inspect/prune)   — independent, S, do first
Gap 2 (wrap)                 — independent, S
Gap 5 (port filtering)       ─┐
Gap 4 (proxy filtering)       ├─ share WFP IPC contract extension, do together, M
Gap 1 (shell/ConPTY)         — independent, M
Gap 6a (runtime caps)        — independent, M, needs named-pipe IPC extension
Gap 3 (learn/ETW)            — independent, L, needs admin, requires ferrisetw evaluation
Gap 6b (trust interception)  — kernel driver, XL, intentionally defer
```

---

## Recommended Milestone Phasing

| Phase | Gaps | Size | Value |
|-------|------|------|-------|
| A | Gap 7 (logs/inspect/prune) + Gap 2 (wrap) | S+S | Unblocks everyday UX with trivial effort |
| B | Gap 5 (port filtering) + Gap 4 (proxy/credential injection) | M+M | High value for agent use cases; shares WFP contract bump |
| C | Gap 1 (shell/ConPTY) | M | Developer UX; ConPTY scaffold exists |
| D | Gap 6a (runtime capability expansion) | M | Advanced feature; safe with deny-all fallback |
| E | Gap 3 (learn/ETW) | L | Useful but requires admin; evaluate ferrisetw |
| Deferred | Gap 6b (runtime trust interception) | XL | Requires kernel driver; not near-term |

---

## Open Questions

1. **Port filtering + proxy in same WFP IPC bump?** Gap 4 and Gap 5 both extend `WfpRuntimeActivationRequest`. They should go into a single protocol version increment to avoid two IPC contract bumps.

2. **`ferrisetw` license and maintenance status** — The crate is Apache-2.0 but last released in 2023. Before adopting it for `nono learn`, evaluate whether the ETW bindings are sufficient or whether a direct `windows-sys` ETW implementation is preferable (more code, no external dependency).

3. **ConPTY minimum version enforcement** — `CreatePseudoConsole` is Windows 10 1809+. The codebase currently targets "Windows 10/11." Verify whether the installed base of Windows 10 < 1809 is a concern. If yes, add a runtime version check and a clear error message; do not silently fall back to a non-PTY path.

4. **Wrap behavioral difference documentation** — Unix `wrap` replaces the CLI process via `exec`. Windows `wrap` keeps the CLI alive as Job Object owner. This is a documentation and help-text concern, not a security concern, but users accustomed to Unix behavior should be warned.

---

## Sources

All findings are based on direct source code inspection of:
- `crates/nono/src/sandbox/windows.rs`
- `crates/nono-cli/src/pty_proxy_windows.rs`
- `crates/nono-cli/src/exec_strategy_windows/mod.rs`, `launch.rs`, `supervisor.rs`
- `crates/nono-cli/src/session_commands_windows.rs`
- `crates/nono-cli/src/trust_intercept_windows.rs`
- `crates/nono-cli/src/learn.rs`
- `crates/nono-proxy/src/server.rs`
- `.planning/quick/260406-ajy-assess-windows-functional-equivalence-to/260406-ajy-SUMMARY.md`

**Confidence:** HIGH — all claims are traceable to source code, not training data.

**Research date:** 2026-04-06
**Valid until:** 2026-07-06 (stable API territory; WFP and ConPTY APIs are stable Windows platform APIs)
