# Feature Landscape: Windows Gap Closure (v2.0)

**Domain:** OS-enforced sandboxing — Windows CLI parity with Unix
**Researched:** 2026-04-06
**Overall confidence:** HIGH (codebase direct inspection + Windows API domain knowledge)

---

## Context

This document replaces the v1.0 FEATURES.md (supervisor parity). The v1.0 foundation is
complete: Job Objects, WFP primary backend, named-pipe supervisor IPC, rollback, MSI
packaging. This file covers only the **seven gap-closure features** in v2.0.

The existing Windows enforcement stack that v2.0 features build on:

- `ExecStrategy::Supervised` (Monitor/Supervised) — already works on Windows
- `WfpRuntimeActivationRequest` over named pipe to `nono-wfp-service` — already in place
- `WindowsPreviewEntryPoint` guard in `sandbox/windows.rs` — currently blocks `Wrap` and `Shell`
- `session_commands_windows.rs` — `run_logs`, `run_inspect`, `run_prune` currently stub to `UnsupportedPlatform`
- `pty_proxy_windows.rs` — `open_pty()` / `PtyPair` scaffolded but not wired into shell command

---

## Table Stakes

Features users expect to be present because the Unix equivalents are documented and in the
`--help` output on Windows. Missing any of these means the Windows CLI feels broken.

| Feature | Why Expected | Complexity | Unix Equivalent |
|---------|--------------|------------|-----------------|
| **`nono wrap` on Windows** | Documented command; currently hard-errors with `UnsupportedPlatform`. Users who follow cross-platform docs hit an immediate brick wall. | S | `exec`-replace via Direct strategy |
| **`nono logs <session>`** | Already works on Unix; session record format is shared. The stub in `session_commands_windows.rs` is a one-liner fix. | S | Reads `~/.config/nono/sessions/<id>/events.ndjson` |
| **`nono inspect <session>`** | Same argument as `logs` — shared session record format. | S | Prints `SessionRecord` fields as text or JSON |
| **`nono prune`** | Session housekeeping. The `reject_if_sandboxed` guard is the only meaningful difference; the rest is pure file I/O. | S | Deletes stale exited-session directories |
| **`nono shell` on Windows** | The most visible gap. Users trying to get an interactive sandboxed shell get a hard no. ConPTY API has been stable since Windows 10 1809. | M | `openpty` + `fork`/`exec` into `$SHELL` |

### `nono wrap` — Behavioral Difference from Unix (CRITICAL to document)

On Unix, `nono wrap` calls `exec` to replace the nono process with the target command.
The nono PID disappears; the target command runs as if launched directly, just inside a
sandboxed environment.

On Windows, `exec`-replace is not available (`std::os::unix::process::CommandExt::exec`
has no Windows counterpart). The Direct strategy on Windows creates the child process,
assigns it to a Job Object, and then **blocks waiting for the child to exit**. The nono
process stays alive as the Job Object owner for the duration.

**Security equivalence:** This is not a security difference. The Job Object provides the
same process-tree containment as the Unix sandbox-then-exec model. The WFP filter enforces
network policy regardless of whether nono is still in process.

**User-visible difference:** On Unix, `$$` inside the child shell reports nono's PID (it
inherits it via exec). On Windows, the child has its own PID; nono's PID remains visible
in task manager. Shell scripts that test `$$` or parent PID will behave differently.

**Help text must say:** "On Windows, `nono wrap` keeps the nono process alive as Job
Object owner. Use `nono run` if you need background/detach semantics."

---

## Differentiators

Features that exceed simple parity and provide meaningful capability improvements over the
current Windows stub state.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Port-level WFP filtering** | Allows `--allow-port 8080` instead of binary block-all/allow-all network modes. The existing WFP IPC only carries `tcp_connect_ports`, `tcp_bind_ports`, `localhost_ports` fields but the service-side filter builder doesn't wire them yet. | M | Extends `WfpRuntimeActivationRequest`; requires adding `FWPM_FILTER0` permit entries before the block-all sublayer entry |
| **Proxy credential injection** | `HTTPS_PROXY` env injection + WFP permit for `127.0.0.1:<proxy_port>` lets agents use a local credential proxy without broad network access. `ProxyFiltering` is currently in `classify_supervisor_support` unsupported list. | M | Extends WFP IPC contract alongside port filtering; share protocol version bump with Port-01 |
| **`nono learn` via ETW** | Path discovery for building profiles. Closes the last developer-tooling gap. ETW `Microsoft-Windows-Kernel-File` and `Microsoft-Windows-Kernel-Network` providers capture file I/O and network events at kernel level per PID. | L | Requires admin privilege; output format must match Unix learn JSON schema |
| **Runtime capability expansion** | Allows a running sandboxed agent to request additional capabilities via named pipe; supervisor prompts user. The `WindowsSupervisorDenyAllApprovalBackend` provides the safe deny-all fallback while this is absent. | M | Stretch goal; IPC channel already exists from v1.0 Phase 2 |

---

## Anti-Features

Features to explicitly NOT build in v2.0, and why.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **Runtime file-open interception (Gap 6b)** | No user-mode equivalent to `seccomp-BPF + SIGSYS`. Kernel minifilter driver (FltMgr) required — needs signed kernel driver, driver signing certificate, maintenance across kernel updates. This is endpoint-security product scope. | Document the limitation explicitly. Pre-exec trust scanning (nono trust) works on Windows. Deferred to v3.0. |
| **ConPTY fallback to non-PTY path** | Silently falling back to a plain `CreateProcess` when `CreatePseudoConsole` fails would remove terminal resize, Ctrl-C forwarding, and proper raw-mode passthrough without warning the user. Violates fail-secure principle. | Enforce minimum build 17763 via `RtlGetVersion` at startup. Return a clear error: "nono shell requires Windows 10 1809 or later." |
| **ETW-based syscall blocking** | ETW providers are observe-only. You cannot block or modify an operation from an ETW event handler. This is a documented Windows API constraint. | ETW for `nono learn` only. Blocking requires minifilter. |
| **Direct `windows-sys` ETW for learn without evaluating ferrisetw** | The `ferrisetw` crate provides safe ETW consumer bindings. Writing a raw ETW consumer against `windows-sys` is ~400 lines of unsafe code for session management, event parsing, and schema lookup. Not justified unless ferrisetw is unsuitable. | Evaluate ferrisetw first (license: Apache-2.0; last release 2023 — check maintenance status before adopting). Document the decision in D-01. |
| **Proxy via separate nono-proxy binary on Windows** | nono-proxy exists and uses tokio/hyper; spawning it as a subprocess from the Windows supervisor adds IPC complexity and a second failure mode. | Inject `HTTPS_PROXY` env var pointing to the pre-existing local proxy address. WFP permits the loopback port. The proxy process is managed externally by the user or agent framework. |
| **`nono shell` without minimum version check** | Windows 10 pre-1809 lacks `CreatePseudoConsole`. Older build number check must be runtime (not compile-time) because the binary is distributed as a universal Windows executable. | `RtlGetVersion` check at `nono shell` entry point. |

---

## Feature Dependencies

```
WRAP-01 (nono wrap)
  └── requires: remove WindowsPreviewEntryPoint::Wrap guard in sandbox/windows.rs
  └── requires: Direct strategy path in exec_strategy_windows/mod.rs to not panic
  └── provides: validated entry-point pattern for B-01 (shell)

SESS-01 (logs/inspect/prune)
  └── requires: session record format already shared — no new infrastructure
  └── provides: nothing downstream, independent

SHELL-01 (nono shell via ConPTY)
  └── requires: Phase A (entry-point pattern validated)
  └── requires: pty_proxy_windows.rs PtyPair (scaffolded, not wired)
  └── requires: Job Object assignment for ConPTY child process
  └── requires: ResizePseudoConsole called from console-resize watcher thread
  └── requires: Ctrl-C routing: GenerateConsoleCtrlEvent to child, NOT to supervisor
  └── requires: RtlGetVersion check (build >= 17763)

PORT-01 (port-level WFP filtering)
  └── requires: WfpRuntimeActivationRequest field extension (already has tcp_connect_ports etc.)
  └── requires: nono-wfp-service deserialization update + filter builder update
  └── requires: protocol_version bump (share with PROXY-01)

PROXY-01 (proxy credential injection)
  └── requires: PORT-01 (share WFP IPC protocol version bump)
  └── requires: ProxyFiltering removed from unsupported list in classify_supervisor_support
  └── requires: HTTPS_PROXY injected into ExecConfig.env_vars
  └── requires: WFP permit filter for 127.0.0.1:<proxy_port> inserted before block-all

LEARN-01 (nono learn via ETW)
  └── requires: admin privilege (ETW kernel providers require elevated session)
  └── requires: ETW library decision (ferrisetw vs windows-sys direct)
  └── requires: Microsoft-Windows-Kernel-File provider GUID EDD08927-9CC4-4E65-B970-C2560FB5C289
  └── requires: Microsoft-Windows-Kernel-Network provider (TcpIp events)
  └── requires: PID filter on events (child PID, not all-system)
  └── provides: output matching LearnResult JSON schema (used by existing tooling)

TRUST-01 (runtime capability expansion) [stretch]
  └── requires: named-pipe IPC already in place from v1.0 Phase 2
  └── requires: SupervisorMessage::RequestCapability variant added
  └── requires: extensions_enabled() hard block removed from sandbox/windows.rs
  └── requires: TerminalApproval routing in Windows supervisor event loop
  └── requires: session token in request (deny requests without valid token)
```

---

## Windows-Specific Behavioral Differences from Unix

This section documents every case where the Windows behavior diverges from Unix in a
user-visible way, to ensure help text, docs, and tests reflect reality.

### `nono wrap`

| Behavior | Unix | Windows |
|----------|------|---------|
| Process model | `exec`-replace; nono PID disappears | `CreateProcess` + Job Object; nono stays alive as owner |
| `$$` in child shell | Returns nono's original PID (inherited via exec) | Returns child's own PID |
| Parent PID of child | Inherited from caller's parent | nono.exe is the parent |
| Ctrl-C from terminal | Delivered to sandboxed process (same process group) | Must be forwarded via `GenerateConsoleCtrlEvent(CTRL_C_EVENT, child_pid)` |
| Exit code | nono exits with child's exit code (same process) | nono collects child exit code from `WaitForSingleObject` and exits with it |
| Proxy mode | Supported | Not supported (returns `ConfigParse` error); use `nono run` |

### `nono shell`

| Behavior | Unix | Windows |
|----------|------|---------|
| PTY mechanism | `openpty`/`posix_openpt` | `CreatePseudoConsole` (ConPTY; requires build 17763+) |
| Default shell | `$SHELL` env var | `powershell.exe` (fallback: `cmd.exe`) |
| Terminal resize | `SIGWINCH` → `ioctl(TIOCSWINSZ)` | Console resize event → `ResizePseudoConsole(hpcon, new_size)` |
| Ctrl-C forwarding | `SIGINT` delivered to child process group | `GenerateConsoleCtrlEvent(CTRL_C_EVENT, child_pid)`; supervisor must NOT attach to the same console |
| Job Object | Applied to shell child | Applied to ConPTY child process; must be done after `CreateProcess` returns, before `ResumeThread` |
| WFP enforcement | N/A (Landlock/Seatbelt) | WFP filters apply to the child SID; ConPTY host process (nono) is exempt |
| Raw mode | `cfmakeraw` on stdin fd | `SetConsoleMode` with `ENABLE_VIRTUAL_TERMINAL_INPUT` + disable `ENABLE_ECHO_INPUT`/`ENABLE_LINE_INPUT` on the parent console |
| Minimum OS | Any supported Linux/macOS | Windows 10 1809 (build 17763); runtime check required |

### `nono learn`

| Behavior | Unix | Windows |
|----------|------|---------|
| Tracing mechanism | `strace` (Linux) / `fs_usage + nettop` (macOS) | ETW kernel providers (admin required) |
| Privilege required | Linux: none (own process via ptrace); macOS: `sudo` for `fs_usage` | Admin/elevated session required for kernel ETW providers |
| Event granularity | Syscall-level | ETW event-level (FileIo/Create, FileIo/Read, FileIo/Write, TcpIp/Connect, TcpIp/Accept) |
| Path reconstruction | Direct from syscall args | Kernel events carry file object handles; full path requires `NtQueryObject` or file name from event data |
| Output format | `LearnResult` JSON schema (read_paths, write_paths, outbound_connections, etc.) | Must emit identical JSON schema for profile compatibility |
| PID filtering | ptrace follows child directly | Must filter ETW events by child PID in the consumer callback |

### `nono logs` / `nono inspect` / `nono prune`

| Behavior | Unix | Windows |
|----------|------|---------|
| Session record location | `~/.config/nono/sessions/` | `~/.config/nono/sessions/` (same path; Windows resolves `~` to `%USERPROFILE%`) |
| `reject_if_sandboxed` guard | Present (`NONO_CAP_FILE` env check) | Must be applied on Windows too for `prune` and `stop` |
| PTY/signal dependencies | `run_stop` uses `nix::signal::kill` (SIGTERM/SIGKILL) | `run_stop` already uses `TerminateJobObject` + named-pipe polite-stop; no Unix deps |
| `run_logs` / `run_inspect` | Pure file reads from session directory | Identical implementation; no platform-specific code needed |

### Port-Level Network Filtering + Proxy

| Behavior | Unix (Linux) | Windows |
|----------|--------------|---------|
| Port enforcement mechanism | Landlock ABI v4+ (TCP network filtering) | WFP `FWPM_FILTER0` per-port permit entries in nono-wfp-service sublayer |
| Filter ordering | Landlock allow-list (no deny-within-allow) | WFP weight ordering: per-port permit (high weight) before block-all (low weight) |
| Proxy injection | `HTTPS_PROXY` env var | `HTTPS_PROXY` env var via `ExecConfig.env_vars` + WFP loopback permit for `127.0.0.1:<port>` |
| Block-all behavior | Landlock denies non-allowed TCP | WFP block-all sublayer filter; existing behavior from v1.0 Phase 6 |

---

## MVP Recommendation

**Phase A (immediately actionable, no new infrastructure):**
1. `nono wrap` — remove `WindowsPreviewEntryPoint::Wrap` guard, add help-text behavioral note.
2. `nono logs`, `nono inspect`, `nono prune` — implement `run_logs`, `run_inspect`, `run_prune` in `session_commands_windows.rs` using shared file I/O against the session record directory.

**Phase B (new infrastructure, medium complexity):**
3. `nono shell` via ConPTY — wire `PtyPair` (already scaffolded in `pty_proxy_windows.rs`) into the shell command entry point, add resize and Ctrl-C forwarding, enforce build 17763 check.

**Phase C (WFP IPC extension, one protocol version bump):**
4. Port-level filtering + proxy injection — extend `WfpRuntimeActivationRequest`, update `nono-wfp-service` filter builder, remove unsupported entries from `classify_supervisor_support`.

**Phase D (admin privilege dependency, large):**
5. `nono learn` via ETW — evaluate ferrisetw vs direct `windows-sys`, stand up ETW consumer session, decode file and network events, emit matching LearnResult JSON.

**Phase E (stretch):**
6. Runtime capability expansion — extend `SupervisorMessage` enum, add session token auth, remove `extensions_enabled()` hard block.

**Explicit deferred (document in product docs):**
- Runtime file-open interception (Gap 6b) — requires signed kernel minifilter driver. v3.0.

---

## Sources

- Codebase direct inspection: `crates/nono-cli/src/session_commands_windows.rs`,
  `crates/nono-cli/src/pty_proxy_windows.rs`, `crates/nono/src/sandbox/windows.rs`,
  `crates/nono-cli/src/exec_strategy_windows/mod.rs`,
  `crates/nono-cli/src/windows_wfp_contract.rs` (HIGH confidence)
- `.planning/PROJECT.md` — v2.0 requirements WRAP-01, SESS-01, SHELL-01, PORT-01, PROXY-01, LEARN-01, TRUST-01 (HIGH confidence)
- `.planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/WINDOWS-V2-ROADMAP.md` — phase ordering, complexity ratings, open questions (HIGH confidence)
- Windows API domain knowledge: `CreatePseudoConsole` (ConPTY, requires build 17763+), `ResizePseudoConsole`, `GenerateConsoleCtrlEvent`, ETW kernel providers `Microsoft-Windows-Kernel-File` (GUID EDD08927-9CC4-4E65-B970-C2560FB5C289) and `Microsoft-Windows-Kernel-Network`, `FWPM_FILTER0` WFP filter weight ordering (MEDIUM confidence — training data, not verified against current MSDN during this session due to WebSearch unavailability)
- ferrisetw crate: Apache-2.0, last release 2023 — maintenance status unverified (LOW confidence on maintenance; HIGH confidence on API surface from prior use)
