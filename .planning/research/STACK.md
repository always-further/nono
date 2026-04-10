# Technology Stack: Windows v2.0 Gap Closure

**Project:** nono — Windows Gap Closure (v2.0)
**Researched:** 2026-04-06
**Scope:** Additive stack changes only — what is NEW relative to the existing windows-sys 0.59 + tokio 1 + nono-proxy baseline already in place.

---

## Baseline (Already in Place — Do Not Re-research)

The following are confirmed present in source code and Cargo.toml files:

| What | Where | Confirmed |
|------|-------|-----------|
| `windows-sys = "0.59"` with features: `Win32_Foundation`, `Win32_NetworkManagement_WindowsFilteringPlatform`, `Win32_Security`, `Win32_Security_Authorization`, `Win32_Storage_FileSystem`, `Win32_System_Console`, `Win32_System_EventLog`, `Win32_System_JobObjects`, `Win32_System_Memory`, `Win32_System_Pipes`, `Win32_System_Rpc`, `Win32_System_Services`, `Win32_System_SystemServices`, `Win32_System_Threading` | `crates/nono-cli/Cargo.toml` | Source-confirmed |
| ConPTY scaffold: `CreatePseudoConsole`, `ClosePseudoConsole`, `HPCON` | `pty_proxy_windows.rs` | Source-confirmed |
| Named-pipe IPC supervisor (create, connect, read, write) | `exec_strategy_windows/supervisor.rs` | Source-confirmed |
| WFP service IPC contract (`WfpRuntimeActivationRequest` / `WfpRuntimeActivationResponse`) | `windows_wfp_contract.rs` | Source-confirmed |
| `nono-proxy` server (tokio TcpListener, cross-platform) | `crates/nono-proxy/` | Source-confirmed |
| Job Object creation and child assignment | `exec_strategy_windows/launch.rs` | Source-confirmed |
| `tokio = "1"` in workspace | `Cargo.toml` | Source-confirmed |
| MSRV: Rust 1.77 | `Cargo.toml` workspace.package.rust-version | Source-confirmed |

---

## New Stack Requirements by Feature

### Phase A: `nono wrap` + Session Log Commands

**No new dependencies required.**

`nono wrap` maps to the existing `execute_direct` path (Job Object + WFP). The only work is removing the `UnsupportedPlatform` guard in `validate_preview_entry_point`.

Session commands (`logs`, `inspect`, `prune`) read JSON session records from `~/.config/nono/sessions/`. The session record format and the `session::list_sessions()` / `session::load_session()` functions already compile and run on Windows — confirmed by `run_ps` and `run_stop` which share the same call sites.

**windows-sys feature additions needed:** None.

---

### Phase B: ConPTY Shell (`nono shell`)

**No new crates required.** The `CreatePseudoConsole` path is already implemented in `pty_proxy_windows.rs`. What is missing is wiring three additional Win32 APIs that are NOT yet imported.

#### New windows-sys feature flag: `Win32_System_Threading` (process attribute list)

Already present in the feature list as `Win32_System_Threading`. However, the following specific APIs within that feature are not yet called anywhere in the source and must be added to the ConPTY-aware `spawn_windows_child` branch:

| API | Feature flag | Already imported? | Required for |
|-----|-------------|-------------------|--------------|
| `InitializeProcThreadAttributeList` | `Win32_System_Threading` | No | Allocate attribute list for `STARTUPINFOEXW` |
| `UpdateProcThreadAttribute` | `Win32_System_Threading` | No | Attach `HPCON` to child process via `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` |
| `DeleteProcThreadAttributeList` | `Win32_System_Threading` | No | Free the attribute list |
| `ResizePseudoConsole` | `Win32_System_Console` | No | Forward terminal resize events |

`Win32_System_Console` is already in the feature list (confirmed: `CreatePseudoConsole` is imported there). `Win32_System_Threading` is already in the feature list. Both feature flags are present; only the specific function imports need to be added in the ConPTY code path.

**Minimum Windows build for ConPTY:** Windows 10 build 17763 (version 1809).
`CreatePseudoConsole` was introduced in build 17763. A runtime version guard using `RtlGetVersion` (available in `ntdll.dll`, bindable via `windows-sys` `Win32_System_SystemServices` which is already in the feature list) must be added to fail closed on older builds with a clear error. Do not silently fall back.

**`STARTUPINFOEXW` struct:** This is defined in `Win32_System_Threading` and is already accessible via the existing feature flag. The `CREATE_EXTENDED_STARTUPINFO_PRESENT` creation flag constant is in the same feature.

**I/O relay threads:** Use `std::thread::spawn` + `std::io::Read`/`Write` over raw Windows `HANDLE` (via `std::os::windows::io::FromRawHandle`). This pattern is already used in `supervisor.rs`. No new crate needed.

**Console resize watcher:** Use `ReadConsoleInputW` (in `Win32_System_Console`, already in feature list) in a background thread to detect `WINDOW_BUFFER_SIZE_EVENT` records. Feed these to `ResizePseudoConsole`.

**`--shell` default on Windows:** Resolve via `std::env::var("COMSPEC")` (already available in `build_child_env`). Fall back to `powershell.exe`. No new dependency.

**Confidence:** HIGH — all API surfaces are in existing `windows-sys` 0.59 feature flags; no new crates needed.

---

### Phase C: WFP Port-Level Filtering + Proxy Filtering

**No new crates required.** Both features extend the existing `WfpRuntimeActivationRequest` IPC contract and add new WFP filter types in the `nono-wfp-service` binary.

#### IPC contract extension

Add to `WfpRuntimeActivationRequest` (in `windows_wfp_contract.rs`):

```rust
pub port_connect_allowlist: Vec<u16>,   // replaces existing tcp_connect_ports (already present but rejected)
pub port_bind_allowlist: Vec<u16>,       // replaces existing tcp_bind_ports (already present but rejected)
pub localhost_port_allowlist: Vec<u16>,  // replaces existing localhost_ports (already present but rejected)
pub proxy_port: Option<u16>,             // new: ProxyOnly mode localhost permit port
```

These fields already exist in `WfpRuntimeActivationRequest` (`tcp_connect_ports`, `tcp_bind_ports`, `localhost_ports`) but are populated and then rejected in `compile_network_policy`. The Phase C work is removing those rejections and wiring the service-side translation.

Bump `WFP_RUNTIME_PROTOCOL_VERSION` from 1 to 2 when these fields are activated. The existing protocol version check in the service handles forward/backward compatibility.

#### WFP filter additions in `nono-wfp-service`

All required WFP layer GUIDs and condition type GUIDs are already accessible via `Win32_NetworkManagement_WindowsFilteringPlatform` (confirmed in the existing feature list):

| New filter type | WFP layer | Condition |
|----------------|-----------|-----------|
| Port-connect allowlist | `FWPM_LAYER_ALE_AUTH_CONNECT_V4` / `_V6` | `FWPM_CONDITION_IP_REMOTE_PORT == port` (`FWP_UINT16`) |
| Port-bind allowlist | `FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4` / `_V6` | `FWPM_CONDITION_IP_LOCAL_PORT == port` (`FWP_UINT16`) |
| Localhost-port allowlist | `FWPM_LAYER_ALE_AUTH_CONNECT_V4` | `FWPM_CONDITION_IP_REMOTE_ADDRESS == 127.0.0.1` AND `FWPM_CONDITION_IP_REMOTE_PORT == port` |
| ProxyOnly localhost permit | `FWPM_LAYER_ALE_AUTH_CONNECT_V4` | `FWPM_CONDITION_IP_REMOTE_ADDRESS == 127.0.0.1` AND `FWPM_CONDITION_IP_REMOTE_PORT == proxy_port` |

Filter weight ordering rule (CRITICAL — security-critical): per-port and localhost-permit filters must have a numerically higher weight value than the block-all filter. The block-all filter is the lowest-weight entry in the sublayer; all permit filters must exceed it. This is the same ordering pattern used for domain allowlists on Unix and is straightforward in WFP using `FWPM_FILTER0.weight`.

**Proxy env injection:** `HTTPS_PROXY` and `NONO_PROXY_TOKEN` are already passed to the child via `ExecConfig.env_vars` and `build_child_env`. The proxy server in `nono-proxy` is a `TcpListener::bind("127.0.0.1:0")` tokio server that is already platform-agnostic. No new work on the proxy server itself.

**windows-sys feature additions needed:** None — `Win32_NetworkManagement_WindowsFilteringPlatform` is already in the feature list.

**Minimum Windows build:** Windows 10 (all WFP ALE layers used here have been present since Vista). No version guard needed beyond the existing Windows 10/11 baseline.

**Confidence:** HIGH — WFP port conditions are standard MSDN-documented filter types; IPC contract extension is additive to existing serde structs.

---

### Phase D: ETW-Based `nono learn`

This is the only phase that requires a genuine dependency decision. Two options; recommendation is to avoid `ferrisetw` and use `windows-sys` direct bindings.

#### Option 1 (Recommended): `windows-sys` direct ETW bindings

Add feature flag `Win32_System_Diagnostics_Etw` to the `windows-sys` entry in `nono-cli/Cargo.toml`.

This feature exposes the full ETW consumer and controller API:

| API | Purpose |
|-----|---------|
| `StartTraceW` | Open a new ETW trace session |
| `OpenTraceW` | Open a real-time or file-based trace |
| `ProcessTrace` | Blocking call that delivers events to a callback |
| `CloseTrace` | Close trace handle |
| `ControlTraceW` | Stop, query, or flush a trace session |
| `EnableTraceEx2` | Enable a provider GUID in the session |
| `EVENT_RECORD` / `EVENT_HEADER` | Inbound event struct in the callback |
| `EVENT_TRACE_PROPERTIES` | Session configuration struct |
| `TdhGetEventInformation` | Decode event schema from TDH |
| `PROPERTY_DATA_DESCRIPTOR` | TDH field accessor |

The `Win32_System_Diagnostics_Etw` feature is available in `windows-sys 0.59` (confirmed in the windows-sys 0.59 crate structure).

**Why over `ferrisetw`:** `ferrisetw` (crates.io: `ferrisetw`, Apache-2.0, maintained by n4r1b) last published in 2023. It provides a safe Rust wrapper but adds a dependency with uncertain maintenance trajectory. The ETW consumer pattern for `nono learn` is a bounded, well-understood surface: start a session, enable two providers (Kernel-File, Kernel-Network), filter by PID, decode three event types each. This is ~300–400 lines of `unsafe` code with `// SAFETY:` documentation, consistent with the existing `windows-sys` usage in `launch.rs`, `restricted_token.rs`, and `supervisor.rs`. The codebase already has patterns for wrapping unsafe Win32 calls safely (`OwnedHandle`, RAII drop impls). Direct bindings eliminate the external dependency risk.

**If `ferrisetw` is chosen instead:** version 1.0.x (check crates.io for latest before D-01; the last confirmed version is 0.3.x from 2023 — treat as LOW confidence on version). License: Apache-2.0. Would need audit of the 2023 codebase for soundness before adoption. This decision must be documented in the D-01 plan per the roadmap's open question.

#### ETW provider GUIDs (stable, from Microsoft documentation)

| Provider | GUID | Events used |
|----------|------|-------------|
| `Microsoft-Windows-Kernel-File` | `{EDD08927-9CC4-4E65-B970-C2560FB5C289}` | `FileIo/Create` (opcode 64), `FileIo/Read` (opcode 67), `FileIo/Write` (opcode 68) |
| `Microsoft-Windows-Kernel-Network` | `{7DD42A49-5329-4832-8DFD-43D979153A88}` | `TcpIp/Connect` (opcode 12), `TcpIp/Accept` (opcode 15) |

These GUIDs are stable since Windows Vista and documented in MSDN. They are unaffected by Windows version within the Windows 10 1809+ baseline.

**Admin privilege requirement:** ETW kernel providers (`Microsoft-Windows-Kernel-File`, `Microsoft-Windows-Kernel-Network`) require `SeSystemProfilePrivilege`. This privilege is held by administrators by default. `nono learn` on Windows must check for elevated privilege at startup using `GetTokenInformation(TokenElevation)` (already called in `exec_strategy_windows/launch.rs` for the low-integrity token path) and emit a clear error if not elevated.

**Minimum Windows build for ETW learn:** Windows 10 1809 (build 17763) — consistent with the ConPTY baseline. The `Microsoft-Windows-Kernel-File` provider's field layout is stable across Windows 10 1809 and later.

#### windows-sys feature addition

```toml
# In crates/nono-cli/Cargo.toml, under [target.'cfg(target_os = "windows")'.dependencies]:
windows-sys = { version = "0.59", features = [
    # ... existing features ...
    "Win32_System_Diagnostics_Etw",   # NEW for Phase D
] }
```

**Confidence:** MEDIUM — `windows-sys 0.59` ETW feature existence confirmed from knowledge of the crate's feature tree (matches the `windows` crate's module structure). The specific API names listed above match MSDN's documented C function names which `windows-sys` binds directly. Flag as needing build verification on Phase D start.

---

### Phase E: Runtime Capability Expansion (Stretch)

**No new crates required.** The named-pipe supervisor IPC is already in place. This phase adds a new message variant to `SupervisorMessage` and routes it through the existing Windows supervisor event loop.

The child-side capability request mechanism (environment variable + named-pipe write) uses only `std::env` and `std::io` — no new dependencies.

Session token authentication uses the existing `uuid` crate (already in `[target.'cfg(target_os = "windows")'.dependencies]`) to generate and validate per-session tokens.

**windows-sys feature additions needed:** None.

---

## Complete Additive Dependency Table

| Package | Version | Location | Phase | Reason |
|---------|---------|----------|-------|--------|
| `windows-sys` feature `Win32_System_Diagnostics_Etw` | 0.59 (existing crate, new feature flag) | `nono-cli/Cargo.toml` | D | ETW consumer API for `nono learn` |

**That is the only additive change to Cargo.toml across all five phases.**

All other work is:
- New `use` imports within existing `windows-sys` feature flags (ConPTY process attribute list APIs in Phase B)
- New WFP filter construction logic calling already-imported APIs (Phase C)
- New message variants in existing serde enums (Phase C IPC contract bump, Phase E supervisor message)
- Removing `UnsupportedPlatform` guards and filling in stub functions (Phase A)

---

## Windows Build Version Requirements by Feature

| Feature | Minimum Windows Build | Minimum Version Name | Enforcement |
|---------|----------------------|---------------------|-------------|
| `nono wrap` (Job Object + WFP) | 16299 | Windows 10 1709 | Already enforced by existing WFP baseline |
| Session log commands | Any Windows 10 | — | No version guard needed (file I/O only) |
| `nono shell` via ConPTY | **17763** | Windows 10 **1809** | Runtime `RtlGetVersion` check required — fail closed |
| Port-level WFP filtering | 15063 | Windows 10 1703 | No new guard (ALE layers predate 1709) |
| Proxy filtering | 15063 | Windows 10 1703 | No new guard |
| `nono learn` via ETW | **17763** | Windows 10 **1809** | Runtime elevation check; consistent with ConPTY minimum |
| Runtime capability expansion | Any Windows 10 | — | No new guard (named-pipe IPC) |

The two hard minimums are build 17763 for ConPTY and ETW kernel providers. These align, so a single shared version guard function (checking `dwBuildNumber >= 17763`) can gate both features. The project's existing `Win32_System_SystemServices` feature flag provides `RtlGetVersion` without additional feature additions.

---

## What NOT to Add

| Package | Why Not |
|---------|---------|
| `portable-pty` | The previous milestone STACK.md recommended this, but source code confirms `pty_proxy_windows.rs` uses `windows-sys` ConPTY bindings directly. Adding `portable-pty` now would require reworking existing code with no benefit. |
| `windows-wfp` | Previous milestone STACK.md recommended this, but source code confirms WFP is implemented via direct `windows-sys` bindings. The WFP sublayer IPC service already exists; switching crates would be a rewrite. |
| `ferrisetw` | Acceptable if the team prefers it, but the direct `windows-sys` ETW bindings cover the exact APIs needed and match the codebase's established pattern for unsafe Win32 work. Decision must be made in D-01 and documented. |
| `sysinfo` | Not needed for any v2.0 feature. Session commands use `session::list_sessions()` which reads JSON files. |
| `tokio::net::windows::named_pipe` | The existing named-pipe supervisor uses synchronous `windows-sys` pipe APIs wrapped in blocking threads. Switching to tokio async named pipes would require a significant supervisor rewrite. Do not change the transport layer. |
| Any new WFP crate | WFP filters for port conditions are `FWPM_FILTER0` structs with `FWP_UINT16` match values — the same pattern as existing SID-based filters. No higher-level abstraction is warranted. |

---

## Confidence Assessment

| Area | Confidence | Basis |
|------|------------|-------|
| Existing feature flags (windows-sys 0.59) | HIGH | Direct `Cargo.toml` source read |
| ConPTY API surfaces needed | HIGH | Direct source read of `pty_proxy_windows.rs` + MSDN API knowledge |
| WFP port filter construction | HIGH | Direct source read of `windows_wfp_contract.rs` + MSDN WFP layer/condition knowledge |
| ETW feature flag existence in windows-sys 0.59 | MEDIUM | windows-sys crate structure knowledge (matches `windows` crate modules); verify on Phase D start |
| ETW provider GUIDs | HIGH | MSDN-documented stable GUIDs, consistent across Windows 10 versions |
| `ferrisetw` version | LOW | Last confirmed release 2023; treat version number as unverified until D-01 crates.io check |
| Build 17763 minimum for ConPTY | HIGH | MSDN `CreatePseudoConsole` documentation |

---

## Sources

- `crates/nono-cli/Cargo.toml` — existing windows-sys 0.59 feature list (source-confirmed, HIGH)
- `crates/nono-cli/src/pty_proxy_windows.rs` — ConPTY scaffold (source-confirmed, HIGH)
- `crates/nono-cli/src/exec_strategy_windows/launch.rs` — `spawn_windows_child`, `STARTUPINFOW` (source-confirmed, HIGH)
- `crates/nono-cli/src/exec_strategy_windows/supervisor.rs` — named-pipe IPC pattern (source-confirmed, HIGH)
- `crates/nono-cli/src/windows_wfp_contract.rs` — existing WFP IPC contract, port fields already present but rejected (source-confirmed, HIGH)
- `.planning/quick/260406-bem-research-and-roadmap-windows-gap-closure/260406-bem-RESEARCH.md` — gap analysis (source-confirmed, HIGH)
- MSDN: `CreatePseudoConsole` minimum build 17763 (knowledge cutoff August 2025, HIGH)
- MSDN: ETW `Microsoft-Windows-Kernel-File` GUID `EDD08927-9CC4-4E65-B970-C2560FB5C289` (HIGH)
- MSDN: ETW `Microsoft-Windows-Kernel-Network` GUID `7DD42A49-5329-4832-8DFD-43D979153A88` (HIGH)
- windows-sys 0.59 crate structure: `Win32_System_Diagnostics_Etw` feature (MEDIUM — verify on Phase D)
