# Roadmap: Windows v2.0 — Gap Closure

This roadmap outlines the path to full cross-platform parity between the Windows implementation of `nono` and its Unix counterparts. It targets the seven feature gaps identified in the equivalence assessment and research phase (see `260406-bem-RESEARCH.md`), organized into dependency-ordered phases.

**Milestone goal:** Close the remaining 7 feature gaps between Windows and Unix platforms, bringing nono to full cross-platform parity for everyday CLI usage, network policy, and developer tooling.

**Core value:** Every nono command that works on Linux/macOS should work on Windows with equivalent security guarantees, or be explicitly documented as intentionally unsupported with a clear rationale.

---

## Gap Coverage Table

| Gap | Description | Phase | Complexity |
|-----|-------------|-------|------------|
| Gap 1 | `nono shell` — ConPTY interactive shell host | Phase B | M |
| Gap 2 | `nono wrap` — one-way apply mode | Phase A | S |
| Gap 3 | `nono learn` — ETW-based path discovery | Phase D | L |
| Gap 4 | Proxy filtering / credential injection | Phase C | M |
| Gap 5 | Port-level network filtering (WFP sublayer) | Phase C | M |
| Gap 6a | Runtime capability expansion (named-pipe IPC) | Phase E (stretch) | M |
| Gap 6b | Runtime trust interception (kernel minifilter) | Deferred to v3.0 | XL |
| Gap 7 | Session log commands (`nono logs`, `nono inspect`, `nono prune`) | Phase A | S |

---

## Dependency Diagram

```
Phase A (wrap + session logs)   ──> Phase B (ConPTY shell)
Phase C (WFP port + proxy)       [independent — no deps]
Phase D (ETW learn)              [independent — no deps]
Phase E (runtime caps, stretch)  [independent — no deps]
```

Phases A, C, and D can be started in parallel. Phase B depends on Phase A
(to validate the shared entry-point pattern before adding ConPTY complexity).
Phase E is a stretch goal and is independent of all other phases.

---

## Phases

- [ ] **Phase A: Quick Wins** — Unblock everyday UX with trivial effort (Gap 2 + Gap 7)
- [ ] **Phase B: ConPTY Shell** — Enable interactive `nono shell` on Windows (Gap 1)
- [ ] **Phase C: WFP Port-Level + Proxy Filtering** — Enable port-granular network policy and credential injection (Gap 4 + Gap 5)
- [ ] **Phase D: ETW-Based Learn Command** — Implement syscall-based path discovery on Windows (Gap 3)
- [ ] **Phase E: Runtime Capability Expansion** — Stretch goal: runtime cap requests over named pipe (Gap 6a)

---

## Phase Details

### Phase A: Quick Wins (PLANNED)

**Goal:** Unblock everyday UX with trivial effort — remove stubs from `nono wrap` and the three session log commands.

**Covers:** Gap 2 (`nono wrap`) and Gap 7 (`nono logs`, `nono inspect`, `nono prune`)

**Complexity:** S + S

**Dependencies:** None — can start immediately.

**Requirements:** WRAP-01, SESS-01

**Plans:** 1–2 plans

Plans:
- [ ] A-01-PLAN.md — Implement `nono wrap` on Windows: map to Direct strategy, remove `UnsupportedPlatform` block, add behavioral-difference note to help text
- [ ] A-02-PLAN.md — Implement `run_logs`, `run_inspect`, `run_prune` in `session_commands_windows.rs` using shared session record format

**Success Criteria** (what must be TRUE):
1. `nono wrap <cmd>` executes on Windows with Job Object + WFP enforcement.
2. `nono logs`, `nono inspect`, `nono prune` work on Windows session records.
3. Help text documents that `nono wrap` does not exec-replace the CLI process on Windows (stays alive as Job Object owner); this is a behavioral difference, not a security difference.
4. All three session commands read from `~/.config/nono/sessions/` without PTY or Unix-specific dependencies.

---

### Phase B: ConPTY Shell (PLANNED)

**Goal:** Enable interactive `nono shell` on Windows via the ConPTY API (`CreatePseudoConsole`).

**Covers:** Gap 1 (`nono shell`)

**Complexity:** M

**Depends on:** Phase A (validate the shared `validate_preview_entry_point` pattern and entry-point guard before layering ConPTY complexity on top)

**Requirements:** SHELL-01

**Plans:** 2 plans

Plans:
- [ ] B-01-PLAN.md — ConPTY wiring + enforcement validation: add ConPTY-aware branch to `spawn_windows_child`, update `validate_preview_entry_point(Shell)` to allow within Windows-supported shape, default `--shell` to `powershell.exe`, verify Job Object attachment for ConPTY child
- [ ] B-02-PLAN.md — I/O relay + terminal resize: add stdout pump thread and stdin feed, wire `ResizePseudoConsole` to console resize watcher, raw-mode stdin passthrough, Ctrl-C forwarding

**Success Criteria** (what must be TRUE):
1. `nono shell` launches an interactive PowerShell or cmd session inside a Job Object + WFP sandbox.
2. Terminal resize events propagate correctly via `ResizePseudoConsole`.
3. Job Object and WFP enforcement apply to the shell child process (not just the ConPTY host).
4. Minimum Windows 10 build 17763 (1809) is enforced at runtime with a clear error on older builds; no silent fallback to a non-PTY path.
5. Ctrl-C is forwarded to the child process without killing the supervisor.

---

### Phase C: WFP Port-Level + Proxy Filtering (PLANNED)

**Goal:** Enable port-granular network policy and proxy credential injection on Windows by extending the WFP IPC contract.

**Covers:** Gap 4 (proxy filtering / credential injection) and Gap 5 (port-level network filtering)

**Complexity:** M + M

**Depends on:** None — WFP IPC service is already in place from v1.0 Phase 3 + Phase 6.

**Note:** Gaps 4 and 5 both extend `WfpRuntimeActivationRequest`. They are grouped in a single phase to avoid two separate IPC contract version bumps.

**Requirements:** PORT-01, PROXY-01

**Plans:** 2–3 plans

Plans:
- [ ] C-01-PLAN.md — Extend `WfpRuntimeActivationRequest` with `ProxyOnly { port: u16 }` and port allowlist fields (`port_connect_allowlist`, `port_bind_allowlist`, `localhost_port_allowlist`); bump IPC contract version; update `nono-wfp-service` deserialization
- [ ] C-02-PLAN.md — Proxy filtering: add WFP permit filter for `127.0.0.1:<proxy_port>` before block-all, remove `ProxyFiltering` from `classify_supervisor_support` unsupported list, verify `HTTPS_PROXY`/`NONO_PROXY_TOKEN` env injection reaches child via `ExecConfig.env_vars`
- [ ] C-03-PLAN.md — Port filtering: translate `PortConnectAllowlist`, `PortBindAllowlist`, `LocalhostPortAllowlist` to WFP `FWPM_FILTER0` entries in the service; remove unsupported entries from `compile_network_policy`; integration tests for filter weight ordering

**Success Criteria** (what must be TRUE):
1. `--allow-port 8080` creates a WFP permit filter for TCP connects to port 8080.
2. `--proxy-only` mode routes outbound TCP through the localhost proxy port with WFP enforcement; all other outbound traffic is blocked.
3. Port bind and connect allowlists work independently of each other.
4. Credential injection via `HTTPS_PROXY` env var reaches the sandboxed child process.
5. WFP filter weight ordering is correct: per-port/localhost permit filters have higher priority than the block-all filter.

---

### Phase D: ETW-Based Learn Command (PLANNED)

**Goal:** Implement `nono learn` on Windows using Event Tracing for Windows (ETW) to capture file and network access patterns.

**Covers:** Gap 3 (`nono learn`)

**Complexity:** L

**Depends on:** None — fully independent. However, requires admin privilege on the host system.

**Requirements:** LEARN-01

**Plans:** 2–3 plans

Plans:
- [ ] D-01-PLAN.md — ETW integration: evaluate `ferrisetw` vs direct `windows-sys` ETW bindings; stand up ETW consumer session using `Microsoft-Windows-Kernel-File` (GUID `EDD08927-9CC4-4E65-B970-C2560FB5C289`) and `Microsoft-Windows-Kernel-Network` providers; filter events by child PID
- [ ] D-02-PLAN.md — File I/O tracing: decode `FileIo/Create`, `FileIo/Read`, `FileIo/Write` events, reconstruct full paths from kernel event data, emit output matching Unix learn format (path, access mode)
- [ ] D-03-PLAN.md — Network tracing + output format: decode `TcpIp/Connect`, `TcpIp/Accept` events, unify output format with Unix backends, add admin privilege check with clear error, wire into `learn.rs` behind `#[cfg(target_os = "windows")]`

**Success Criteria** (what must be TRUE):
1. `nono learn <cmd>` captures file and network access events on Windows using ETW.
2. Output format matches Unix learn output (paths, access modes) so existing tooling and profiles can consume it.
3. Running without admin privilege produces a clear, actionable error message rather than silent failure.
4. The ETW library choice (`ferrisetw` or `windows-sys` direct) is documented with rationale in the phase summary.
5. ETW provider GUIDs and event field mappings are validated against the Windows version matrix (Windows 10 1809+).

---

### Phase E: Runtime Capability Expansion (Stretch / Planned)

**Goal:** Enable the sandboxed child process to request additional capabilities from the supervisor at runtime via the named-pipe IPC channel.

**Covers:** Gap 6a (runtime capability expansion)

**Complexity:** M

**Depends on:** Named-pipe supervisor IPC (already in place from v1.0 Phase 2). Independent of Phases A–D.

**Note:** This is a stretch goal. It may be deferred to v2.1 if the timeline for Phases A–D is tight. The existing `WindowsSupervisorDenyAllApprovalBackend` provides a safe deny-all fallback that keeps the system secure while this feature is not yet implemented.

**Requirements:** TRUST-01

**Plans:** 1–2 plans

Plans:
- [ ] E-01-PLAN.md — Add `RequestCapability { request: CapabilityRequest, session_token: String }` to `SupervisorMessage` enum; add child-side SDK (environment variable + named-pipe write protocol) for agents to emit capability requests; wire `TerminalApproval` routing in Windows supervisor event loop
- [ ] E-02-PLAN.md — Session token authentication on capability requests; remove `extensions_enabled()` hard block in `sandbox/windows.rs`; integration tests for grant/deny flows

**Success Criteria** (what must be TRUE):
1. A sandboxed child process can request additional capabilities by writing a JSON message to the supervisor's named pipe.
2. The supervisor prompts the user for approval via `TerminalApproval` before granting any capability.
3. Capability requests include the session token; requests without a valid token are denied immediately.
4. The existing deny-all fallback remains active when this feature is disabled or not yet available.

---

## Deferred Items

### Gap 6b: Runtime Trust Interception — Deferred to v3.0

**What it is:** Real-time interception of file-open operations from a sandboxed child process, equivalent to the Unix `ptrace`/`seccomp-BPF` + `SIGSYS` model.

**Why it is deferred:** Windows has no user-mode equivalent. Achieving runtime file-open interception on Windows requires a signed kernel-mode minifilter driver using the Windows Filter Manager (`FltMgr`). This is how endpoint security products (antivirus, DLP) implement file-open mediation. Obtaining a kernel driver signing certificate, building the driver, and maintaining it across Windows kernel updates is equivalent to building a component of an endpoint security product. This is out of scope for the v2.0 milestone.

**Alternatives rejected:**
- **User-mode API hooking (Detours-style):** Unreliable, bypassed by direct syscalls, and triggers antivirus false positives. Rejected.
- **ETW-based blocking:** ETW providers are observe-only. You cannot block an operation from an ETW event handler. Rejected.
- **Debug port (single-step NtCreateFile):** Extraordinarily slow; incompatible with programs that detect debuggers. Rejected.

**What the product docs must say:** Pre-exec trust verification (scanning instruction files before launch) works on Windows. Runtime interception of file opens during execution is not available on Windows. This limitation is structural and cannot be worked around without a kernel driver.

**Target version:** v3.0 (requires separate kernel driver project and signing infrastructure).

---

## Open Questions

The following questions are unresolved and must be answered before or during the relevant phase:

1. **Port filtering + proxy in same WFP IPC bump?** Gap 4 and Gap 5 both extend `WfpRuntimeActivationRequest`. They are grouped in Phase C specifically to share a single protocol version increment. Confirm that the IPC versioning scheme can accommodate both extensions in a single bump before starting C-01.

2. **`ferrisetw` license and maintenance status** — `ferrisetw` is Apache-2.0 but last released in 2023. Before adopting it for `nono learn` in Phase D, evaluate whether the ETW consumer bindings are sufficient or whether a direct `windows-sys` ETW implementation is preferable (more code, no external dependency with uncertain maintenance). Document the decision in D-01.

3. **ConPTY minimum version enforcement** — `CreatePseudoConsole` requires Windows 10 1809 (build 17763). The codebase currently targets "Windows 10/11" without a fine-grained build check. Verify whether the installed base of Windows 10 older than 1809 is a concern for the target user base. If yes, add a runtime `RtlGetVersion` check and a clear error message in B-01. Do not silently fall back to a non-PTY path.

4. **`nono wrap` behavioral difference documentation** — Unix `wrap` replaces the CLI process via `exec`. Windows `wrap` keeps the CLI alive as Job Object owner. This is a documentation and help-text concern, not a security concern, but users accustomed to Unix behavior should be warned. Confirm help text wording in A-01 before shipping.

---

## Progress Table

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| A. Quick Wins | 0/2 | Not Started | — |
| B. ConPTY Shell | 0/2 | Not Started | — |
| C. WFP Port + Proxy Filtering | 0/3 | Not Started | — |
| D. ETW Learn Command | 0/3 | Not Started | — |
| E. Runtime Capability Expansion | 0/2 | Not Started | — |
