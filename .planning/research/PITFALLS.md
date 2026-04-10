# Domain Pitfalls: Windows v2.0 Gap Closure

**Domain:** Windows Security & Sandbox Implementation — v2.0 Feature Set
**Researched:** 2026-04-06
**Overall confidence:** HIGH (codebase-grounded; v1.0 pitfalls retained and extended)

This document covers pitfalls specific to adding ConPTY shell hosting, ETW-based path discovery,
WFP port-level filtering, proxy credential injection, and runtime capability expansion to the
existing nono Windows implementation. Generic Rust advice is omitted. Security implications
are called out explicitly.

---

## Critical Pitfalls

### Pitfall 1: ConPTY — STARTUPINFOEX Not Used With CreatePseudoConsole

**Phase:** B (ConPTY Shell)
**What goes wrong:** `CreateProcessW` is called with a `STARTUPINFOW` (not `STARTUPINFOEXW`) after
`CreatePseudoConsole` succeeds. The child process is created but inherits the parent's console
rather than the pseudo-console. Terminal output is garbled or entirely missing; the `HPCON` is
referenced but never actually connected to the child.

**Why it happens:** `CreatePseudoConsole` creates the infrastructure but does NOT automatically
wire it to child processes. The caller must explicitly pass the `HPCON` handle via a
`PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` attribute in `lpAttributeList`. This requires
`InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute` with
`PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`, and the `EXTENDED_STARTUPINFO_PRESENT` flag in
`dwCreationFlags`. Missing any one step silently falls back to default console inheritance.

**Consequences:** Supervisor appears to start but terminal I/O does not route through the PTY.
All ANSI escape codes are broken. ResizePseudoConsole calls have no effect.

**Prevention:**
- Use `STARTUPINFOEXW` unconditionally for ConPTY-backed child spawns.
- Call `InitializeProcThreadAttributeList` with `dwAttributeCount = 1`, then
  `UpdateProcThreadAttribute(..., PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpcon, ...)`.
- Pass `CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT` to `CreateProcessW`.
- After spawning, do NOT pass `HPCON` size as `sizeof(HPCON)` — the attribute value is the
  handle value itself, not a pointer to it.
- The current `open_pty` in `pty_proxy_windows.rs` creates the pipe pair and `HPCON` correctly
  but does not yet wire `STARTUPINFOEXW`. This must be done in `spawn_windows_child` (Phase B-01).

**Detection:** Child process exits immediately or `ReadFile` on `output_read` returns 0 bytes.
Check that `GetLastError()` after `CreateProcessW` is not `ERROR_INVALID_PARAMETER` (0x57),
which is the characteristic failure for a malformed `STARTUPINFOEXW`.

---

### Pitfall 2: ConPTY — Missing Runtime Build Version Check

**Phase:** B (ConPTY Shell)
**What goes wrong:** `CreatePseudoConsole` is called on Windows 10 builds before 17763 (version
1809). The function does not exist; calling it via `windows-sys` causes an immediate access
violation because `windows-sys` links the symbol at compile time and the DLL export is absent.

**Why it happens:** `CreatePseudoConsole` was introduced in build 17763. Earlier builds of
Windows 10 (e.g., 1703, 1709, 1803) are still in active enterprise use and nono's stated
compatibility range is "Windows 10/11" without a fine-grained build check.

**Security implication:** If the check is missing and the binary is deployed to an older build,
the process crashes at sandbox entry — a fail-open scenario where the supervisor never starts
enforcement. Any agent command runs unsandboxed before the crash.

**Prevention:**
- Check `RtlGetVersion` (not `GetVersionEx`, which is deprecated and lies) at runtime before
  any ConPTY code path. The `windows-sys` binding is `ntdll::RtlGetVersion`.
- If `dwBuildNumber < 17763`, return `NonoError::UnsupportedPlatform` with a clear message:
  "nono shell requires Windows 10 version 1809 (build 17763) or later. This system is build
  {build}. Upgrade to Windows 10 1809+ or use `nono run`."
- NEVER fall back silently to a non-PTY execution path. The roadmap (SHELL-01, success criterion 4)
  explicitly forbids this. A silent fallback would be an enforcement gap.
- Place this check in `validate_preview_entry_point(Shell, ...)` in `sandbox/windows.rs` before
  any ConPTY allocation.

**Detection:** Runtime crash with STATUS_ACCESS_VIOLATION at ConPTY call site on older Windows 10.

---

### Pitfall 3: ConPTY — Job Object Does Not Contain the ConPTY Host Process

**Phase:** B (ConPTY Shell)
**What goes wrong:** `AssignProcessToJobObject` is called for the child process returned by
`CreateProcessW`, but the ConPTY infrastructure itself runs in a separate conhost.exe process
that is NOT part of the Job Object. When the Job Object terminates (e.g., via `TerminateJobObject`
or `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`), the child shell exits but the conhost process lingers.
This is not a direct security issue (conhost has no access to the sandboxed filesystem), but it
does mean WFP SID-based filtering may not terminate cleanly.

**Why it happens:** Windows 10 hosts the ConPTY inside a conhost.exe instance spawned by the
kernel as part of the console subsystem, outside the Job Object created by nono. This is by
design — the ConPTY host predates the child.

**Prevention:**
- Accept that the ConPTY host (conhost.exe) lives outside the Job Object. This is documented
  Windows behavior, not a bug.
- Ensure that `HPCON` `ClosePseudoConsole` is called in the `Drop` impl of `PtyPair` (already
  done in the existing code). This signals the conhost to exit.
- After child process exit, explicitly call `ClosePseudoConsole` before closing pipe handles.
  Closing in the wrong order causes conhost to hang waiting for a reader.
- Do not rely on `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` to clean up the PTY infrastructure.
  The cleanup sequence is: wait for child exit → ClosePseudoConsole → CloseHandle pipe ends.

**Detection:** `nono shell` exits but conhost.exe remains in Task Manager.

---

### Pitfall 4: ConPTY — Ctrl-C Forwarding Kills the Supervisor

**Phase:** B (ConPTY Shell, B-02)
**What goes wrong:** When the user presses Ctrl-C in a ConPTY session, the generated
`CTRL_C_EVENT` is delivered to both the supervisor process and the child process. The supervisor
exits before it can clean up Job Object, WFP filters, and session records.

**Why it happens:** By default, all processes in the same console session receive console events.
The ConPTY creates an isolated console for the child, but the supervisor's console is the parent
console. If the supervisor does not install a `SetConsoleCtrlHandler` that returns `TRUE` for
`CTRL_C_EVENT`, the default handler kills it.

**Security implication:** Supervisor exit without cleanup leaves WFP dynamic filters alive
temporarily (until the WFP engine drops the session handle), and leaves the Job Object open to
any process with the Job Object name until it's garbage collected. For short gaps this is
tolerable, but the session record is left in `Running` state.

**Prevention:**
- Call `SetConsoleCtrlHandler(Some(handler), TRUE)` in the supervisor before starting I/O relay,
  where `handler` returns `TRUE` for `CTRL_C_EVENT` and `CTRL_BREAK_EVENT`.
- Forward the signal to the child via `GenerateConsoleCtrlEvent(CTRL_C_EVENT, child_pid)`.
- Ensure the Job Object Drop impl (via `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) still terminates
  the child even if the supervisor is signaled while the handler is active.
- Add an integration test: send Ctrl-C during a `nono shell` session and verify the supervisor
  exits cleanly (session record updated, Job Object released).

**Detection:** Supervisor exits with code 0xC000013A (STATUS_CONTROL_C_EXIT) on Ctrl-C.

---

### Pitfall 5: WFP — Per-Port Permit Filters With Weight Lower Than Block-All

**Phase:** C (WFP Port-Level + Proxy Filtering, C-03)
**What goes wrong:** Per-port `FWPM_FILTER0` permit entries are installed with the same or lower
`weight` value than the existing block-all filter. WFP evaluates filters in descending weight
order; the block-all fires first and the port permit is never reached. All outbound traffic is
blocked regardless of allowlist.

**Why it happens:** The WFP weight field is a union of `FWP_UINT64` (explicit weight) or
`FWP_EMPTY` (auto-assigned by BFE). When `FWP_EMPTY` is used for both the block-all and the
permit, BFE assigns weights in installation order. If block-all was installed first (it was, in
the existing v1.0 backend), auto-weighted permits added later receive lower weight and lose.

**Security implication:** A misconfigured weight is a silent enforcement failure: the user
believes port 8080 is permitted but all traffic is actually blocked. Unlike a security
over-claim, this is a usability failure, not a safety failure — the sandbox is MORE restrictive
than claimed. But it makes the feature non-functional, which undermines trust.

**Prevention:**
- Use explicit `FWP_UINT64` weights. Assign the block-all a base weight (e.g., `0x0000_0000_0000_0001`).
- Assign per-port permits and the localhost proxy permit a weight strictly greater than the
  block-all (e.g., `0x0000_0000_0001_0000`).
- Order: highest weight = permit filters (port allowlist, localhost) > lowest weight = block-all.
- The WFP service's protocol version bump (C-01) must document the weight values as part of the
  IPC contract so the client and service agree on ordering without runtime negotiation.
- Add an integration test for the ordering: install block-all, install port permit, attempt a
  TCP connect to that port. A real connection (not just a filter presence check) is the only
  meaningful test.

**Detection:** `nono --allow-port 8080` installs filters visible in `netsh wfp show filters` but
connections to port 8080 still fail with WSAECONNREFUSED or WSAETIMEDOUT.

---

### Pitfall 6: WFP — Proxy Port Permit Added After Block-All Using Same Sublayer

**Phase:** C (Proxy Filtering, C-02)
**What goes wrong:** The localhost proxy permit filter is added to the same sublayer as the
block-all filter. WFP sublayers perform independent evaluation; within a sublayer, only the
highest-weight filter's action counts. If both the block-all and the localhost permit are in the
nono sublayer with the permit at lower weight, all traffic (including localhost) is blocked.

**Why it happens:** Developers add the localhost permit assuming "permit before block" ordering,
but WFP sublayer ordering is weight-descending, not installation-order. The block-all added in
v1.0 has a fixed weight. The new localhost permit inherits `FWP_EMPTY` and gets a lower BFE-
assigned weight.

**Security implication:** Proxy credential injection (PROXY-01) is broken: the sandboxed child
cannot reach the local proxy, so it either falls back to direct connections (if allowed) or
fails entirely. If the policy is `ProxyOnly`, direct connections are blocked, but the child
cannot reach the proxy either — this is fail-closed (good for security), but the agent cannot
function.

**Prevention:**
- Same weight discipline as Pitfall 5: explicit weight for the localhost permit above block-all.
- Add a specific assertion in C-02 tests: after injecting `HTTPS_PROXY=http://127.0.0.1:<port>`,
  the sandboxed process can open a TCP connection to 127.0.0.1:<port> and to no other address.

---

### Pitfall 7: ETW — Observing Without Admin Fails Silently

**Phase:** D (ETW Learn)
**What goes wrong:** `StartTrace` or `EnableTraceEx2` for `Microsoft-Windows-Kernel-File` and
`Microsoft-Windows-Kernel-Network` is called without administrator privileges. The call returns
`ERROR_ACCESS_DENIED` (5). If the error check is absent or the error is logged but execution
continues, `nono learn` produces an empty output — zero paths recorded — and exits 0.

**Why it happens:** Kernel ETW providers require the caller to hold `SeSystemProfilePrivilege`
(or be SYSTEM/Administrator). This is not a soft requirement — the providers simply do not emit
events to non-admin consumers.

**Security implication:** A non-admin `nono learn` run appears to succeed but captures nothing.
If the output is used to generate a profile, the resulting profile is empty, which means no
paths are allowed and the agent runs in a maximally-restricted (potentially broken) sandbox.
This is a correctness failure but not a security escalation.

**Prevention:**
- Check admin status at the start of `learn.rs` for the Windows path using
  `OpenProcessToken` + `GetTokenInformation(TokenElevation)` before opening any ETW trace.
- On non-admin, return `NonoError::UnsupportedPlatform("nono learn on Windows requires
  administrator privileges. Re-run from an elevated prompt.")` — not just a warning.
- Do not log-and-continue. The success criterion (LEARN-01, criterion 3) explicitly requires a
  clear actionable error.

**Detection:** `nono learn notepad.exe` produces empty output and exits 0 without an error message.

---

### Pitfall 8: ETW — PID Filter Race: Child Events Before Trace Session Is Active

**Phase:** D (ETW Learn, D-02)
**What goes wrong:** The child process is spawned before the ETW trace session is fully
established. File I/O events from the child's startup (loading DLLs, reading config) occur in
the window between `CreateProcess` and `ProcessTrace` becoming active. These events are lost.

**Why it happens:** ETW uses a buffered, asynchronous delivery model. `StartTrace` + `EnableTraceEx2`
does not guarantee that events generated immediately after the call are captured. The kernel
buffers have a minimum latency before consumer callbacks begin receiving events.

**Consequence:** The learn output is missing paths accessed during process startup (e.g., system
DLL directories, CRT paths). This makes generated profiles incomplete. For agents that read
configuration at startup, the profile may be missing their config directory.

**Prevention:**
- Establish the ETW trace session and verify it is receiving events BEFORE spawning the child.
  One approach: use a process-create event from the `Microsoft-Windows-Kernel-Process` provider
  as a synchronization point — wait for the child's PID to appear in a CreateProcess event
  before marking the trace as "active".
- Alternatively, use `CREATE_SUSPENDED`, establish the trace, then `ResumeThread`. This
  narrows the race to the thread-resume latency.
- Document that some startup events may still be missed and that the learn output represents
  steady-state access patterns, not guaranteed complete coverage. This matches the Unix strace
  behavior (strace also attaches post-exec sometimes).

**Detection:** Compare `nono learn` output on Windows vs Linux for the same command. Missing
system library paths (e.g., `C:\Windows\System32\ntdll.dll`) indicate the race is occurring.

---

### Pitfall 9: ETW — Kernel File Path Reconstruction

**Phase:** D (ETW Learn, D-02)
**What goes wrong:** ETW `Microsoft-Windows-Kernel-File` events report file paths in the
NT namespace format (`\Device\HarddiskVolume3\Users\...`), not the Win32 path format
(`C:\Users\...`). If paths are emitted directly to the learn output, they cannot be matched
against nono policy paths (which are Win32 format), and the output is useless.

**Why it happens:** The Windows kernel internally uses NT object namespace paths. The ETW
provider emits what the kernel sees. Translation to drive letters requires `QueryDosDevice` or
`GetLogicalDriveStrings` + `QueryDosDevice` for each volume.

**Prevention:**
- Build a volume → drive-letter mapping table at trace startup using `GetLogicalDriveStringsW`
  followed by `QueryDosDeviceW` for each drive letter. Cache the table for the duration of the
  trace.
- For each file path in an ETW event, iterate the volume map and replace the NT device prefix
  with the corresponding drive letter.
- Handle the case where a volume has no drive letter (e.g., mounted volumes, WSL drives). Log
  these paths as-is with a prefix marker so they are visible but not confused with Win32 paths.
- The output format must match the Unix learn output exactly (success criterion 2 of LEARN-01).
  Run cross-platform tests with the same binary and compare path format.

**Detection:** Learn output contains paths starting with `\Device\HarddiskVolume` instead of `C:\`.

---

### Pitfall 10: Runtime Capability Expansion — Session Token Passed as Plain Env Var

**Phase:** E (Runtime Capability Expansion)
**What goes wrong:** The session token is injected into the child process as a plain environment
variable (e.g., `NONO_SESSION_TOKEN`). The sandboxed child (or any subprocess spawned by it) can
read this variable, extract the token, and use it to request arbitrary capabilities from the
supervisor without user interaction.

**Why it happens:** Environment variables in a process are readable by the process itself and by
any child spawned with `INHERIT_ENV`. In a sandboxed agent scenario, the agent IS the child, so
this is expected — but it also means any code the agent runs (e.g., shell scripts, tools invoked
via `exec`) inherits the token and can escalate.

**Security implication:** A compromised or malicious agent can enumerate what capabilities it can
request (the request schema is public) and request all of them. If the supervisor's
`TerminalApproval` is automated or bypassed by the user, the session token provides an unlimited
escalation path. The session token must be scoped, single-use, or rate-limited.

**Prevention:**
- The token MUST be validated on the supervisor side before any capability is granted (TRUST-01,
  success criterion 3 explicitly requires this).
- Token generation must use `generate_session_token()` from `nono-proxy/src/token.rs` (already
  uses `getrandom::fill` + hex encoding for cryptographic randomness). Verify this is wired.
- Token comparison MUST use constant-time equality (`constant_time_eq` already exists in
  `nono-proxy/src/token.rs`). Never use `==` for token comparison.
- The existing `WindowsSupervisorDenyAllApprovalBackend` must remain the default when Phase E
  is not active. The `extensions_enabled()` check in `sandbox/windows.rs` must only be removed
  when Phase E is fully validated.
- Do NOT log the session token value. It appears in structured tracing output if logged at the
  `debug!` or `trace!` level by accident.
- Consider adding request-rate limiting in the supervisor event loop: deny any session that
  submits more than N capability requests per minute (prevents enumeration attacks).

**Detection:** Supervisor grants a capability request that was never shown to the user.

---

### Pitfall 11: Runtime Capability Expansion — Replay Attack on Named Pipe

**Phase:** E (Runtime Capability Expansion)
**What goes wrong:** A malicious subprocess records a `RequestCapability` message that was
approved by the user, then replays it to request the same capability again (or a different
capability if the request_id is not validated). The supervisor grants the replay without
prompting the user.

**Why it happens:** Named pipes are byte streams; messages do not have built-in replay
protection. The `SupervisorMessage` enum uses `request_id` fields, but the supervisor must
actively check that each `request_id` has not been seen before.

**Security implication:** One user approval could be replayed to grant the same capability to
arbitrary subsequent code paths without the user's knowledge.

**Prevention:**
- The supervisor must maintain a `HashSet<String>` of seen `request_id` values for the session.
  The existing Unix supervisor already uses `MAX_TRACKED_REQUEST_IDS` and a `HashSet` for this
  purpose (see `exec_strategy.rs`). Apply the same pattern to the Windows supervisor event loop
  in Phase E.
- Use the same `MAX_TRACKED_REQUEST_IDS = 4096` cap to prevent memory exhaustion from a
  request-id flood.
- Request IDs must be generated by the supervisor (or validated as cryptographically random)
  to prevent the child from predicting the next accepted ID.

**Detection:** Two capability grants appear in audit logs with the same `request_id`.

---

## Moderate Pitfalls

### Pitfall 12: nono wrap — Behavioral Difference Not Documented (UX Confusion)

**Phase:** A (Quick Wins, A-01)
**What goes wrong:** A user familiar with Unix `nono wrap` expects the CLI process to be replaced
via `exec` (exec-replace). On Windows, Direct strategy uses `CreateProcessW` + `WaitForSingleObject`,
so the nono CLI process stays alive as the Job Object owner. Scripts that parse process lists or
check whether nono is still running will see two processes instead of one.

**Why it happens:** Windows has no equivalent to `execve`. The CLI process must stay alive to
maintain the Job Object — if the supervisor exits, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` kills
the child.

**Consequence:** Not a security issue but a reliable source of user confusion and automation
breakage. Shell scripts that do `nono wrap <cmd> && other_cmd` work differently on Windows.

**Prevention:**
- Update the help text for `nono wrap` on Windows (in the CLI argument definition) to explicitly
  say: "On Windows, nono wrap keeps the supervisor alive as Job Object owner. This is different
  from Unix, where nono wrap replaces the CLI process."
- The `validate_preview_entry_point(Wrap, ...)` function currently returns
  `UnsupportedPlatform`. Phase A-01 removes this block. Ensure the new code path adds the help-
  text note rather than just removing the error.

---

### Pitfall 13: Proxy Credential Injection — HTTPS_PROXY Visible in Child Environment

**Phase:** C (Proxy Filtering, C-02)
**What goes wrong:** `HTTPS_PROXY=http://127.0.0.1:<port>` is injected into the child's
environment. Any subprocess spawned by the child (tools, shells, scripts) inherits this
variable. A malicious tool in the sandbox can read `HTTPS_PROXY` to discover the proxy port
and potentially craft direct requests to the proxy bypassing credential validation.

**Why it happens:** Environment variables in inherited child processes are readable by definition.
The proxy token is injected as `NONO_PROXY_TOKEN` alongside `HTTPS_PROXY`.

**Security implication:** Knowing the proxy port is not itself an escalation — the proxy still
validates the `NONO_PROXY_TOKEN` using constant-time comparison (the existing `validate_proxy_auth`
in `nono-proxy`). However, a sandboxed process can enumerate the proxy port and attempt to use
it as an exfiltration channel if the proxy's domain filter is not strict.

**Prevention:**
- The WFP localhost permit filter must restrict access to ONLY the proxy port, not all of
  localhost. This is already the design intent (`localhost_port_allowlist` in the IPC contract).
  Verify that the WFP filter created in C-02 specifies the exact port, not `0.0.0.0:0`.
- Confirm that the proxy's domain allowlist is enforced even for connections authenticated with
  a valid `NONO_PROXY_TOKEN`. The proxy is the last line of defense if WFP is bypassed.

---

### Pitfall 14: WFP IPC Contract Version Bump — Deserialization Mismatch

**Phase:** C (C-01)
**What goes wrong:** The `WfpRuntimeActivationRequest` struct gains new optional fields
(`ProxyOnly`, port allowlists). The `nono-wfp-service` binary is not updated (or an old version
is running). Serde deserializes the new request; unknown fields are silently ignored if
`#[serde(deny_unknown_fields)]` is absent. The service processes the request as if it were a
v1 request — no port filters are installed, but no error is returned.

**Why it happens:** Serde by default ignores unknown fields during deserialization. The service
returns `status: "ok"` and `details: ""` because the v1 code path completed successfully. The
caller believes port filtering is active when it is not.

**Security implication:** The service silently reverts to block-all-only mode without port
permits. This is fail-closed (safer), but it causes a functional regression for legitimate
allowlisted ports. More critically, if `ProxyOnly` mode is requested, the service does not
install the proxy permit, so the agent cannot reach its proxy at all.

**Prevention:**
- The `protocol_version` field already exists in `WfpRuntimeActivationRequest`. The service
  MUST validate this field first: if `protocol_version != WFP_RUNTIME_PROTOCOL_VERSION`, return
  an error response immediately (not `status: "ok"`).
- Bump `WFP_RUNTIME_PROTOCOL_VERSION` from 1 to 2 in C-01.
- Add `#[serde(deny_unknown_fields)]` to the RESPONSE struct (not request — requests may gain
  fields, responses should be exact).
- The open question from the roadmap (IPC versioning for both gaps in a single bump) means both
  port allowlists and proxy fields must be part of the v2 schema. Design both before bumping.

---

### Pitfall 15: Named Pipe Visibility for Low Integrity Child (Existing Risk, New Surface)

**Phase:** A, B, E (any Windows execution that uses named-pipe IPC)
**What goes wrong:** The nono supervisor pipe (`\\.\pipe\nono-session-<id>`) is accessible only
to medium-integrity processes. The sandboxed child runs at Low Integrity (enforced via
`SetTokenInformation(TokenIntegrityLevel, WinLowLabelSid)`). Low Integrity processes cannot
write to objects without a Mandatory Label that allows Low writes.

**Why it happens:** The existing pipe SDDL (`D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;OW)`) in
`PIPE_SDDL` (nono-wfp-service) grants access to SYSTEM, Administrators, and owner. It does not
include a Mandatory Label permitting Low Integrity writes.

**Consequence:** A Low Integrity child process cannot send `SupervisorMessage` requests over the
named pipe. Runtime capability expansion (Phase E) is broken for sandboxed children.

**Prevention:**
- For supervisor IPC pipes that the sandboxed child must write to, the SDDL must include a
  Mandatory Label ACE: `S:(ML;;NW;;;LW)` ("No-Write-Up" from Low Integrity).
  The `NW` flag is the correct flag — it allows Low IL processes to write to this object
  without being considered a "write-up" (integrity elevation).
- This was identified as a critical pitfall in the v1.0 research. Verify that `socket_windows.rs`
  `create_named_pipe` adds the correct Mandatory Label when the pipe is intended for
  Low Integrity clients.
- The control pipe in `nono-wfp-service.rs` uses `PIPE_SDDL` (admin/SYSTEM only) — that is
  correct because only the supervisor talks to the WFP service. The per-session supervisor pipe
  used for capability expansion needs different ACLs.

---

### Pitfall 16: WFP Orphan Filters After Supervisor Crash

**Phase:** C (WFP Port + Proxy)
**What goes wrong:** The supervisor crashes before cleanup. Dynamic WFP filters (tied to the WFP
engine session handle) are deleted automatically by BFE when the handle closes. However, if the
nono-wfp-service also crashes, static filters survive and continue to block all network access
for any subsequent process matching the SID.

**Why it happens:** The startup orphan sweep in `nono-wfp-service.rs` already handles this for
v1.0 block-all filters. New per-port permit filters added in Phase C must also be swept.

**Prevention:**
- The sweep logic in `run_startup_sweep()` enumerates all filters in the nono sublayer. Per-port
  filters added in Phase C will be in the nono sublayer and will be swept automatically — no
  code change needed IF the naming convention is consistent (filter names include the session ID
  and the word "nono").
- Verify the sweep test in `nono-wfp-service.rs` covers the new per-port filter names. Add a
  test case specifically for orphaned per-port filters.

---

## Minor Pitfalls

### Pitfall 17: ferrisetw License and Maintenance Risk

**Phase:** D (ETW Learn, D-01)
**What goes wrong:** `ferrisetw` is Apache-2.0 licensed (compatible) but last released in 2023.
If ETW event schemas change in a future Windows update, `ferrisetw` may not be updated and the
learn output silently degrades (missing events, incorrect field offsets).

**Prevention:**
- Evaluate `ferrisetw` vs direct `windows-sys` ETW bindings in D-01 as the roadmap requires.
- If `ferrisetw` is chosen, vendor the dependency or pin an exact version with a recorded
  hash. Do not use a `^` (caret) version constraint.
- Document the decision with a date in the D-01 plan summary and flag it for review in v3.0.

---

### Pitfall 18: ConPTY Pipe Handle Ordering in Drop

**Phase:** B (ConPTY Shell)
**What goes wrong:** Handles are closed in the wrong order in `PtyPair::Drop`, causing conhost
to hang waiting for a reader to close before it exits.

**Prevention:**
- Required close order: (1) `ClosePseudoConsole(hpcon)`, (2) `CloseHandle(input_write)`,
  (3) `CloseHandle(output_read)`.
- The existing `PtyPair` Drop impl (in `pty_proxy_windows.rs`) already follows this order.
  Do not reorder during Phase B-02 I/O relay changes.

---

### Pitfall 19: ETW Kernel-Network Event Schema Differences Between Windows Versions

**Phase:** D (ETW Learn, D-03)
**What goes wrong:** `Microsoft-Windows-Kernel-Network` `TcpIp/Connect` event field offsets and
types differ between Windows 10 1809 and Windows 11 22H2. A hardcoded field offset for the
remote address field produces garbage IP addresses on one version.

**Prevention:**
- Use the provider's manifest (parse via TDH: `TdhGetEventInformation`) to look up field offsets
  at runtime rather than hardcoding them. `ferrisetw` does this automatically; direct `windows-sys`
  ETW bindings require calling `TdhGetEventInformation`.
- Validate output against the Windows version matrix (success criterion 5 of LEARN-01 explicitly
  requires this). Test on Windows 10 1809 AND Windows 11 22H2 (the two primary version targets).

---

## Phase-Specific Warning Summary

| Phase | Feature | Pitfall | Priority |
|-------|---------|---------|----------|
| A | `nono wrap` | Behavioral difference not documented (Pitfall 12) | Low |
| A | Session commands | None — straightforward read from session records | — |
| B-01 | ConPTY spawn | STARTUPINFOEXW not used (Pitfall 1) | Critical |
| B-01 | ConPTY spawn | No build version check (Pitfall 2) | Critical |
| B-01 | ConPTY + Job | conhost outside Job Object (Pitfall 3) | Moderate |
| B-02 | ConPTY I/O | Ctrl-C kills supervisor (Pitfall 4) | Critical |
| B-02 | ConPTY I/O | Handle close ordering (Pitfall 18) | Minor |
| C-01 | WFP IPC | Version mismatch silent degradation (Pitfall 14) | Moderate |
| C-02 | Proxy filter | Proxy port permit below block-all (Pitfall 6) | Critical |
| C-02 | Proxy inject | HTTPS_PROXY visible to subprocesses (Pitfall 13) | Moderate |
| C-03 | Port filter | Permit weight below block-all (Pitfall 5) | Critical |
| C | All WFP | Orphan filters after crash (Pitfall 16) | Moderate |
| D-01 | ETW | ferrisetw maintenance risk (Pitfall 17) | Minor |
| D-01 | ETW | Admin check absent — silent empty output (Pitfall 7) | Critical |
| D-02 | ETW | PID filter race at child startup (Pitfall 8) | Moderate |
| D-02 | ETW | NT path not translated to Win32 path (Pitfall 9) | Critical |
| D-03 | ETW | Field schema version differences (Pitfall 19) | Minor |
| E | Runtime caps | Session token escalation (Pitfall 10) | Critical |
| E | Runtime caps | Replay attack on named pipe (Pitfall 11) | Critical |
| A/B/E | Named pipe | Low Integrity child cannot write to pipe (Pitfall 15) | Moderate |

---

## Retained v1.0 Pitfalls (Still Relevant)

### Named Pipe Visibility and Security (AppContainer)
Pipe names must use `LOCAL\` prefix. SDDL must include `S:(ML;;NW;;;LW)` for any pipe that
Low Integrity clients must write to. `FILE_FLAG_FIRST_PIPE_INSTANCE` prevents squatting.
See Phase E (Pitfall 15) for the specific v2.0 surface.

### WFP Rule Lifecycle
Dynamic filters auto-deleted on BFE handle close. The nono-wfp-service must stay alive for
the session duration. Startup sweep handles orphans. Per-port filters in Phase C are covered by
the existing sweep (Pitfall 16).

### Atomic Snapshots and Locked Files
No new surface in v2.0 (snapshot/rollback is complete from v1.0). Remains relevant if any
Phase B session record writes race with file lock.

### Path Normalization
`std::fs::canonicalize` normalizes paths on Windows. Case-insensitive comparison is required
for all policy path matching. No new surface in v2.0, but ETW path reconstruction (Pitfall 9)
adds a new form of this: NT namespace vs Win32 namespace.

---

## Sources

- Windows ConPTY documentation: https://docs.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session
- `CreatePseudoConsole` API requirements: https://docs.microsoft.com/en-us/windows/console/createpseudoconsole
- ETW `Microsoft-Windows-Kernel-File` provider GUIDs: internal Microsoft documentation, GUID `EDD08927-9CC4-4E65-B970-C2560FB5C289` (referenced in WINDOWS-V2-ROADMAP.md Phase D)
- WFP filter weight ordering: https://docs.microsoft.com/en-us/windows/win32/fwp/filter-weight-identifiers
- Named pipe security and integrity levels: https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- `RtlGetVersion` vs `GetVersionEx`: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion
- Existing codebase: `crates/nono-cli/src/pty_proxy_windows.rs`, `crates/nono-cli/src/bin/nono-wfp-service.rs`, `crates/nono/src/supervisor/socket_windows.rs`, `crates/nono/src/sandbox/windows.rs`
