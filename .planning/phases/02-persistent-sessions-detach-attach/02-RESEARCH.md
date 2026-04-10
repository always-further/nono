# Phase 2: Persistent Sessions (Detach/Attach) - Research

**Researched:** 2026-04-04
**Domain:** Windows Process Management, ConPTY, Named Pipe IPC, Daemonization
**Confidence:** HIGH

## Summary

Phase 2 focuses on enabling background agent execution on Windows with functional parity to Unix PTY systems. The core challenge is decoupling the agent's lifecycle from the initiating terminal session while maintaining interactive I/O capabilities and security. This is achieved through a "Double-Launch" daemonization pattern, the modern Win32 ConPTY API for terminal emulation, and secured Named Pipe IPC for control and data streaming.

**Primary recommendation:** Use a manual ConPTY implementation via `windows-sys` for maximum control and minimal dependencies, secured with specific SDDLs on Named Pipes to ensure owner-only access.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **Terminal Emulation (ConPTY):** Use the modern Win32 **ConPTY (PseudoConsole)** API for true functional parity with Unix PTYs.
- **Strategy:** Implement directly via `windows-sys` (features: `Win32_System_Console`, `Win32_System_Pipes`) to keep the dependency tree lean.
- **Supervisor Persistence (Double-Launch):** Use a "Double-Launch" pattern to daemonize the supervisor.
- **IPC Mechanism:** Use a **Dual-Pipe Architecture** for IPC:
    - **Control Pipe:** `\\.\pipe\nono-session-{id}` for structured management messages.
    - **Data Pipe:** `\\.\pipe\nono-data-{id}` for raw byte streaming (ConPTY input/output).
- **Scrollback:** Implement **File-backed logging** in `~/.nono/sessions/{id}.log`.
- **Security:** SDDL security descriptors must be applied to both Named Pipes to ensure owner-only access.

### the agent's Discretion
- **Implementation details of the "Double-Launch" pattern.**
- **Exact SDDL string configuration.**
- **Asynchronous I/O orchestration using Tokio.**

### Deferred Ideas (OUT OF SCOPE)
- **Window Resizing:** Propagating terminal size changes.
- **Input Sanitization:** Detailed filtering of ANSI escape sequences.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SUPV-01 | User can detach from a running Windows agent using `nono run --detach`. | Double-Launch pattern and `DETACHED_PROCESS` flag findings. |
| SUPV-02 | User can re-attach to a running Windows agent session via Named Pipe IPC. | Dual-Pipe architecture and secured Named Pipes with SDDL. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows-sys` | 0.52+ | Low-level Win32 API access | Official, zero-overhead, project standard. |
| `tokio` | 1.35+ | Asynchronous I/O and Named Pipe support | Industry standard for async Rust. |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|--------------|
| `serde_json` | 1.0+ | Session metadata serialization | For `~/.nono/sessions/{id}.json`. |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `windows-sys` | `portable-pty` | Easier but adds 20+ dependencies; project prefers lean `windows-sys`. |
| `windows-sys` | `windows` (crate) | Higher-level but larger binary size and less "raw" control. |

## Architecture Patterns

### Recommended Project Structure
```
crates/nono-cli/src/
├── app_runtime.rs       # Entry point for session management
├── session_runtime.rs   # Logic for attach/detach/list
├── pty_proxy_windows.rs # ConPTY orchestration (Manual implementation)
├── supervisor/
│   ├── mod.rs           # Supervisor entry and daemonization logic
│   └── ipc_windows.rs   # Named Pipe server and SDDL handling
└── execution_runtime.rs # Updated to support Detached strategy
```

### Pattern 1: Double-Launch Daemonization
**What:** CLI spawns an Intermediate process which spawns the final Supervisor and then both exit.
**When to use:** To break process group and job object inheritance.
**Example:**
```rust
// Phase findings: Use these flags for true detachment
const DETACHED_PROCESS: u32 = 0x00000008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x01000000;

// Step 1: CLI -> Intermediate (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
// Step 2: Intermediate -> Supervisor (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB)
```

### Pattern 2: Secured Named Pipe Server (Tokio)
**What:** Create an async Named Pipe server with restricted permissions.
**Example:**
```rust
// Use SDDL to restrict access to Current User, System, and Admins
let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";
// Use ServerOptions::create_with_security_attributes_raw()
```

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SDDL Parsing | Custom regex/string parser | `ConvertStringSecurityDescriptorToSecurityDescriptorW` | Extremely complex security logic; Win32 has a native, audited parser. |
| Terminal Emulation | Custom VT100 parser | ConPTY (`CreatePseudoConsole`) | Windows terminal behavior is notoriously difficult to replicate manually. |
| Async Pipes | Manual Threaded I/O | `tokio::net::windows::named_pipe` | High-performance, tested async implementation. |

## Runtime State Inventory

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | `~/.nono/sessions/{id}.log` | Create/Write/Tail (Scrollback) |
| Stored data | `~/.nono/sessions/{id}.json` | Create/Write (Metadata/Registry) |
| OS-registered state | `\\.\pipe\nono-session-{id}` | Named Pipe registration |
| OS-registered state | `\\.\pipe\nono-data-{id}` | Named Pipe registration |
| Build artifacts | `nono.exe` | No change required (existing CLI) |

## Common Pitfalls

### Pitfall 1: Handle Inheritance Deadlocks
**What goes wrong:** Child processes inherit the pipe handles used by ConPTY.
**Why it happens:** Default `CreateProcess` behavior can inherit all open handles.
**How to avoid:** Explicitly set `bInheritHandle = FALSE` in `SECURITY_ATTRIBUTES` for pipes and ensure the `STARTUPINFOEXW` handles are correctly scoped.

### Pitfall 2: ConPTY Hang on Close
**What goes wrong:** `ClosePseudoConsole` hangs indefinitely.
**Why it happens:** Pending read/write operations on the pipes on older Windows 10 versions.
**How to avoid:** Close the pipe handles *before* calling `ClosePseudoConsole`, or perform the closure on a separate background thread.

### Pitfall 3: Breakaway Denied
**What goes wrong:** `CREATE_BREAKAWAY_FROM_JOB` fails with "Access Denied".
**Why it happens:** The parent process is in a Job Object that does not allow breakaway (`JOB_OBJECT_LIMIT_BREAKAWAY_OK`).
**How to avoid:** Fallback to normal detached process if breakaway is forbidden, or detect job restrictions early via `IsProcessInJob`.

## Code Examples

### ConPTY Initialization (Manual)
```rust
// Source: https://docs.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session
// 1. Create pipes (Non-inherited)
// 2. CreatePseudoConsole(size, h_in, h_out, 0, &mut h_pcon)
// 3. InitializeProcThreadAttributeList + UpdateProcThreadAttribute
// 4. CreateProcessW with EXTENDED_STARTUPINFO_PRESENT
```

### Secured Named Pipe (Tokio + SDDL)
```rust
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{SDDL_REVISION_1, SECURITY_ATTRIBUTES};
use tokio::net::windows::named_pipe::ServerOptions;

unsafe fn create_secure_pipe(name: &str) -> Result<ServerOptions, NonoError> {
    let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)\0";
    let mut sd_ptr = std::ptr::null_mut();
    
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl.as_ptr() as *const _,
        SDDL_REVISION_1,
        &mut sd_ptr,
        std::ptr::null_mut(),
    );

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd_ptr,
        bInheritHandle: 0,
    };

    Ok(ServerOptions::new().create_with_security_attributes_raw(name, &mut sa as *mut _ as *mut _))
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| WinPTY | ConPTY | Win10 1809 | Native, high-performance, no external DLLs needed. |
| Service-based daemon | Double-Launch | N/A | No administrative rights needed for installation. |

## Open Questions

1. **Named Job Objects Ownership:** If the supervisor exits unexpectedly, who cleans up the Job Object?
   - **Recommendation:** Named Job Objects on Windows persist until the last handle is closed. The supervisor should hold a handle, and the agent processes are *in* it. If both exit, it clears automatically.
2. **UTF-8 in ConPTY:** ConPTY expects UTF-8, but some Windows versions have quirks.
   - **Recommendation:** Use `SetConsoleCP(65001)` and `SetConsoleOutputCP(65001)` in the child process if needed.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Windows 10 | ConPTY / WFP | ✓ | 1809+ | Legacy WinPTY (Descope) |
| kernel32.dll | ConPTY APIs | ✓ | — | — |
| Named Pipes | IPC | ✓ | — | — |

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | cargo test (Rust) |
| Config file | None |
| Quick run command | `cargo test -p nono-cli` |
| Full suite command | `make test` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SUPV-01 | Spawn detached process | Integration | `tests/integration/test_detach.sh` | ❌ Wave 0 |
| SUPV-02 | Attach to named pipe | Integration | `tests/integration/test_attach.sh` | ❌ Wave 0 |

## Sources

### Primary (HIGH confidence)
- [Microsoft Docs: Creating a PseudoConsole session](https://docs.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session)
- [Tokio Documentation: Named Pipe ServerOptions](https://docs.rs/tokio/latest/tokio/net/windows/named_pipe/struct.ServerOptions.html)
- [Microsoft Docs: SDDL for Security Descriptors](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Aligns with project and Win32 standards.
- Architecture: HIGH - Proven daemonization and IPC patterns for Windows.
- Pitfalls: HIGH - Well-documented Win32 edge cases.

**Research date:** 2026-04-04
**Valid until:** 2026-05-04
