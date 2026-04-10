# Phase 1: Windows Control Foundation - Research

**Researched:** 2026-04-04
**Domain:** Windows Process Lifecycle, Job Objects, Named Pipe IPC
**Confidence:** HIGH

## Summary

This phase establishes the foundational process control and session discovery mechanisms for the `nono` agent on Windows. It replicates the robust process tree management of Unix using Windows **Job Objects** and provides a secure, single-user **Named Pipe IPC** for agent control. 

**Primary recommendation:** Use **Named Job Objects** in the `Local\` namespace for session lifecycle tracking and atomicity, paired with **Tokio Named Pipes** for supervisor-cli communication, secured via explicit **SDDL strings**.

<user_constraints>
## User Constraints (from 01-CONTEXT.md)

### Locked Decisions
- **Job Object Naming & Discovery:** 
    - Use named Job Objects for all sessions.
    - Namespace: `Local\nono-session-{id}` (User session, no Admin required).
    - ID Format: 16-character Hex string (e.g., `nono-session-a3f7c2`).
    - Discovery: "File-First, Object-Verified" (JSON in `~/.nono/sessions/` + `OpenJobObjectW`).
    - Zombie Cleanup: Auto-mark as `Exited` if Job Object is missing.
- **`nono stop` Strategy (Hybrid):**
    - Primary: `Terminate` request via Named Pipe IPC to supervisor.
    - Secondary: `TerminateJobObject()` after 5-second timeout.
- **`setup --check-only` Enhancements:**
    - Verify Job Object creation permissions in `Local\` namespace.
    - Verify capability to lower process token integrity.
    - Verify WFP service (`BFE`) status is `RUNNING`.

### the agent's Discretion
- Choice of library versioning for `windows-sys`. (Already pinned to 0.59 in project).
- Exact SDDL string format for Named Pipe security.
- Implementation of "File-First, Object-Verified" logic.

### Deferred Ideas (OUT OF SCOPE)
- Detach/Attach: Persistent background supervisor monitoring (Phase 2).
- Network Enforcement: Kernel-level WFP rule application (Phase 3).
- Filesystem Rollback: Merkle-tree snapshots (Phase 4).
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SUPV-03 | User can list all running Windows agent processes using `nono ps`. | Use `QueryInformationJobObject` with `JobObjectBasicProcessIdList` to verify active PIDs in a named Job Object. |
| SUPV-04 | User can atomically stop a Windows agent and its entire process tree using `nono stop`. | Use `TerminateJobObject` as the definitive forced-stop mechanism. |
| SUPV-05 | Windows Job Objects are named using session IDs to allow persistent management after CLI exit. | Named Job Objects in `Local\` namespace persist as long as a process is attached, even if the creating process exits. |
| DEPL-02 | CLI provides a unified support status report on Windows via `nono setup --check-only`. | Use `OpenSCManagerW` / `QueryServiceStatusEx` for WFP (BFE) check and token integrity probes. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows-sys` | 0.59.0 | Win32 FFI bindings | Official, lightweight, already in project. |
| `tokio` | 1.x | Named Pipe IPC | Standard async runtime with robust Windows support. |
| `serde_json` | 1.0 | Session Metadata | Project standard for filesystem state. |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|--------------|
| `windows-service` | 0.7 | Service Monitoring | Optional: Provides safer wrappers for `setup --check-only` service checks. |

**Installation:**
```toml
# In crates/nono-cli/Cargo.toml
[target.'cfg(target_os = "windows")'.dependencies]
windows-sys = { version = "0.59", features = [
    "Win32_Foundation",
    "Win32_System_JobObjects",
    "Win32_System_Threading",
    "Win32_Security",
    "Win32_System_Services",
    "Win32_System_SystemServices",
    "Win32_Security_Authorization"
] }
```

## Architecture Patterns

### Pattern 1: File-First, Object-Verified Discovery
To list sessions (`nono ps`), the CLI should not iterate all kernel objects (expensive/privileged).
1. Read `~/.nono/sessions/*.json`.
2. Extract the `session_id`.
3. Call `OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, L"Local\\nono-session-{id}")`.
4. If successful, query for the process list to confirm liveness.
5. If `ERROR_FILE_NOT_FOUND`, the session has terminated; mark the file as `Exited`.

### Pattern 2: Secure Single-User IPC
Named Pipes on Windows can be "squatted" by other processes.
- **Prevention:** Always set `PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE` when creating the server.
- **Security:** Use an SDDL string to restrict access to the Owner (current user) only: `D:P(A;;GA;;;OW)(D;;GA;;;WD)`.
- **Integrity:** Use `tokio::net::windows::named_pipe` for async-friendly IPC.

### Anti-Patterns to Avoid
- **PID-only tracking:** Do not rely solely on PIDs for process tree management; child processes can escape or PIDs can be recycled. Always use Job Objects.
- **Manual Handle Closing:** Avoid raw `CloseHandle` calls in business logic; use `OwnedHandle` or scope-guarded abstractions to prevent leaks.
- **Global Namespace:** Do not use `Global\` for Job Objects unless specifically requested (requires Admin). Default to `Local\`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Process Tree Management | Manual PID tracking | Job Objects | Windows natively handles process grouping and atomic termination in Job Objects. |
| String Conversion | Manual `u16` buffers | `windows::core::w!` or `encode_utf16()` helper | Win32 requires null-terminated UTF-16; manual errors lead to buffer overflows or silent failures. |
| IPC Protocol | Raw socket handling | `tokio` Named Pipes | Provides high-level async abstractions for bytes-in-flight. |

## Common Pitfalls

### Pitfall 1: Null-Termination
**What goes wrong:** Win32 `W` functions (e.g., `CreateJobObjectW`) fail or behave unpredictably.
**Why:** Strings must be null-terminated UTF-16 (`Vec<u16>` ending with `0`).
**How to avoid:** Use a helper function to ensure every string passed to FFI is correctly terminated.

### Pitfall 2: Variable-Length Structures
**What goes wrong:** `QueryInformationJobObject` with `JobObjectBasicProcessIdList` returns `ERROR_MORE_DATA` or crashes.
**Why:** The `JOBOBJECT_BASIC_PROCESS_ID_LIST` structure is variable-length. The `ProcessIdList` field is just a header.
**How to avoid:** Perform a two-step query: call with a small buffer to get the count, then allocate a correctly-sized byte vector for the second call.

### Pitfall 3: Job Persistence
**What goes wrong:** Job object disappears when the CLI exits.
**Why:** A Job Object is destroyed when the last handle is closed **AND** all associated processes exit.
**How to avoid:** Ensure at least one agent process is assigned to the Job before the CLI closes its handle. For Phase 1, the agent remains assigned until it exits, keeping the Job alive for `nono ps`.

## Code Examples

### Querying Process IDs in a Job
```rust
// Verified pattern for variable-length Win32 struct
unsafe fn get_pids(h_job: HANDLE) -> Vec<usize> {
    let mut basic_list: JOBOBJECT_BASIC_PROCESS_ID_LIST = std::mem::zeroed();
    let mut returned_len = 0;
    
    // Step 1: Get the count
    QueryInformationJobObject(
        h_job,
        JobObjectBasicProcessIdList,
        &mut basic_list as *mut _ as *mut _,
        std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() as u32,
        &mut returned_len,
    );

    if basic_list.NumberOfAssignedProcesses == 0 { return vec![]; }

    // Step 2: Allocate correctly sized buffer
    let size = std::mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() 
               + (basic_list.NumberOfAssignedProcesses as usize - 1) * std::mem::size_of::<usize>();
    let mut buffer = vec![0u8; size];
    let list_ptr = buffer.as_mut_ptr() as *mut JOBOBJECT_BASIC_PROCESS_ID_LIST;
    (*list_ptr).NumberOfAssignedProcesses = basic_list.NumberOfAssignedProcesses;

    QueryInformationJobObject(
        h_job,
        JobObjectBasicProcessIdList,
        list_ptr as *mut _,
        size as u32,
        &mut returned_len,
    );

    let pids = std::slice::from_raw_parts(
        (*list_ptr).ProcessIdList.as_ptr(),
        (*list_ptr).NumberOfProcessIdsInList as usize
    );
    pids.to_vec()
}
```

### Checking Service Status (setup --check-only)
```rust
unsafe fn is_bfe_running() -> bool {
    let sc_manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
    let service = OpenServiceW(sc_manager, w!("BFE"), SERVICE_QUERY_STATUS);
    
    let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
    let mut needed = 0;
    QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        &mut status as *mut _ as *mut u8,
        std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
        &mut needed,
    );
    
    status.dwCurrentState == SERVICE_RUNNING
}
```

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Job Objects | Lifecycle | ✓ | Win10+ | None (Core feature) |
| BFE Service | WFP Check | ✓ | Running | Warn user |
| windows-sys | FFI | ✓ | 0.59 | — |
| Named Pipes | IPC | ✓ | Win10+ | None |

**Missing dependencies with no fallback:**
- None.

## Sources

### Primary (HIGH confidence)
- Microsoft Docs: [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- Microsoft Docs: [Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- Rust `windows-sys` Crate: [API Bindings](https://docs.rs/windows-sys/latest/windows_sys/)

### Secondary (MEDIUM confidence)
- `tokio` docs for Named Pipe Server examples.
- Community patterns for SDDL strings in Rust/C++.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Directly follows project Cargo.toml and Microsoft official crates.
- Architecture: HIGH - Matches Windows kernel best practices for process management.
- Pitfalls: HIGH - Common C++-to-Rust Win32 issues well-documented.

**Research date:** 2026-04-04
**Valid until:** 2026-05-04
