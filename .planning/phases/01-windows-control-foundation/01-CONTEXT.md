# Phase 1 Context: Windows Control Foundation

## Goal
Establish robust process lifecycle management and session discovery on Windows using Job Objects and Named Pipe IPC.

## Implementation Decisions

### 1. Job Object Naming & Discovery
- **Naming Strategy:** Use named Job Objects for all Windows sessions.
- **Namespace:**
    - Default: `Local\nono-session-{id}` (User session, no Admin required).
    - Override: Provide internal support for `Global\nono-session-{id}` (requires Admin/`SeCreateGlobalPrivilege`).
- **ID Format:** 16-character Hex string (e.g., `nono-session-a3f7c2`).
- **Discovery:** `nono ps` will use a "File-First, Object-Verified" approach. It reads `.json` session records from `~/.nono/sessions/` and attempts to `OpenJobObjectW` using the ID to verify liveness.
- **Zombie Cleanup:** `nono ps` will automatically mark sessions as `Exited` (exit code -1) if the named Job Object is no longer present in the kernel.

### 2. `nono stop` Strategy (Hybrid)
- **Primary (Polite):** Send a `Terminate` request via Named Pipe IPC to the supervisor process.
- **Secondary (Forced):** If the IPC call fails or the process does not exit within a 5-second timeout, call `TerminateJobObject()` on the named job.
- **Rationale:** Aligns with the Unix `SIGTERM` -> `SIGKILL` escalation.

### 3. `setup --check-only` Enhancements
- **Job Object Permissions:** Verify the current user can create and name Job Objects in the `Local\` namespace.
- **Integrity Level Support:** Verify the capability to lower process token integrity (required for Low-Integrity filesystem sandboxing).
- **WFP Service Readiness:** Explicitly check if the WFP placeholder service and driver are `RUNNING`, not just installed.

### 4. Codebase Patterns
- **Registry:** Continue using `~/.nono/sessions/` for metadata persistence.
- **Safety:** Maintain current "fail-closed" logic for all Windows API calls.
- **FFI:** Leverage existing `windows-sys` features in `nono-cli/Cargo.toml`.

## Out of Scope for Phase 1
- **Detach/Attach:** Persistent background supervisor monitoring (deferred to Phase 2).
- **Network Enforcement:** Kernel-level WFP rule application (deferred to Phase 3).
- **Filesystem Rollback:** Merkle-tree snapshots (deferred to Phase 4).
