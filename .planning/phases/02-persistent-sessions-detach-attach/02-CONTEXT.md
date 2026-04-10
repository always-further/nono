# Phase 2 Context: Persistent Sessions (Detach/Attach)

## Goal
Enable long-running agent support with persistent background monitoring on Windows, allowing users to safely detach from and re-attach to active sessions.

## Implementation Decisions

### 1. Terminal Emulation (ConPTY)
- **Strategy:** Use the modern Win32 **ConPTY (PseudoConsole)** API for true functional parity with Unix PTYs.
- **Dependency:** Implement directly via `windows-sys` (features: `Win32_System_Console`, `Win32_System_Pipes`) to keep the dependency tree lean.
- **Interaction:** ConPTY will ensure interactive agents (color, spinners, prompts) behave correctly.
- **Resizing:** Window resizing support is **deferred** to a later milestone; initial implementation will use a fixed standard terminal size (e.g., 80x24).

### 2. Supervisor Persistence (Double-Launch)
- **Strategy:** Use a "Double-Launch" pattern to daemonize the supervisor.
- **Mechanism:**
    1. CLI starts and re-launches itself with a hidden internal flag (e.g., `--internal-supervisor`).
    2. The second process is created using the `DETACHED_PROCESS` Win32 flag.
    3. The detached supervisor process becomes the primary owner of the named Job Object and IPC pipes.
- **Rationale:** Ensures the supervisor is completely decoupled from the parent console session and outlives the initiating terminal.

### 3. I/O & Multiplexing (Dual Pipes + File Logging)
- **Streaming:** Use a **Dual-Pipe Architecture** for IPC:
    - **Control Pipe:** `\\.\pipe\nono-session-{id}` for structured management messages (Stop, Status, etc.).
    - **Data Pipe:** `\\.\pipe\nono-data-{id}` for raw byte streaming (ConPTY input/output).
- **Scrollback:** Implement **File-backed logging**:
    - Supervisor writes all ConPTY output to `~/.nono/sessions/{id}.log`.
    - `nono attach` reads the tail of this log before switching to live streaming from the Data Pipe.

### 4. Codebase Patterns
- **Safety:** SDDL security descriptors must be applied to both Named Pipes to ensure owner-only access.
- **Cleanup:** The detached supervisor is responsible for deleting the session registry file and closing Job Object handles on exit.

## Out of Scope for Phase 2
- **Window Resizing:** Propagating terminal size changes (deferred).
- **Input Sanitization:** Detailed filtering of ANSI escape sequences (deferred).
