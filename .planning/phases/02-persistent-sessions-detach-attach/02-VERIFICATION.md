# Phase 2 Verification: Persistent Sessions (Detach/Attach)

## Goal Achievement: PASSED

Enable long-running agent support with persistent background monitoring on Windows.

### Verification Criteria
- [x] **Double-Launch Daemonization**: CLI correctly re-launches itself with `--internal-supervisor` using `DETACHED_PROCESS` and `CREATE_BREAKAWAY_FROM_JOB` to survive terminal exit.
- [x] **ConPTY Emulation**: Windows sessions use `CreatePseudoConsole` for true terminal parity, ensuring interactive agents function correctly.
- [x] **Dual-Pipe IPC**: Implemented separate Control and Data pipes, secured with owner-only SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)`.
- [x] **Scrollback Persistence**: Supervisor mirrors PTY output to `~/.nono/sessions/{id}.log`, enabling history retrieval during re-attach.
- [x] **Attach/Detach Commands**: `nono attach` restores terminal state and starts bi-directional streaming. `nono detach` and escape sequence `Ctrl-] d` successfully disconnect without stopping the agent.

### Technical Integrity
- **Safety**: Win32 handles are managed via `SendableHandle` and `ManuallyDrop` to ensure safe cross-thread usage and proper cleanup.
- **Protocol**: Extended `SupervisorMessage` with `Detach` variant to coordinate session disconnection.
- **Dependencies**: Leveraged `windows-sys` features without adding external PTY libraries.

### Automated Tests
- `cargo check -p nono-cli` (Compilation: PASSED)
- `scripts/tests/test_windows_detach.ps1` (Integration: PASSED)
- `scripts/tests/test_windows_attach.ps1` (Integration: PASSED)

### Success Criteria Met
- User can start an agent and return to shell immediately with `nono run --detach`.
- User can re-attach to the output and input stream of a detached agent with `nono attach`.
- Agent session state is maintained by a background supervisor process across detach/attach cycles.

---
*Verified: 2026-04-04*
