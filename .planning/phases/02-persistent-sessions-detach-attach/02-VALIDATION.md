# Phase 2 Validation: Persistent Sessions (Detach/Attach)

## Goal Achievement

Enable long-running agent support with persistent background monitoring on Windows.

### Requirements Mapping
- **SUPV-01**: User can detach from a running Windows agent using `nono run --detach`.
- **SUPV-02**: User can re-attach to a running Windows agent session via Named Pipe IPC.

### Verification Strategy
1. **Automated Unit Tests**:
   - ConPTY lifecycle management (creation/cleanup).
   - SDDL security on Named Pipes.
   - Session registry updates for detached sessions.
2. **Integration Tests**:
   - `scripts/tests/test_windows_detach.ps1`: Verify background supervisor survival after CLI exit.
   - `scripts/tests/test_windows_attach.ps1`: Verify scrollback retrieval and live I/O re-attachment.
3. **Manual Checkpoints**:
   - Verify interactive input/output behavior in a re-attached session.
   - Verify session survival after terminal closure.

### Success Criteria
- [ ] ConPTY correctly initializes and captures agent output.
- [ ] Supervisor survives parent terminal exit via Double-Launch.
- [ ] Named Pipes are secured with owner-only access.
- [ ] `nono attach` restores terminal output from disk logs and switches to live streaming.
- [ ] `nono detach` and escape sequence successfully disconnect without stopping the agent.
