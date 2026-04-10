# Phase 3 Validation: Network Sandboxing (WFP Integration)

## Goal Achievement

Implement robust, kernel-level network enforcement on Windows using WFP and Restricted Tokens, providing "Structural Impossibility" for network bypass.

### Requirements Mapping
- **NETW-01**: Block all network access for sandboxed processes using Session SID filtering.
- **NETW-02**: Ensure rules persist across detach/attach cycles via the `nono-wfp-service`.
- **NETW-03**: Allow specific ports (TCP connect/bind) while blocking all other traffic.

### Verification Strategy
1. **Unit Tests**:
   - SID string to Security Descriptor conversion.
   - Restricted Token creation with SID assignment.
   - Named Pipe IPC serialization/deserialization.
2. **Integration Tests**:
   - `test_network_wfp.sh`: Use `test-connector` probe to verify BLOCK and PERMIT rules.
   - Verify that child processes spawned by a sandboxed process are also blocked (inheritance test).
3. **Manual Checkpoints**:
   - Verify that stopping `nono-wfp-service` automatically removes all filters (Dynamic Session check).
   - Verify that an elevated `nono-wfp-service` is required for enforcement.

### Success Criteria
- [ ] Sandboxed process cannot connect to external IPs (e.g., 8.8.8.8) when blocked.
- [ ] Sandboxed process can connect to allowed ports.
- [ ] Child processes of the sandboxed process inherit the same restrictions.
- [ ] Rules are automatically cleaned up when the service exits.
- [ ] Named Pipe control channel is secured.
