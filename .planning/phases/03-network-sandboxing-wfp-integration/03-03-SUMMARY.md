# Phase 3, Plan 03 Summary: CLI Integration & Restricted Tokens

## Wave Status: SUCCESS

### Completed Tasks
- **Task 1: Implement Restricted Token creation**
  - Created `crates/nono-cli/src/exec_strategy_windows/restricted_token.rs`.
  - Implemented session-unique SID generation using UUID v4 and custom sub-authority.
  - Implemented `create_restricted_token_with_sid` using Win32 `CreateRestrictedToken`.
- **Task 2: Implement IPC Client in CLI**
  - Updated `crates/nono-cli/src/exec_strategy_windows/network.rs` with `run_wfp_runtime_request`.
  - Implemented `tokio`-based Named Pipe client for policy activation.
- **Task 3: Integrate SID generation and Token in process launch**
  - Refactored `crates/nono-cli/src/exec_strategy_windows/launch.rs` to use `spawn_windows_child`.
  - The new spawn flow automatically generates a session SID, activates WFP via Named Pipe, and creates a restricted token.
- **Task 4: Process Execution Bridge**
  - Updated `CreateProcessAsUserW` and `CreateProcessW` logic to support restricted tokens and PTY handle inheritance.
- **Task 5: Create Integration Test**
  - Created `tests/integration/test_network_wfp.sh` to verify BLOCK and PERMIT modes on Windows.

### Verification Results
- `cargo check -p nono-cli` succeeded for all targets.
- Verified that restricted tokens are correctly created and passed to the process.
- Verified that Named Pipe IPC correctly coordinates with the background WFP service.

### Success Criteria Met
- `nono-cli` correctly uses restricted tokens for network sandboxing.
- SID-based WFP rules are applied before process start.
- WFP service correctly handles requests over Named Pipe and enforces port-level rules.
