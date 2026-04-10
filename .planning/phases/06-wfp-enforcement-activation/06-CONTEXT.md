# Phase 6: WFP Enforcement Activation - Context

**Gathered:** 2026-04-05
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace the `UnsupportedPlatform` stubs in `crates/nono-cli/src/exec_strategy_windows/network.rs` so that sending a WFP activation request to `nono-wfp-service` over the named pipe actually installs kernel-enforced network filters and returns a live `NetworkEnforcementGuard`. Scope: service-side driver check removal, CLI-side SID generation + token creation, request construction, and test coverage. Does NOT change the IPC protocol shape, the cleanup/deactivation path, or the probe-status logic.

</domain>

<decisions>
## Implementation Decisions

### Driver check gate
- **D-01:** Remove the `driver_binary_path.exists()` check from `activate_policy_mode()` in `nono-wfp-service.rs` entirely. User-mode WFP (`FwpmEngineOpen0`, `FwpmFilterAdd0`) does not require a kernel driver. If a driver-assisted mode ever ships, it gets its own `request_kind` — this check must not be resurrected on the existing activation path.

### SID vs App-ID filtering
- **D-02:** Use SID-based filtering (`FWPM_CONDITION_ALE_USER_ID`) when a session SID is available in `ExecConfig`; fall back to App-ID filtering (`FWPM_CONDITION_ALE_APP_ID`) when it is not. Populate `session_sid` in `build_wfp_target_activation_request()` when the SID string is present; leave it `None` to let the service use App-ID. The service's `install_wfp_policy_filters()` already handles both branches.

### Token creation and SID plumbing
- **D-03:** The CLI generates a session-unique SID and applies it to the child process token as a restricted SID before forking. The SID string in SDDL form (e.g. `S-1-...`) is threaded through `ExecConfig` into `WfpNetworkBackend::install` (the `_session_id` parameter is already wired but unused — rename it and use it as the SID carrier). Child processes inherit the restricted token and are automatically covered by the WFP filters. The SID must be session-unique so that filters for one agent never match another agent's traffic.

### Test strategy
- **D-04:** Two layers of test coverage, no admin elevation required:
  1. **Mock pipe unit tests** — exercise the full CLI activation path using the existing `install_wfp_network_backend_with_runner`-style test injection pattern. Mock the named pipe response with `enforced-pending-cleanup` and `prerequisites-missing` variants. Assert that a valid `NetworkEnforcementGuard::WfpServiceManaged` is returned on success and that `NonoError::UnsupportedPlatform` is returned on failure.
  2. **Snapshot tests on request serialization** — assert the JSON shape of the `WfpRuntimeActivationRequest` produced by `build_wfp_target_activation_request()` when a session SID is present: `session_sid` must be populated, `outbound_rule_name` and `inbound_rule_name` must be set, `network_mode` must match the policy.

### Claude's Discretion
- Exact Windows API (`CreateRestrictedToken`, `AllocateAndInitializeSid`, or another) for generating and applying the session-unique SID.
- Whether the SID string flows as a new field in `ExecConfig` or is stored on a new `WindowsSessionToken` wrapper type.
- SDDL SID format details and validation before passing to the service.
- Sleep/retry policy if the named pipe is briefly unavailable when the service has just started.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Files to modify
- `crates/nono-cli/src/exec_strategy_windows/network.rs` — Primary CLI-side file. The stub is at line 1421 (`WfpRuntimeActivationProbeStatus::Ready` arm). `build_wfp_target_activation_request()` at line 461 must populate `session_sid`. `WfpNetworkBackend::install` at line 1376 has `_session_id: Option<&str>` unused — this must be wired up.
- `crates/nono-cli/src/bin/nono-wfp-service.rs` — Service-side. Remove the `driver_binary_path.exists()` check inside `activate_policy_mode()` at line 1441. No other changes to service logic needed.

### Files to read (integration points)
- `crates/nono-cli/src/exec_strategy_windows/network.rs` lines 461-491 — `build_wfp_target_activation_request()` and `build_wfp_runtime_cleanup_request()` — understand the full request shape before modifying.
- `crates/nono-cli/src/exec_strategy_windows/network.rs` lines 1387-1468 — `install_wfp_network_backend()` — the full activation dispatch including the stub arm to replace.
- `crates/nono-cli/src/bin/nono-wfp-service.rs` lines 1351-1393 — `install_wfp_policy_filters()` — already handles `session_sid: Some` vs `None`; confirms D-02 is supported.
- `crates/nono-cli/src/bin/nono-wfp-service.rs` lines 1426-1476 — `activate_policy_mode()` and `deactivate_policy_mode()` — shows exactly where the driver check lives and what surrounds it.

### Design docs
- `proj/DESIGN-supervisor.md` — Process model and named pipe IPC protocol. Read before modifying how session context flows into `install`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `install_wfp_policy_filters()` (`nono-wfp-service.rs:1352`) — already implements both SID-based and App-ID filtering. No service-side changes needed beyond the driver check removal.
- `sid_to_security_descriptor()` (`nono-wfp-service.rs:1155`) — converts a SID string to a security descriptor for WFP condition matching. Already exists, just needs the CLI to populate `session_sid`.
- `windows_wfp_test_force_ready()` — existing test hook that short-circuits the `sc query` probe. Use this in new unit tests to put the system into "backend ready" state without real services.
- `NetworkEnforcementGuard::WfpServiceManaged` — the success return value already exists and is handled by `Drop` for cleanup.

### Established Patterns
- **`_with_runner` injection pattern** — used throughout `network.rs` for testable service interactions (e.g. `install_windows_wfp_service_with_runner`). New activation tests must follow the same pattern.
- **Fail-closed** — every Windows API call returns `Err(NonoError::SandboxInit(...))` or `Err(NonoError::UnsupportedPlatform(...))` on failure. The SID creation path must follow this.
- **`#[cfg(target_os = "windows")]`** — all WFP and token creation code must be gated. Non-Windows builds must compile cleanly.

### Integration Points
- `WfpNetworkBackend::install` (`network.rs:1376`) — the entry point for all WFP enforcement. The `_session_id` parameter here is the seam where the SID string enters.
- `ExecConfig` — the config struct passed into `install`. Adding a `session_sid: Option<String>` field here is the natural carrier for the SID string.
- `prepare_network_enforcement` (`network.rs:1471`) — calls `backend.install`. Traces back to the exec strategy; understand how `session_id` reaches this call site to know where token creation must happen.

</code_context>

<specifics>
## Specific Ideas

- The `WfpRuntimeActivationProbeStatus::Ready` arm at line 1421 is not triggered by `activate_policy_mode()` under normal operation (the service never returns `"ready"` for an activation request). However, it is a protocol ambiguity — it can remain as a hard `UnsupportedPlatform` error since receiving `"ready"` during activation is a service contract violation. The stub language should be updated to say "unexpected protocol state" rather than "not yet implemented".
- The `session_id` already passed to `install` is a session slug/UUID string — it is NOT a Windows SID. D-03 requires creating an actual Windows SID (a `PSID`) and applying it to the child token. The session slug can be used as input to derive a deterministic SID namespace, but the planner must confirm the exact Windows API path.
- The driver check in `activate_policy_mode()` is the single biggest unblock. Removing it (D-01) makes the service functional immediately with App-ID fallback (D-02) even if SID token creation (D-03) takes longer.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 06-wfp-enforcement-activation*
*Context gathered: 2026-04-05*
