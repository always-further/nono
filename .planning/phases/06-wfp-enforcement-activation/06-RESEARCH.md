# Phase 6: WFP Enforcement Activation - Research

**Researched:** 2026-04-05
**Domain:** Windows Filtering Platform (WFP), Windows restricted tokens, named pipe IPC, Rust `windows-sys`
**Confidence:** HIGH — all findings are from direct source inspection; no external library research required

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Remove the `driver_binary_path.exists()` check from `activate_policy_mode()` in `nono-wfp-service.rs` entirely. User-mode WFP (`FwpmEngineOpen0`, `FwpmFilterAdd0`) does not require a kernel driver. If a driver-assisted mode ever ships, it gets its own `request_kind` — this check must not be resurrected on the existing activation path.
- **D-02:** Use SID-based filtering (`FWPM_CONDITION_ALE_USER_ID`) when a session SID is available in `ExecConfig`; fall back to App-ID filtering (`FWPM_CONDITION_ALE_APP_ID`) when it is not. Populate `session_sid` in `build_wfp_target_activation_request()` when the SID string is present; leave it `None` to let the service use App-ID. The service's `install_wfp_policy_filters()` already handles both branches.
- **D-03:** The CLI generates a session-unique SID and applies it to the child process token as a restricted SID before forking. The SID string in SDDL form (e.g. `S-1-...`) is threaded through `ExecConfig` into `WfpNetworkBackend::install` (the `_session_id` parameter is already wired but unused — rename it and use it as the SID carrier). Child processes inherit the restricted token and are automatically covered by the WFP filters. The SID must be session-unique so that filters for one agent never match another agent's traffic.
- **D-04:** Two layers of test coverage, no admin elevation required:
  1. Mock pipe unit tests — exercise the full CLI activation path using the existing `install_wfp_network_backend_with_runner`-style test injection pattern. Mock the named pipe response with `enforced-pending-cleanup` and `prerequisites-missing` variants. Assert that a valid `NetworkEnforcementGuard::WfpServiceManaged` is returned on success and that `NonoError::UnsupportedPlatform` is returned on failure.
  2. Snapshot tests on request serialization — assert the JSON shape of the `WfpRuntimeActivationRequest` produced by `build_wfp_target_activation_request()` when a session SID is present: `session_sid` must be populated, `outbound_rule_name` and `inbound_rule_name` must be set, `network_mode` must match the policy.

### Claude's Discretion

- Exact Windows API (`CreateRestrictedToken`, `AllocateAndInitializeSid`, or another) for generating and applying the session-unique SID.
- Whether the SID string flows as a new field in `ExecConfig` or is stored on a new `WindowsSessionToken` wrapper type.
- SDDL SID format details and validation before passing to the service.
- Sleep/retry policy if the named pipe is briefly unavailable when the service has just started.

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| NETW-01 | User can block network access for Windows agents using the WFP backend. | Enabled by removing the driver check (D-01) and replacing the stub arm in `install_wfp_network_backend` with a real activation call that sends the structured request to the service and returns `NetworkEnforcementGuard::WfpServiceManaged`. |
| NETW-03 | User can allow specific local ports on Windows via WFP-enforced filtering. | `install_wfp_policy_filters()` already consults `tcp_bind_ports`, `tcp_connect_ports`, and `localhost_ports` from the request. Populating `session_sid` in the request automatically activates SID-scoped filtering that covers all port rules. No additional service changes needed. |
</phase_requirements>

---

## Summary

Phase 6 replaces three stubs that together block WFP from ever engaging. The root cause is a cascading gate: the service-side driver check causes `activate_policy_mode()` to return `"prerequisites-missing"` unconditionally on all real installs (D-01 fix), and the CLI-side `install_wfp_network_backend` fails closed on the `"enforced-pending-cleanup"` success response because the `Ready` probe-status arm at line 1421 is wrong — it should route through an actual activation request, not return `UnsupportedPlatform` (D-02/D-03 fix).

The good news: **all service-side machinery is already in place**. `install_wfp_policy_filters()` in `nono-wfp-service.rs` already handles both SID-based and App-ID filtering, `sid_to_security_descriptor()` already validates and converts SID strings, and `NetworkEnforcementGuard::WfpServiceManaged` already exists with a working `Drop` for cleanup. On the CLI side, `restricted_token::generate_session_sid()` and `create_restricted_token_with_sid()` already exist in `restricted_token.rs`. The entire call chain just needs to be wired together.

There is one additional coordination issue to be aware of: `launch.rs:spawn_windows_child()` contains a parallel, partially-implemented WFP activation path (lines 806-822) that sends `"activate_policy_mode"` as the `request_kind`. The service dispatch does NOT recognize that request_kind (it only accepts `"activate_blocked_mode"`, `"activate_proxy_mode"`, `"activate_allow_all_mode"`), so that code path silently generates an `"invalid-request"` response and errors. This code must be reconciled with the canonical path through `prepare_network_enforcement` → `install_wfp_network_backend` to avoid double-activation or a broken secondary flow.

**Primary recommendation:** Fix in this order — (1) remove driver check in service, (2) wire `session_sid` through `ExecConfig` and `build_wfp_target_activation_request()`, (3) replace the `Ready` stub arm with a real `run_wfp_runtime_probe_with_request` call, (4) reconcile or remove `launch.rs:806-822` parallel activation path, (5) add tests.

---

## Standard Stack

### Core (already in project — no new dependencies)
| Component | Location | Purpose |
|-----------|----------|---------|
| `windows-sys` v0.59 | `Cargo.toml` (workspace) | `CreateRestrictedToken`, `ConvertStringSidToSidW`, WFP APIs |
| `tokio` v1 (named pipe client) | `crates/nono-cli` | Async named pipe IPC to `nono-wfp-service` |
| `serde_json` | `crates/nono-cli` | Serialize/deserialize `WfpRuntimeActivationRequest` / `WfpRuntimeActivationResponse` |
| `uuid` | Already used in `restricted_token.rs` | UUID v4 source for session-unique SID generation |

No new dependencies are needed. All required APIs are already imported in the relevant files.

---

## Architecture Patterns

### Existing Activation Flow (what SHOULD happen)

```
ExecStrategy::run()
  └─ prepare_live_windows_launch(config, session_id)
       └─ prepare_network_enforcement(config, session_id)       [network.rs:1471]
            └─ backend.install(policy, config, session_id)      [network.rs:1376]
                 └─ install_wfp_network_backend(...)            [network.rs:1387]
                      ├─ probe_wfp_backend_status_with_config() [verify service ready]
                      ├─ build_wfp_target_activation_request()  [construct request]
                      ├─ run_wfp_runtime_probe_with_request()   [send over named pipe]
                      └─ parse_wfp_runtime_probe_status()       [dispatch on response]
                           └─ EnforcedPendingCleanup ──►  NetworkEnforcementGuard::WfpServiceManaged  ✓
                           └─ Ready ──────────────────►  Err(UnsupportedPlatform) ← STUB (line 1421)
```

The `Ready` arm at line 1421 is misidentified — a `"ready"` response during an activation request is a service protocol violation ("unexpected protocol state"), not an unsupported feature. The actual `EnforcedPendingCleanup` arm is already implemented correctly.

### Parallel Activation Path in launch.rs (CONFLICT — must reconcile)

```
spawn_windows_child(config, ..., session_id)              [launch.rs:794]
  ├─ generate_session_sid()                               [line 806]
  ├─ build_wfp_runtime_activation_request(...)            [line 809]
  ├─ request.request_kind = "activate_policy_mode"        [line 812] ← WRONG kind
  ├─ run_wfp_runtime_request(&request)                    [line 814] ← bypasses probe
  └─ create_restricted_token_with_sid(sid)                [line 822]
```

This path sends the wrong `request_kind` (`"activate_policy_mode"`) which the service dispatch does not recognize, causing an `"invalid-request"` response → `NonoError::Setup` error. It also bypasses the `probe_wfp_backend_status_with_config` readiness check and creates the restricted token AFTER the WFP activation request (wrong ordering — token should be created and session_sid populated BEFORE the activation request is built).

### Correct Ordering (post-fix)

1. Generate session-unique SID string (`generate_session_sid()`)
2. Populate `session_sid` in `ExecConfig` (new field or wrapper)
3. Call `prepare_network_enforcement()` → `install_wfp_network_backend()`
4. Build request with `session_sid` populated via `build_wfp_target_activation_request()`
5. Service installs SID-scoped WFP filters
6. CLI creates restricted token with same SID → child process inherits token
7. Child process traffic matches WFP filter by SID

### Pattern: `_with_runner` Injection

All testable service interactions use this pattern. The production path uses the real runner; tests inject a mock closure:

```rust
// Production
pub(crate) fn install_windows_wfp_service() -> Result<WindowsWfpInstallReport> {
    let config = current_wfp_probe_config()?;
    install_windows_wfp_service_with_runner(&config, run_sc_query, run_sc_command)
}

// Generic (testable)
pub(super) fn install_windows_wfp_service_with_runner<Q, R>(
    config: &WfpProbeConfig,
    query_service: Q,
    run_service_command: R,
) -> Result<WindowsWfpInstallReport>
where
    Q: Fn(&str) -> Result<String>,
    R: Fn(&[String]) -> Result<String>,
{ ... }
```

New activation tests must follow the same pattern: extract an `install_wfp_network_backend_with_runner` that accepts a `run_probe: R` closure replacing `run_wfp_runtime_probe_with_request`.

### Pattern: `windows_wfp_test_force_ready()`

```rust
// In mod.rs
#[cfg(debug_assertions)]
static WINDOWS_WFP_TEST_FORCE_READY: AtomicBool = AtomicBool::new(false);

fn windows_wfp_test_force_ready() -> bool { ... }
pub(crate) fn set_windows_wfp_test_force_ready(force_ready: bool) { ... }
```

`probe_wfp_backend_status_with_config()` uses this flag to skip the real `sc query` call in tests. Tests that exercise the activation path must call `set_windows_wfp_test_force_ready(true)` before invoking `install_wfp_network_backend`.

### SID Generation Format

```rust
// restricted_token.rs:22
pub(super) fn generate_session_sid() -> String {
    let u = Uuid::new_v4();
    let fields = u.as_fields();
    // Custom sub-authority: S-1-5-117-{D1}-{D2}-{D3}-{D4}
    format!("S-1-5-117-{}-{}-{}-{}", fields.0, fields.1, fields.2, u.as_u128() as u32)
}
```

This produces a standard Windows SDDL SID string. Sub-authority `117` is in the Microsoft-reserved range `116-127` (not allocated to any well-known SID), making it safe for agent-scoped use. `ConvertStringSidToSidW` on the service side validates this format before constructing the security descriptor.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Session-unique SID | Custom SID encoding | `generate_session_sid()` in `restricted_token.rs` | Already exists, uses UUID v4 |
| Restricted token creation | Direct `CreateRestrictedToken` call | `create_restricted_token_with_sid()` in `restricted_token.rs` | Already exists with proper error handling |
| SID → security descriptor | Custom SDDL builder | `sid_to_security_descriptor()` in `nono-wfp-service.rs` | Already exists with Windows API validation |
| SID/App-ID filter dispatch | New filter logic | `install_wfp_policy_filters()` in `nono-wfp-service.rs:1352` | Already handles both `session_sid: Some` and `None` branches |
| Named pipe IPC | Custom pipe protocol | `run_wfp_runtime_request()` / `run_wfp_runtime_probe_with_request()` | Already exists, handles tokio async + serde |
| WFP backend readiness probe | New service state check | `probe_wfp_backend_status_with_config()` | Already exists, respects `windows_wfp_test_force_ready()` test hook |

---

## Common Pitfalls

### Pitfall 1: Wrong `request_kind` in launch.rs
**What goes wrong:** `launch.rs:812` sets `request_kind = "activate_policy_mode"`, which is not in the service's dispatch table. The service returns `"invalid-request"` response, causing `NonoError::Setup` at runtime.
**Why it happens:** `"activate_policy_mode"` was written as a generic name but the service dispatch only recognizes `"activate_blocked_mode"`, `"activate_proxy_mode"`, `"activate_allow_all_mode"`.
**How to avoid:** Use `build_wfp_target_activation_request()` which derives `request_kind` from `policy.mode` correctly. Do not construct `request_kind` manually.
**Warning signs:** Service responds `status: "invalid-request"` with details containing `activate_policy_mode`.

### Pitfall 2: Double activation — launch.rs and install_wfp_network_backend both activate
**What goes wrong:** After fixing `install_wfp_network_backend`, the `launch.rs:807-822` path may still run (if `session_id` is `Some`), sending a second activation request for the same target program. The service would install duplicate WFP filters for the same rule names, which either fail with duplicate-key errors or silently corrupt filter state.
**Why it happens:** `spawn_windows_child` is called AFTER `prepare_live_windows_launch` returns a `PreparedWindowsLaunch` with an already-installed `NetworkEnforcementGuard`. When `session_id` is `Some`, `spawn_windows_child` tries to do the same activation again.
**How to avoid:** Remove or gate the WFP activation code from `launch.rs:806-822`. The restricted token creation in that block is still needed — separate the token creation concern from the WFP activation concern.
**Warning signs:** Two WFP filter sets with the same rule name suffix installed simultaneously; `Drop` on `NetworkEnforcementGuard` fails with `FWP_E_FILTER_NOT_FOUND` because cleanup already ran.

### Pitfall 3: Token created before WFP activation in launch.rs
**What goes wrong:** In `launch.rs`, the restricted token is created AFTER the WFP request is sent. If WFP activation fails, the token is never created — but if activation order matters (WFP must reference a SID that corresponds to a real token), creating the token first is safer.
**Why it happens:** Token creation and WFP activation are interleaved in `spawn_windows_child`.
**How to avoid:** In the canonical path, generate the SID string first, then activate WFP with that SID, then create the restricted token. All three steps use the same SID string.

### Pitfall 4: `Ready` stub language misleads future developers
**What goes wrong:** The current `Ready` arm says "enforcement installation is still not implemented" — this implies `Ready` is a normal status that should eventually be handled. In fact, `"ready"` during an activation request is a service protocol violation.
**How to avoid:** Replace the error message with "unexpected protocol state — the service returned 'ready' in response to an activation request, which violates the WFP IPC contract."

### Pitfall 5: `ExecConfig` session_sid field not gated
**What goes wrong:** `ExecConfig` is defined in `exec_strategy_windows/mod.rs` which is already Windows-only. However, if the field is ever referenced in shared code paths, a `#[cfg(target_os = "windows")]` gate is needed.
**How to avoid:** Keep the new `session_sid: Option<String>` field only within the Windows-gated structs. Verify that non-Windows CI builds compile cleanly with `make build` after the change.

### Pitfall 6: Service driver check blocks App-ID fallback path
**What goes wrong:** Even when `session_sid` is `None` (App-ID fallback), `activate_policy_mode()` returns `"prerequisites-missing"` because `driver_binary_path.exists()` is checked before `validate_target_request_fields()`. The driver `.sys` file does not exist on user-mode-only installs.
**Why it happens:** The driver check was added as a prerequisite gate but user-mode WFP filters (`FwpmFilterAdd0`) have no kernel driver dependency.
**How to avoid:** D-01 — remove the `driver_binary_path.exists()` block (lines 1437-1446) entirely. The path that remains: protocol version check → network_mode validation → target field validation → `install_wfp_policy_filters()`.

---

## Code Examples

### Current stub (to be replaced)
```rust
// network.rs:1420-1427 — CURRENT (broken)
return match parse_wfp_runtime_probe_status(&probe_output)? {
    WfpRuntimeActivationProbeStatus::Ready => Err(NonoError::UnsupportedPlatform(
        format!(
            "Windows WFP runtime activation reported ready for {}, but enforcement installation is still not implemented ...",
            ...
        ),
    )),
    WfpRuntimeActivationProbeStatus::EnforcedPendingCleanup => Ok(Some(
        NetworkEnforcementGuard::WfpServiceManaged { ... }
    )),
    ...
```

The `EnforcedPendingCleanup` arm at line 1442 is the success path and is ALREADY CORRECT. The `Ready` arm needs its error message updated to say "unexpected protocol state" (per SPECIFICS in CONTEXT.md).

### build_wfp_target_activation_request — add session_sid
```rust
// network.rs:461 — needs session_sid populated
pub(super) fn build_wfp_target_activation_request(
    policy: &nono::WindowsNetworkPolicy,
    target_program: &Path,
    outbound_rule: &str,
    inbound_rule: &str,
    session_sid: Option<&str>,              // ← add parameter
) -> WfpRuntimeActivationRequest {
    let mut request = build_wfp_runtime_activation_request(policy);
    request.target_program_path = Some(target_program.display().to_string());
    request.outbound_rule_name = Some(outbound_rule.to_string());
    request.inbound_rule_name = Some(inbound_rule.to_string());
    request.session_sid = session_sid.map(str::to_string);  // ← populate
    request
}
```

### Driver check removal in nono-wfp-service.rs
```rust
// nono-wfp-service.rs:1426 — activate_policy_mode — REMOVE these lines (1437-1446):
//   let driver_binary_path = match current_driver_binary_path() { ... };
//   if !driver_binary_path.exists() { return build_prerequisites_missing_response(...); }
// Resulting function starts directly with validate_target_request_fields().
```

### ExecConfig session_sid carrier
```rust
// exec_strategy_windows/mod.rs — ExecConfig struct addition
pub struct ExecConfig<'a> {
    pub command: &'a [String],
    pub resolved_program: &'a Path,
    pub caps: &'a CapabilitySet,
    pub env_vars: Vec<(&'a str, &'a str)>,
    pub cap_file: Option<&'a Path>,
    pub current_dir: &'a Path,
    pub session_sid: Option<String>,        // ← add: SDDL SID string for WFP SID-based filtering
}
```

Alternatively, a `WindowsSessionToken` wrapper (per Claude's discretion) can hold both the SID string and the `RestrictedToken` handle together, but the `ExecConfig` field approach is simpler and aligns with what the CONTEXT.md describes.

### _with_runner pattern for new activation test
```rust
// network.rs — new testable variant
pub(super) fn install_wfp_network_backend_with_runner<R>(
    policy: &nono::WindowsNetworkPolicy,
    config: &ExecConfig<'_>,
    probe_config: &WfpProbeConfig,
    run_probe: R,
) -> Result<Option<NetworkEnforcementGuard>>
where
    R: Fn(&WfpProbeConfig, &WfpRuntimeActivationRequest) -> Result<WfpRuntimeProbeOutput>,
{ ... }

// Production entry point (unchanged signature, delegates to _with_runner)
pub(super) fn install_wfp_network_backend(
    policy: &nono::WindowsNetworkPolicy,
    config: &ExecConfig<'_>,
    probe_config: &WfpProbeConfig,
) -> Result<Option<NetworkEnforcementGuard>> {
    install_wfp_network_backend_with_runner(policy, config, probe_config, run_wfp_runtime_probe_with_request)
}
```

### Snapshot test for request serialization
```rust
// In mod tests, no elevation needed
#[test]
fn build_wfp_target_activation_request_populates_session_sid() {
    use nono::{CapabilitySet, WindowsNetworkPolicy};
    let policy = ...;  // blocked mode
    let request = build_wfp_target_activation_request(
        &policy,
        Path::new(r"C:\tools\agent.exe"),
        "nono-wfp-block-out-abc123",
        "nono-wfp-block-in-abc123",
        Some("S-1-5-117-123456789-1234-5678-9012"),
    );
    assert_eq!(request.session_sid.as_deref(), Some("S-1-5-117-123456789-1234-5678-9012"));
    assert_eq!(request.outbound_rule_name.as_deref(), Some("nono-wfp-block-out-abc123"));
    assert_eq!(request.network_mode, "blocked");
}
```

---

## State of the Art

| Old Approach | Current Approach | Status |
|--------------|------------------|--------|
| Driver-gated activation (`driver_binary_path.exists()`) | User-mode WFP only via `FwpmEngineOpen0` | D-01 removes the gate |
| `UnsupportedPlatform` stub at line 1421 | Real activation through named pipe returning `EnforcedPendingCleanup` | Phase 6 replaces |
| `_session_id: Option<&str>` unused in `install()` | SID string wired from `ExecConfig` into activation request | D-02/D-03 |
| App-ID filtering only | SID-based filtering with App-ID fallback | `install_wfp_policy_filters()` already supports both |

---

## Open Questions

1. **Should launch.rs:806-822 be removed, or moved to be invoked from inside install_wfp_network_backend?**
   - What we know: The parallel activation path uses the wrong `request_kind` and would cause double-activation after the main stub is fixed. The restricted token creation IS needed somewhere.
   - What's unclear: Whether `spawn_windows_child` is ever called when `session_id` is `None` (meaning the token block would be skipped anyway), or whether refactoring to put token creation in `prepare_live_windows_launch` is a pre-req.
   - Recommendation: Planner should audit the `spawn_windows_child` call sites to determine if the WFP code in `launch.rs:806-822` is currently dead in practice (because the probe always fails closed), and schedule its removal or refactor as a sub-task within this phase. If the token creation needs to remain in `spawn_windows_child`, the WFP activation portion should be removed and rely on the guard returned by `prepare_live_windows_launch`.

2. **Does ExecConfig need session_sid for the token creation seam, or is `_session_id: Option<&str>` on `WfpNetworkBackend::install` sufficient?**
   - What we know: D-03 says the SID string is the carrier. The `install()` trait already has `_session_id: Option<&str>`. For token creation to happen before spawning the child, the SID must be available at spawn time.
   - Recommendation: Use `ExecConfig.session_sid: Option<String>` as the canonical carrier. Token creation in `spawn_windows_child` reads `config.session_sid`; `install_wfp_network_backend` reads `config.session_sid` and passes it to `build_wfp_target_activation_request`. The `_session_id` parameter on `install()` can be removed or kept as a no-op alias.

---

## Environment Availability

Step 2.6: SKIPPED — Phase 6 is a code change to Rust source files. All build tooling (Rust, Cargo, windows-sys) is already established in the project. No new external tools or services are required.

---

## Sources

### Primary (HIGH confidence)
- Direct source inspection: `crates/nono-cli/src/exec_strategy_windows/network.rs` (1495 lines)
- Direct source inspection: `crates/nono-cli/src/bin/nono-wfp-service.rs` (1818 lines)
- Direct source inspection: `crates/nono-cli/src/exec_strategy_windows/restricted_token.rs`
- Direct source inspection: `crates/nono-cli/src/exec_strategy_windows/launch.rs`
- Direct source inspection: `crates/nono-cli/src/exec_strategy_windows/mod.rs`
- Direct source inspection: `crates/nono-cli/src/windows_wfp_contract.rs`
- `.planning/phases/06-wfp-enforcement-activation/06-CONTEXT.md` — locked decisions, canonical refs

### Secondary (MEDIUM confidence)
- `crates/nono-cli/src/exec_strategy.rs` — ExecConfig structure on Unix side (reference)
- `.planning/REQUIREMENTS.md` — NETW-01, NETW-03 requirements

---

## Metadata

**Confidence breakdown:**
- Stub location and fix: HIGH — verified by direct inspection of network.rs:1421 and service:1441
- Service-side readiness (no new code needed): HIGH — verified `install_wfp_policy_filters`, `sid_to_security_descriptor`, `generate_session_sid`, `create_restricted_token_with_sid` all exist
- launch.rs conflict: HIGH — verified by tracing `spawn_windows_child` call flow and wrong `request_kind`
- ExecConfig field approach: MEDIUM — based on CONTEXT.md guidance and code structure; the wrapper alternative is also viable
- Test pattern: HIGH — `_with_runner` pattern is established throughout `network.rs` and `windows_wfp_test_force_ready()` exists

**Research date:** 2026-04-05
**Valid until:** 2026-05-05 (stable internal codebase; no external dependency drift)
