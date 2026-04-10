# Phase 3: Network Sandboxing (WFP Integration) - Research

**Researched:** 2026-04-04
**Domain:** Windows Filtering Platform (WFP), ALE Layers, Process Isolation via Restricted Tokens
**Confidence:** HIGH

## Summary

This phase implements kernel-level network enforcement on Windows by integrating with the **Windows Filtering Platform (WFP)**. It achieves "Structural Impossibility" for network bypass by tagging each `nono` session with a **unique, transient Security Identifier (SID)** and using **ALE (Application Layer Enforcement)** filters to block or permit traffic based on that SID.

**Primary recommendation:** Use a **Restricted Token** with a unique SID in the `SidsToRestrict` list for child processes, paired with a background **WFP Service** (running as Admin) that applies `FWPM_CONDITION_ALE_USER_ID` filters matching those SIDs.

<user_constraints>
## User Constraints (from 03-CONTEXT.md)

### Locked Decisions
- **Filtering Strategy (SID-Based):** 
    - Switch from `ALE_APP_ID` (path-based) to **Session SID** filtering.
    - Generate a unique, transient SID for each `nono` session.
    - WFP rules match this SID via `ALE_USER_SID` (implemented as `ALE_USER_ID` with Security Descriptor).
- **Lifecycle & Cleanup:** 
    - `nono-wfp-service` owns the WFP session.
    - Use `FWPM_SESSION_FLAG_DYNAMIC` for automatic rule cleanup on service exit/crash.
- **Architecture:** 
    - Primary target: **User-mode WFP** via Win32 ALE layers.
    - Driver-mode (`.sys`) is a deferred backup.
- **IPC:** 
    - Persistent Named Pipe (`\\.\pipe\nono-wfp-control`) for CLI/Supervisor to Service communication.
    - Secured via SDDL to restrict access to the session owner.

### the agent's Discretion
- Exact SID generation scheme (e.g., using a random GUID sub-authority).
- Sublayer weight configuration to ensure precedence over Windows Firewall.
- Integration of SID assignment into the `nono-cli` process spawning logic.

### Deferred Ideas (OUT OF SCOPE)
- L7 Filtering (Deep Packet Inspection).
- Bandwidth Throttling (QoS).
- Driver-level (`.sys`) implementation.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| NETW-01 | User can block network access for Windows agents using the WFP backend. | Use `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` with a `BLOCK` action filter matching the Session SID. |
| NETW-02 | WFP rules persist correctly during detach/attach cycles. | The `nono-wfp-service` maintains the dynamic session independently of the CLI/Supervisor lifecycle. |
| NETW-03 | User can allow specific local ports on Windows via WFP-enforced filtering. | Add `PERMIT` filters with higher weight within the same sublayer, combining the SID condition and `FWPM_CONDITION_IP_REMOTE_PORT`. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `windows-sys` | 0.59.0 | Win32 FFI (WFP, Security) | Project standard for low-level Windows integration. |
| `tokio` | 1.x | Async Named Pipes | Required for the WFP control service IPC. |
| `serde_json` | 1.0 | IPC Serialization | Existing contract format for activation requests. |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|--------------|
| `uuid` | 1.x | Unique SID generation | Used to create unique sub-authorities for session SIDs. |

**Installation:**
```toml
# Ensure these features are enabled in crates/nono-cli/Cargo.toml
windows-sys = { version = "0.59", features = [
    "Win32_NetworkManagement_WindowsFilteringPlatform",
    "Win32_Security",
    "Win32_Security_Authorization",
    "Win32_System_Rpc",
    "Win32_System_Pipes"
] }
```

## Architecture Patterns

### Pattern 1: The "Restricted SID" Sandbox
To isolate network traffic without requiring a new Windows User account:
1.  **Generate SID:** Create a unique SID (e.g., `S-1-5-117-{GUID_PARTS}`).
2.  **Restrict Token:** Use `CreateRestrictedToken` to create a child token. Add the unique SID to the `SidsToRestrict` parameter.
3.  **WFP Match:** Use `FWPM_CONDITION_ALE_USER_ID` with a Security Descriptor (SD) that grants access to that specific SID.
4.  **Evaluation:** Windows `AccessCheck` for a restricted token only succeeds if the SID is granted access in *both* the normal and restricted passes. By granting access to the unique SID in the SD, the filter matches specifically for that session.

### Pattern 2: Multi-Layered Sublayer Weighting
To ensure `nono` rules are respected even if Windows Defender Firewall has "Allow" rules:
- Create a custom `nono` **Sublayer** (`FWPM_SUBLAYER0`).
- Set the `weight` higher than `FWPM_SUBLAYER_FIREWALL` (typically > 0x100).
- Within this sublayer:
    - **Block Filter:** Weight 0 (Lowest).
    - **Allow Filter (Specific Ports):** Weight 100 (Higher).
- Result: If `nono` blocks, the packet is dropped before the Firewall even sees it. If `nono` permits, the packet proceeds to the Firewall for its own checks.

### Anti-Patterns to Avoid
- **ALE_APP_ID (Path) Filtering:** Do not use executable paths. They are easily bypassed by renaming or copying the binary (e.g., `copy nono-agent.exe git.exe`).
- **Global `BLOCK` without SID:** Never add a block rule that doesn't target the specific session SID, or you will break the host machine's network.
- **Persistent Filters:** Avoid `FWPM_FILTER_FLAG_PERSISTENT` for session rules. If the system crashes, "Zombie" rules will remain. Always use `FWPM_SESSION_FLAG_DYNAMIC`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Rule Cleanup | Manual `FilterDelete` | `DYNAMIC` Sessions | BFE (Base Filtering Engine) handles atomic cleanup on process exit via RPC rundown. |
| SID Parsing | String manipulation | `ConvertStringSidToSidW` | SID binary format is complex and version-dependent. |
| Access Check Logic | Manual SID comparison | `ALE_USER_ID` (SD-based) | Correctly handles restricted tokens, groups, and inheritance. |

## Runtime State Inventory

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None | WFP state is transient (BFE in-memory). |
| Live service config | WFP Dynamic Session | Handled by `nono-wfp-service` process. |
| OS-registered state | WFP Filters/Sublayers | Auto-cleaned by BFE on service exit. |
| Secrets/env vars | None | SIDs are generated on-the-fly. |
| Build artifacts | `nono-wfp-service.exe` | New binary to be built and signed. |

## Common Pitfalls

### Pitfall 1: BFE Service Dependency
**What goes wrong:** `FwpmEngineOpen0` fails with `RPC_S_SERVER_UNAVAILABLE`.
**Why:** The Base Filtering Engine (BFE) is disabled or stopped.
**How to avoid:** Check service status in `setup --check-only` and provide a clear error message.

### Pitfall 2: Sublayer Interaction
**What goes wrong:** `nono` permits a port, but traffic is still blocked.
**Why:** Windows Defender Firewall or another 3rd-party firewall has a `BLOCK` rule in a different sublayer.
**How to avoid:** Document that `nono` is a *restrictive* sandbox, not a bypass tool. It can only block what the system allows, not allow what the system blocks.

### Pitfall 3: Restricted Token Integrity
**What goes wrong:** Child process cannot access its own workspace or registry keys.
**Why:** `CreateRestrictedToken` can sometimes lower the integrity level or strip too many groups.
**How to avoid:** Only use `SidsToRestrict` to add the session SID; do not strip "Administrators" or other primary groups unless explicitly requested by a "Hardened" mode.

## Code Examples

### Adding a SID-based Block Filter
```rust
// Verified Pattern for SID-based ALE Blocking
unsafe fn add_sid_block_filter(engine: HANDLE, sublayer: GUID, session_sid: PSID) -> u64 {
    // 1. Create SDDL string granting access to the unique SID
    // D:(A;;CC;;;{SID}) -> Allow Create Child (CC) for the SID
    let sddl = format!("D:(A;;CC;;;{})", sid_to_string(session_sid));
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    ConvertStringSecurityDescriptorToSecurityDescriptorW(
        w!(sddl), SDDL_REVISION_1, &mut sd, ptr::null_mut()
    );

    // 2. Define Condition using the Security Descriptor
    let mut condition = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_USER_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            type_: FWP_SECURITY_DESCRIPTOR_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 { sd: sd as *mut _ },
        },
    };

    // 3. Add Filter with BLOCK action
    let filter = FWPM_FILTER0 {
        layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        subLayerKey: sublayer,
        action: FWPM_ACTION0 { type_: FWP_ACTION_BLOCK, .. },
        numFilterConditions: 1,
        filterCondition: &condition,
        weight: FWP_VALUE0 { type_: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: 0 } },
        ..Default::default()
    };

    let mut filter_id = 0;
    FwpmFilterAdd0(engine, &filter, ptr::null(), &mut filter_id);
    LocalFree(sd as _);
    filter_id
}
```

### Launching Process with Restricted SID
```rust
// Pattern for adding a session SID to a Restricted Token
unsafe fn create_session_token(session_sid: PSID) -> HANDLE {
    let mut h_token: HANDLE = 0;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut h_token);

    let sid_restrict = SID_AND_ATTRIBUTES {
        Sid: session_sid,
        Attributes: 0,
    };

    let mut h_restricted: HANDLE = 0;
    CreateRestrictedToken(
        h_token,
        0, // Flags
        0, ptr::null(), // SidsToDisable
        0, ptr::null(), // PrivilegesToDelete
        1, &sid_restrict, // SidsToRestrict <--- This is the key
        &mut h_restricted
    );
    h_restricted
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Windows Firewall Rules (`netsh`) | WFP ALE Filtering | Win 10+ | True kernel-level enforcement; path-agnostic; child-process inheritance. |
| Per-user accounts | Restricted Tokens + unique SIDs | Win 8+ | No OS-level user creation required; lightweight and transient. |

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| BFE Service | WFP Backend | ✓ | Running | Blocking failure |
| Admin Privs | WFP Service | ✓ | — | Manual elevation prompt |
| windows-sys | FFI | ✓ | 0.59 | — |

**Missing dependencies with no fallback:**
- **Base Filtering Engine (BFE):** Must be enabled and running for any network enforcement to function.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `cargo test` + Integration Bins |
| Config file | None |
| Quick run command | `cargo test --test test_network` |
| Full suite command | `./scripts/run-all-tests.sh` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| NETW-01 | Blocked process cannot connect to internet | Integration | `cargo run --bin test-connector -- --should-fail` | ❌ Wave 0 |
| NETW-02 | Rules persist after CLI detach | Smoke | `nono run --net-block --detach && curl --fail ...` | ❌ Wave 0 |
| NETW-03 | Allowed port permits traffic | Integration | `cargo run --bin test-connector --port 80` | ❌ Wave 0 |

### Wave 0 Gaps
- [ ] `tests/integration/wfp_behavior.rs` — Core WFP logic validation.
- [ ] `crates/nono-cli/src/bin/test-connector.rs` — Helper for network probes.

## Sources

### Primary (HIGH confidence)
- Microsoft Docs: [WFP Condition Identifiers](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)
- Microsoft Docs: [ALE Layers](https://learn.microsoft.com/en-us/windows/win32/fwp/about-ale)
- Google Project Zero: [A Guide to WFP](https://googleprojectzero.blogspot.com/2021/08/wfp-internals.html)

### Secondary (MEDIUM confidence)
- Chromium Sandbox Source: [Restricted Token implementation](https://source.chromium.org/chromium/chromium/src/+/main:sandbox/win/src/restricted_token.cc)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Core Win32/WFP APIs are stable and well-documented.
- Architecture: HIGH - SID-based restricted token approach is used by major browsers (Chrome/Edge).
- Pitfalls: HIGH - Common WFP issues (BFE status, sublayer weights) are well-known.

**Research date:** 2026-04-04
**Valid until:** 2026-06-04 (WFP is a stable Windows component).
