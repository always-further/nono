# Phase 3 Context: Network Sandboxing (WFP Integration)

## Goal
Implement robust, kernel-level network enforcement on Windows using the Windows Filtering Platform (WFP), providing functional parity with Landlock (Linux) and Seatbelt (macOS).

## Implementation Decisions

### 1. Filtering Strategy (SID-Based)
- **Mechanism:** Switch from `ALE_APP_ID` (executable path) to **Session SID** filtering.
- **Enforcement:** Generate a unique, transient SID for each `nono` session. WFP rules will match this SID (`ALE_USER_SID`).
- **Advantage:** Ensures "Structural Impossibility" of network escape. Child processes inherit the SID/Token and are automatically bound by the same WFP rules as the parent.

### 2. Lifecycle & Cleanup (Dynamic Sessions)
- **Ownership:** The `nono-wfp-service` will own the WFP filtering session.
- **Automatic Cleanup:** Use the `FWPM_SESSION_FLAG_DYNAMIC` flag. If the service process terminates, Windows will automatically and atomically remove all active `nono` filters.
- **Service Type:** The service must be long-lived and running for enforcement to be active.

### 3. Architecture & Drivers
- **Primary Target:** Pure **User-mode WFP** via the Win32 API (ALE layers).
- **Driver Status:** The `nono-wfp-driver.sys` remains on the roadmap as a backup/hedge. It will **not** be implemented in this phase unless user-mode WFP is proven insufficient for port-level filtering.
- **IPC:** Move from one-shot CLI execution to a **Persistent Named Pipe** (`\\.\pipe\nono-wfp-control`) for communication between the CLI/Supervisor and the WFP service.

### 4. Codebase Patterns
- **Protocol:** Extend the existing `WfpRuntimeActivationRequest` JSON contract for use over Named Pipes.
- **Security:** Apply SDDL to the WFP control pipe to ensure only the owner can request policy changes.
- **FFI:** Continue using `windows-sys` features for all WFP API calls.

## Out of Scope for Phase 3
- **L7 Filtering:** Deep packet inspection or domain-level filtering (deferred).
- **Bandwidth Throttling:** Network QoS limits (deferred).
- **Driver Development:** Actual `.sys` implementation (deferred/on-hold).
