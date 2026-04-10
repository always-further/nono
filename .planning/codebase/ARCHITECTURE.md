# Architecture

**Analysis Date:** 2024-04-04

## Pattern Overview

**Overall:** Supervised Capability-Based Sandboxing with Network Proxying

**Key Characteristics:**
- **Platform-Agnostic Interface**: A unified library API (`nono`) that abstracts over platform-specific sandboxing mechanisms: Landlock (Linux), Seatbelt (macOS), and WFP/AppContainer concepts (Windows).
- **Supervised Execution**: A multi-process model where an unsandboxed supervisor process (`nono-cli`) monitors and mediates a sandboxed child process.
- **Explicit Capability Grants**: Security is based on positive allow-lists (capabilities) defined in a `CapabilitySet`.
- **Network Proxying & Credential Injection**: Outbound network traffic is intercepted by a local proxy (`nono-proxy`) to enforce domain-level filtering and securely inject API credentials without exposing them to the sandboxed environment.
- **State Integrity with Rollback**: Support for filesystem snapshots and Merkle-tree-based integrity verification to allow "undoing" changes made during a session.

## Layers

**Core Library (`nono`):**
- Purpose: Provides low-level sandboxing primitives, capability models, and integrity engines.
- Location: `crates/nono/src/`
- Contains: Platform drivers (`sandbox/`), supervisor IPC primitives (`supervisor/`), and rollback logic (`undo/`).
- Depends on: `libc`, `nix` (non-Windows), `windows-sys` (Windows).
- Used by: `nono-cli`, `bindings/c`.

**CLI Orchestration (`nono-cli`):**
- Purpose: Entry point for users and agents; manages session lifecycle, policies, and UI.
- Location: `crates/nono-cli/src/`
- Contains: Execution strategies (`exec_strategy/`), command runtimes (`..._runtime.rs`), and profile management (`profile/`).
- Depends on: `nono`, `nono-proxy`, `clap`, `tracing`.

**Network Proxy (`nono-proxy`):**
- Purpose: Intercepts and filters network traffic from sandboxed processes.
- Location: `crates/nono-proxy/src/`
- Contains: Proxy server (`server.rs`), credential injection (`credential.rs`), and host filtering (`filter.rs`).
- Depends on: `tokio`, `h2`, `rustls`.
- Used by: `nono-cli`.

**Bindings (`bindings/c`):**
- Purpose: Exposes the core library to C/C++ and other languages.
- Location: `bindings/c/`
- Contains: FFI wrappers and header generation (`cbindgen`).

## Data Flow

**Execution Lifecycle:**

1. **Setup**: `nono-cli` parses arguments and loads policies/profiles (`crates/nono-cli/src/sandbox_prepare.rs`).
2. **Proxy Start**: If network filtering is enabled, `nono-cli` starts `nono-proxy` on a local port (`crates/nono-cli/src/proxy_runtime.rs`).
3. **Supervisor Spawn**: `nono-cli` initializes the supervisor state, creating IPC channels for capability requests and URL opening (`crates/nono/src/supervisor/mod.rs`).
4. **Execution Strategy**:
   - **Linux/macOS**: Uses `fork()` to create a child process. The child applies `Sandbox::apply()` and then `execve()`.
   - **Windows**: Spawns the child process in a restricted state using Job Objects or AppContainer-like restrictions (`crates/nono-cli/src/exec_strategy_windows/mod.rs`).
5. **Mediation**: The sandboxed child communicates with the supervisor via a Unix Domain Socket (or named pipe on Windows) to request dynamic resource grants or open URLs.
6. **Network Interception**: The child's network traffic is routed to `nono-proxy`. The proxy validates domains against an allowlist and injects secrets from the `nono` keystore.
7. **Cleanup & Rollback**: After the child exits, the supervisor offers to rollback filesystem changes if a snapshot was taken (`crates/nono-cli/src/rollback_runtime.rs`).

## Key Abstractions

**Sandbox:**
- Purpose: Encapsulates the platform-specific logic for applying restrictions.
- Examples: `crates/nono/src/sandbox/mod.rs`.
- Pattern: Strategy Pattern.

**CapabilitySet:**
- Purpose: A portable representation of allowed resources.
- Examples: `crates/nono/src/capability.rs`.

**ExecStrategy:**
- Purpose: Defines how the sandboxed process is launched and monitored.
- Examples: `crates/nono-cli/src/exec_strategy.rs` (Unix), `crates/nono-cli/src/exec_strategy_windows/mod.rs` (Windows).

## Entry Points

**CLI Main:**
- Location: `crates/nono-cli/src/main.rs`
- Responsibilities: Bootstrap, logging, and dispatching to `app_runtime`.

**Library API:**
- Location: `crates/nono/src/lib.rs`
- Responsibilities: Public interface for embedding sandboxing in other Rust apps.

## Error Handling

**Strategy:** Strongly typed errors using `thiserror`.

**Patterns:**
- `nono::NonoError`: Central error enum for the core library.
- `nono_proxy::ProxyError`: Errors specific to network interception.
- `DiagnosticFormatter`: Generates human-readable explanations for sandbox denials (`crates/nono/src/diagnostic.rs`).

## Cross-Cutting Concerns

**Logging:** Centralized via `tracing` crate. Sub-processes often inherit or forward logs.
**Trust & Attestation**: Code signing and integrity verification for executed binaries and configuration files (`crates/nono/src/trust/mod.rs`).
**Secrets Management**: `Keystore` handles secure loading of environment variables and 1Password/Apple Keychain secrets for injection by the proxy (`crates/nono/src/keystore.rs`).

---

*Architecture analysis: 2024-04-04*
