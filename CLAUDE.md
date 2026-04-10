# nono - Development Guide

## Project Overview

nono is a capability-based sandboxing system for running untrusted AI agents with OS-enforced isolation. It uses Landlock (Linux) and Seatbelt (macOS) to create sandboxes where unauthorized operations are structurally impossible.

The project is a Cargo workspace with three members:
- **nono** (`crates/nono/`) - Core library. Pure sandbox primitive with no built-in security policy.
- **nono-cli** (`crates/nono-cli/`) - CLI binary. Owns all security policy, profiles, hooks, and UX.
- **nono-ffi** (`bindings/c/`) - C FFI bindings. Exposes the library via `extern "C"` functions and auto-generated `nono.h` header.

Language bindings live in separate repositories:
- **nono-py** (`../nono-py/`) - Python bindings via PyO3. Published to PyPI.
- **nono-ts** (`../nono-ts/`) - TypeScript/Node bindings via napi-rs. Published to npm.

## Architecture

```
crates/nono/src/                    # Library - pure sandbox primitive
├── lib.rs                          # Public API re-exports
├── capability.rs                   # CapabilitySet, FsCapability, AccessMode (builder pattern)
├── error.rs                        # NonoError enum
├── state.rs                        # SandboxState serialization
├── diagnostic.rs                   # DiagnosticFormatter
├── query.rs                        # QueryContext for permission checking
├── keystore.rs                     # Secure credential loading from system keystore
├── undo/
│   ├── mod.rs                      # Module root, re-exports public API
│   ├── types.rs                    # ContentHash, FileState, Change, SnapshotManifest, SessionMetadata
│   ├── object_store.rs             # Content-addressable file storage (SHA-256, dedup, clone_or_copy)
│   ├── merkle.rs                   # MerkleTree (cryptographic state commitment)
│   ├── snapshot.rs                 # SnapshotManager (baseline, incremental, restore)
│   └── exclusion.rs                # ExclusionFilter (gitignore, patterns, globs)
└── sandbox/
    ├── mod.rs                      # Sandbox facade: apply(), is_supported(), support_info()
    ├── linux.rs                    # Landlock implementation
    └── macos.rs                    # Seatbelt implementation

crates/nono-cli/src/                # CLI - security policy and UX
├── main.rs                         # Entry point, command routing
├── cli.rs                          # Clap argument definitions
├── capability_ext.rs               # CapabilitySetExt trait (CLI-specific construction)
├── policy.rs                       # Group resolver: parse policy.json, filter, expand, resolve
├── query_ext.rs                    # CLI-specific query functions
├── sandbox_state.rs                # CLI-specific state handling
├── exec_strategy.rs                # Fork+exec with signal forwarding (Direct/Monitor/Supervised)
├── hooks.rs                        # Claude Code hook installation
├── setup.rs                        # System setup and verification
├── output.rs                       # Banner, dry-run output, prompts
├── rollback_ui.rs                  # Interactive rollback review and restore prompts
├── learn.rs                        # strace-based path discovery (Linux only)
├── config/
│   ├── mod.rs                      # Config module root
│   ├── embedded.rs                 # Embedded data (build.rs artifacts)
│   ├── user.rs                     # User configuration
│   └── version.rs                  # Version tracking
└── profile/
    ├── mod.rs                      # Profile loading
    └── builtin.rs                  # Built-in profiles (delegates to policy resolver)

crates/nono-cli/data/               # Embedded at build time via build.rs
├── policy.json                     # Groups, deny rules, built-in profiles (single source of truth)
└── hooks/
    └── nono-hook.sh                # Hook script for Claude Code

bindings/c/src/                     # C FFI - extern "C" wrappers over core library
├── lib.rs                          # Thread-local error store, string helpers, version
├── types.rs                        # #[repr(C)] enums and structs
├── capability_set.rs               # NonoCapabilitySet opaque pointer API
├── fs_capability.rs                # Index-based FsCapability accessors
├── sandbox.rs                      # Sandbox apply/support functions
├── query.rs                        # NonoQueryContext opaque pointer API
└── state.rs                        # NonoSandboxState opaque pointer API
```

### Library vs CLI Boundary

The library is a **pure sandbox primitive**. It applies ONLY what clients explicitly add to `CapabilitySet`:

| In Library | In CLI |
|------------|--------|
| `CapabilitySet` builder | Policy groups (deny rules, dangerous commands, system paths) |
| `Sandbox::apply()` | Group resolver (`policy.rs`) and platform-aware deny handling |
| `SandboxState` | `ExecStrategy` (Direct/Monitor/Supervised) |
| `DiagnosticFormatter` | Profile loading and hooks |
| `QueryContext` | All output and UX |
| `keystore` | `learn` mode |
| `undo` module (ObjectStore, SnapshotManager, MerkleTree, ExclusionFilter) | Rollback lifecycle, exclusion policy, rollback UI |

## Build & Test

After every session, run these commands to verify correctness:

```bash
# Build everything
make build

# Run all tests
make test

# Full CI check (clippy + fmt + tests)
make ci
```

Individual targets:
```bash
make build-lib       # Library only
make build-cli       # CLI only
make test-lib        # Library tests only
make test-cli        # CLI tests only
make test-doc        # Doc tests only
make clippy          # Lint (strict: -D warnings -D clippy::unwrap_used)
make fmt-check       # Format check
make fmt             # Auto-format
```

## Coding Standards

- **Error Handling**: Use `NonoError` for all errors; propagation via `?` only.
- **Unwrap Policy**: Strictly forbid `.unwrap()` and `.expect()`; enforced by `clippy::unwrap_used`.
- **Libraries should almost never panic**: Panics are for unrecoverable bugs, not expected error conditions. Use `Result` instead.
- **Unsafe Code**: Restrict to FFI; must be wrapped in safe APIs with `// SAFETY:` docs.
- **Path Security**: Validate and canonicalize all paths before applying capabilities.
- **Arithmetic**: Use `checked_`, `saturating_`, or `overflowing_` methods for security-critical math.
- **Memory**: Use the `zeroize` crate for sensitive data (keys/passwords) in memory.
- **Testing**: Write unit tests for all new capability types and sandbox logic.
- **Environment variables in tests**: Tests that modify `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`, or other env vars must save and restore the original value. Rust runs unit tests in parallel within the same process, so an unrestored env var causes flaky failures in unrelated tests (e.g. `config::check_sensitive_path` fails when another test temporarily sets `HOME` to a fake path). Always use save/restore pattern and keep the modified window as short as possible.
- **Attributes**: Apply `#[must_use]` to functions returning critical Results.
- **Lazy use of dead code**: Avoid `#[allow(dead_code)]`. If code is unused, either remove it or write tests that use it.
- **Commits**: All commits must include a DCO sign-off line (`Signed-off-by: Name <email>`).

## Key Design Decisions

1. **No escape hatch**: Once sandbox is applied via `restrict_self()` (Landlock) or `sandbox_init()` (Seatbelt), there is no API to expand permissions.

2. **Fork+wait process model**: nono stays alive as a parent process. On child failure, prints a diagnostic footer to stderr. Three execution strategies: `Direct` (exec, backward compat), `Monitor` (sandbox-then-fork, default), `Supervised` (fork-then-sandbox, for rollbacks/expansion).

3. **Capability resolution**: All paths are canonicalized at grant time to prevent symlink escapes.

4. **Library is policy-free**: The library applies ONLY what's in `CapabilitySet`. No built-in sensitive paths, dangerous commands, or system paths. Clients define all policy.

## Platform-Specific Notes

### macOS (Seatbelt)
- Uses `sandbox_init()` FFI with raw profile strings
- Profile is Scheme-like DSL: `(allow file-read* (subpath "/path"))`
- Network denied by default with `(deny network*)`

### Linux (Landlock)
- Uses landlock crate for safe Rust bindings
- Detects highest available ABI (v1-v5)
- ABI v4+ includes TCP network filtering
- Strictly allow-list: cannot express deny-within-allow. `deny.access`, `deny.unlink`, and `symlink_pairs` are macOS-only. Avoid broad allow groups that cover deny paths.

## Security Considerations

**SECURITY IS NON-NEGOTIABLE.** This is a security-critical codebase. Every change must be evaluated through a security lens first. When in doubt, choose the more restrictive option.

### Core Principles
- **Principle of Least Privilege**: Only grant the minimum necessary capabilities.
- **Defense in Depth**: Combine OS-level sandboxing with application-level checks.
- **Fail Secure**: On any error, deny access. Never silently degrade to a less secure state.
- **Explicit Over Implicit**: Security-relevant behavior must be explicit and auditable.

### Path Handling (CRITICAL)
- Always use path component comparison, not string operations. String `starts_with()` on paths is a vulnerability.
- Canonicalize paths at the enforcement boundary. Be aware of TOCTOU race conditions with symlinks.
- Validate environment variables before use. Never assume `HOME`, `TMPDIR`, etc. are trustworthy.
- Escape and validate all data used in Seatbelt profile generation.

### Permission Scope (CRITICAL)
- Never grant access to entire directories when specific paths suffice.
- Separate read and write permissions explicitly.
- Configuration load failures must be fatal. If security lists fail to load, abort.

### Common Footguns
1. **String comparison for paths**: `path.starts_with("/home")` matches `/homeevil`. Use `Path::starts_with()`.
2. **Silent fallbacks**: `unwrap_or_default()` on security config returns empty permissions = no protection.
3. **Trusting resolved paths**: Symlinks can change between resolution and use.
4. **Platform differences**: macOS `/etc` is a symlink to `/private/etc`. Both must be considered.
5. **Overly broad permissions**: Granting `/tmp` read/write when only `/tmp/specific-file` is needed.
6. **Solving for one architecture**: Linux and macOS have different capabilities and threat models. Design must account for both. Develop abstractions that can be implemented securely on both platforms. Test on both platforms regularly to catch divergences.

## References

- [DESIGN-library.md](proj/DESIGN-library.md) - Library architecture, workspace layout, bindings
- [DESIGN-group-policy.md](proj/DESIGN-group-policy.md) - Group-based security policy, `never_grant`
- [DESIGN-supervisor.md](proj/DESIGN-supervisor.md) - Process model, execution strategies, supervisor IPC
- [DESIGN-undo-system.md](proj/DESIGN-undo-system.md) - Content-addressable snapshot system
- [Landlock docs](https://landlock.io/)
- [macOS Sandbox Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/)

<!-- GSD:project-start source:PROJECT.md -->
## Project

**nono - Windows Parity Milestone**

nono is a capability-based sandboxing system for running untrusted AI agents with OS-enforced isolation. This milestone focuses on bringing the Windows implementation to functional parity with Linux and macOS, specifically enabling supervisor capabilities for long-running agents and robust, kernel-level network enforcement via WFP.

**Core Value:** Windows security must be as structurally impossible and feature-complete as Unix platforms, ensuring the dangerous bits are kernel-enforced without compromising the supervisor-led security model.

### Constraints

- **Security**: Fail secure on any unsupported shape â€” never silently degrade.
- **Compatibility**: Must support Windows 10/11 (modern Job Objects and WFP).
- **Performance**: Zero startup latency must be maintained for the Windows backend.
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->
## Technology Stack

## Languages
- Rust 1.77 (Edition 2021) - Core library, CLI, and proxy implementation.
- Shell (Bash/Sh) - Integration tests and build scripts (`scripts/test-linux.sh`, `tests/run_integration_tests.sh`).
- PowerShell - Windows-specific build and test automation (`scripts/build-windows-msi.ps1`, `tests/windows-test-harness.ps1`).
- C - FFI bindings for the core library (`bindings/c/src/lib.rs`).
## Runtime
- Native binary (compiled for Linux, macOS, Windows).
- Minimum Rust version: 1.77 (bumped in Phase 04 plan 02 to support safer Windows service/WFP handle bindings via windows-sys 0.59).
- Cargo - Rust's package manager.
- Lockfile: `Cargo.lock` present.
## Frameworks
- `nono` - Internal capability-based sandboxing library.
- Rust's built-in test runner.
- `tempfile` - Temporary file management for tests.
- `proptest` - Property-based testing in `nono-cli`.
- `jsonschema` - Schema validation for manifests and capability files.
- `cbindgen` - C header generation from Rust code.
- `typify` - Rust type generation from JSON schema.
- `prettyplease` - Code formatting for generated code.
## Key Dependencies
- `tokio` (v1) - Asynchronous runtime for CLI and proxy.
- `hyper` (v1) - HTTP implementation for network filtering and update checks.
- `landlock` (v0.4) - Linux Landlock LSM bindings.
- `windows-sys` (v0.59) - Low-level Windows API bindings.
- `sigstore-rs` (`sigstore-verify`, `sigstore-sign`) - Attestation and verification.
- `serde` / `serde_json` / `toml` - Serialization and configuration handling.
- `tracing` / `tracing-subscriber` - Structured logging and diagnostics.
- `clap` (v4) - CLI argument parsing.
- `keyring` (v3) - Cross-platform system keystore access.
- `zeroize` - Secure memory clearing for sensitive data.
## Configuration
- Configured via environment variables (e.g., `NONO_LOG`, `NONO_NO_UPDATE_CHECK`, `NONO_UPDATE_URL`).
- Supports `env://` URI scheme for credentials in `crates/nono/src/keystore.rs`.
- `Cargo.toml` (workspace and crate-level).
- `Makefile` for high-level build orchestration.
- `Cross.toml` for cross-compilation.
## Platform Requirements
- Rust toolchain (1.74+).
- Platform-specific headers (libc, etc.).
- Linux: Kernel with Landlock support (5.13+).
- macOS: Recent macOS version (Seatbelt support).
- Windows: Windows 10/11 (WFP and Job Objects support).
- Standalone binaries for Linux (x86_64, aarch64), macOS (Intel/Apple Silicon), and Windows (x64).
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Naming Patterns
- Snake case: `capability.rs`, `net_filter.rs`, `cli_bootstrap.rs`.
- Platform-specific suffixes: `pty_proxy_windows.rs`, `session_commands_windows.rs`.
- Snake case: `allow_path()`, `block_network()`, `init_tracing()`.
- Factory methods: `new()`, `new_dir()`, `new_file()`.
- Conversion methods: `from_json()`, `to_json()`.
- Snake case: `caps`, `support`, `legacy_network_warnings`.
- Pascal case for Structs and Enums: `CapabilitySet`, `Sandbox`, `NonoError`, `AccessMode`.
- Type aliases: `pub type Result<T> = std::result::Result<T, NonoError>;`.
## Code Style
- `rustfmt`: Standard Rust formatting is enforced.
- Config: Managed by `cargo fmt --all`. No custom `.rustfmt.toml` detected, implying default settings.
- `clippy`: Used for static analysis.
- Strictness: CI runs with `-D warnings` (fail on any warning).
- Specific Rules: `-D clippy::unwrap_used` is enforced to prevent panics in production code.
- Exceptions: `#[allow(clippy::unwrap_used)]` is permitted in test modules and documentation examples.
## Import Organization
- Re-exports in `crates/nono/src/lib.rs` provide a flat public API for the core library.
## Error Handling
- Custom Error Enum: `NonoError` defined in `crates/nono/src/error.rs` using `thiserror`.
- Error Variants: Descriptive names with contextual data (e.g., `PathNotFound(PathBuf)`).
- Result Alias: `Result<T>` used throughout the codebase for brevity.
- Error Propagation: Use of the `?` operator is standard.
- User-facing errors: CLI commands return `nono::Result<()>` to main.
## Logging
- Initialization: Centralized in `crates/nono-cli/src/cli_bootstrap.rs` via `init_tracing()`.
- Verbosity: Controlled by CLI flags (`-v`, `-vv`, `-vvv`) or `RUST_LOG` environment variable.
- Silent Mode: `--silent` suppresses all logs (sets level to `off`).
- File Logging: Supported via `--log-file` path.
- Macro Usage: `error!`, `warn!`, `info!`, `debug!`, `trace!` from the `tracing` crate.
## Comments
- Public API documentation is mandatory.
- Complex logic within functions.
- Platform-specific implementation details (e.g., Landlock vs Seatbelt).
- Rust doc comments: `///` for items, `//!` for module/crate level documentation.
- Examples: Documentation often includes `fn main() -> nono::Result<()>` examples in `no_run` blocks.
## Function Design
## Module Design
- Explicit re-exports in `lib.rs`.
- Use of `pub(crate)` for internal logic not intended for the public API.
- `lib.rs` acts as the primary entry point for the library.
- `mod.rs` (or file-based modules) used to organize sub-modules.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## Pattern Overview
- **Platform-Agnostic Interface**: A unified library API (`nono`) that abstracts over platform-specific sandboxing mechanisms: Landlock (Linux), Seatbelt (macOS), and WFP/AppContainer concepts (Windows).
- **Supervised Execution**: A multi-process model where an unsandboxed supervisor process (`nono-cli`) monitors and mediates a sandboxed child process.
- **Explicit Capability Grants**: Security is based on positive allow-lists (capabilities) defined in a `CapabilitySet`.
- **Network Proxying & Credential Injection**: Outbound network traffic is intercepted by a local proxy (`nono-proxy`) to enforce domain-level filtering and securely inject API credentials without exposing them to the sandboxed environment.
- **State Integrity with Rollback**: Support for filesystem snapshots and Merkle-tree-based integrity verification to allow "undoing" changes made during a session.
## Layers
- Purpose: Provides low-level sandboxing primitives, capability models, and integrity engines.
- Location: `crates/nono/src/`
- Contains: Platform drivers (`sandbox/`), supervisor IPC primitives (`supervisor/`), and rollback logic (`undo/`).
- Depends on: `libc`, `nix` (non-Windows), `windows-sys` (Windows).
- Used by: `nono-cli`, `bindings/c`.
- Purpose: Entry point for users and agents; manages session lifecycle, policies, and UI.
- Location: `crates/nono-cli/src/`
- Contains: Execution strategies (`exec_strategy/`), command runtimes (`..._runtime.rs`), and profile management (`profile/`).
- Depends on: `nono`, `nono-proxy`, `clap`, `tracing`.
- Purpose: Intercepts and filters network traffic from sandboxed processes.
- Location: `crates/nono-proxy/src/`
- Contains: Proxy server (`server.rs`), credential injection (`credential.rs`), and host filtering (`filter.rs`).
- Depends on: `tokio`, `h2`, `rustls`.
- Used by: `nono-cli`.
- Purpose: Exposes the core library to C/C++ and other languages.
- Location: `bindings/c/`
- Contains: FFI wrappers and header generation (`cbindgen`).
## Data Flow
## Key Abstractions
- Purpose: Encapsulates the platform-specific logic for applying restrictions.
- Examples: `crates/nono/src/sandbox/mod.rs`.
- Pattern: Strategy Pattern.
- Purpose: A portable representation of allowed resources.
- Examples: `crates/nono/src/capability.rs`.
- Purpose: Defines how the sandboxed process is launched and monitored.
- Examples: `crates/nono-cli/src/exec_strategy.rs` (Unix), `crates/nono-cli/src/exec_strategy_windows/mod.rs` (Windows).
## Entry Points
- Location: `crates/nono-cli/src/main.rs`
- Responsibilities: Bootstrap, logging, and dispatching to `app_runtime`.
- Location: `crates/nono/src/lib.rs`
- Responsibilities: Public interface for embedding sandboxing in other Rust apps.
## Error Handling
- `nono::NonoError`: Central error enum for the core library.
- `nono_proxy::ProxyError`: Errors specific to network interception.
- `DiagnosticFormatter`: Generates human-readable explanations for sandbox denials (`crates/nono/src/diagnostic.rs`).
## Cross-Cutting Concerns
<!-- GSD:architecture-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd:quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd:debug` for investigation and bug fixing
- `/gsd:execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd:profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
