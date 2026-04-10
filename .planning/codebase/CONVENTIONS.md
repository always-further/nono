# Coding Conventions

**Analysis Date:** 2025-04-05

## Naming Patterns

**Files:**
- Snake case: `capability.rs`, `net_filter.rs`, `cli_bootstrap.rs`.
- Platform-specific suffixes: `pty_proxy_windows.rs`, `session_commands_windows.rs`.

**Functions:**
- Snake case: `allow_path()`, `block_network()`, `init_tracing()`.
- Factory methods: `new()`, `new_dir()`, `new_file()`.
- Conversion methods: `from_json()`, `to_json()`.

**Variables:**
- Snake case: `caps`, `support`, `legacy_network_warnings`.

**Types:**
- Pascal case for Structs and Enums: `CapabilitySet`, `Sandbox`, `NonoError`, `AccessMode`.
- Type aliases: `pub type Result<T> = std::result::Result<T, NonoError>;`.

## Code Style

**Formatting:**
- `rustfmt`: Standard Rust formatting is enforced.
- Config: Managed by `cargo fmt --all`. No custom `.rustfmt.toml` detected, implying default settings.

**Linting:**
- `clippy`: Used for static analysis.
- Strictness: CI runs with `-D warnings` (fail on any warning).
- Specific Rules: `-D clippy::unwrap_used` is enforced to prevent panics in production code.
- Exceptions: `#[allow(clippy::unwrap_used)]` is permitted in test modules and documentation examples.

## Import Organization

**Order:**
1. Standard library (`std::...`)
2. External crates (`thiserror`, `serde`, `tokio`)
3. Workspace crates (`nono::...`)
4. Module-local imports (`use crate::...`, `mod ...`)

**Path Aliases:**
- Re-exports in `crates/nono/src/lib.rs` provide a flat public API for the core library.

## Error Handling

**Patterns:**
- Custom Error Enum: `NonoError` defined in `crates/nono/src/error.rs` using `thiserror`.
- Error Variants: Descriptive names with contextual data (e.g., `PathNotFound(PathBuf)`).
- Result Alias: `Result<T>` used throughout the codebase for brevity.
- Error Propagation: Use of the `?` operator is standard.
- User-facing errors: CLI commands return `nono::Result<()>` to main.

## Logging

**Framework:** `tracing` with `tracing-subscriber`.

**Patterns:**
- Initialization: Centralized in `crates/nono-cli/src/cli_bootstrap.rs` via `init_tracing()`.
- Verbosity: Controlled by CLI flags (`-v`, `-vv`, `-vvv`) or `RUST_LOG` environment variable.
- Silent Mode: `--silent` suppresses all logs (sets level to `off`).
- File Logging: Supported via `--log-file` path.
- Macro Usage: `error!`, `warn!`, `info!`, `debug!`, `trace!` from the `tracing` crate.

## Comments

**When to Comment:**
- Public API documentation is mandatory.
- Complex logic within functions.
- Platform-specific implementation details (e.g., Landlock vs Seatbelt).

**JSDoc/TSDoc:**
- Rust doc comments: `///` for items, `//!` for module/crate level documentation.
- Examples: Documentation often includes `fn main() -> nono::Result<()>` examples in `no_run` blocks.

## Function Design

**Size:** Functions are generally focused and modular.

**Parameters:** Use of the builder pattern for complex configuration (e.g., `CapabilitySet`).

**Return Values:** Almost always returns `Result<T>` to handle potential failures gracefully.

## Module Design

**Exports:**
- Explicit re-exports in `lib.rs`.
- Use of `pub(crate)` for internal logic not intended for the public API.

**Barrel Files:**
- `lib.rs` acts as the primary entry point for the library.
- `mod.rs` (or file-based modules) used to organize sub-modules.

---

*Convention analysis: 2025-04-05*
