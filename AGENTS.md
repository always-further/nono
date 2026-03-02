# Agent Guide: nono

This repository contains the `nono` project, a capability-based sandboxing system for running untrusted AI agents.
It is a Cargo workspace with three members:
- `crates/nono` (core library): Pure sandbox primitive.
- `crates/nono-cli` (CLI binary): Owns security policy, profiles, and UX.
- `bindings/c` (C FFI): C bindings.

## Build, Test, and Lint Commands

### Primary Commands
Use the `Makefile` for standard workflows:

- **Build All**: `make build`
- **Test All**: `make test`
- **Lint & Format**: `make check` (runs clippy + fmt check)
- **CI Simulation**: `make ci` (runs check + test)

### Component-Specific Targets
- **Library**: `make build-lib` / `make test-lib`
- **CLI**: `make build-cli` / `make test-cli`
- **FFI**: `make build-ffi` / `make test-ffi`

### Running a Single Test
To run a specific test case, use `cargo test` directly:

```bash
# Run a specific test in the library
cargo test -p nono -- test_function_name

# Run a specific test in the CLI
cargo test -p nono-cli -- test_function_name

# Run a test and show stdout (useful for debugging)
cargo test -p nono -- test_function_name --nocapture
```

## Code Style & Standards

### Formatting & Linting
- **Strict Clippy**: We enforce `clippy::unwrap_used`. **NEVER** use `.unwrap()` or `.expect()`.
- **Formatting**: Run `make fmt` to apply standard Rust formatting.
- **Imports**: Group imports by crate (std, external, internal).

### Error Handling
- **No Panics**: Libraries should almost never panic. Use `Result` for all error conditions.
- **Error Type**: Use `NonoError` for all errors. Propagate using `?`.
- **Must Use**: Apply `#[must_use]` to functions returning critical `Result`s.

### Naming Conventions
- **Types/Traits**: `PascalCase` (e.g., `SandboxState`, `CapabilitySet`).
- **Functions/Variables**: `snake_case` (e.g., `apply_sandbox`, `is_supported`).
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_PATH_LENGTH`).

## Security Mandates (CRITICAL)

**SECURITY IS NON-NEGOTIABLE.** Every change must be evaluated through a security lens.

### Path Handling
- **Canonicalization**: Always canonicalize paths at the enforcement boundary.
- **Comparison**: Use `Path::components()` or `Path::starts_with()`.
  - **NEVER** use string operations like `str::starts_with()` for paths (vulnerable to `/home` vs `/homeevil`).
- **Symlinks**: Be aware of TOCTOU (Time-of-Check Time-of-Use) race conditions.

### Memory & Arithmetic
- **Secrets**: Use the `zeroize` crate for sensitive data (keys/passwords) in memory.
- **Math**: Use `checked_`, `saturating_`, or `overflowing_` methods for security-critical arithmetic.

### Safe Code
- **Unsafe**: Restrict `unsafe` code to FFI modules only.
- **Documentation**: All `unsafe` blocks must be wrapped in `// SAFETY:` comments explaining why it is safe.

### Principles
- **Least Privilege**: Only grant the minimum necessary capabilities.
- **Fail Secure**: On any error, deny access. Never silently degrade to a less secure state.
- **Explicit Over Implicit**: Security-relevant behavior must be explicit and auditable.

## Usage Example (Library)

The core library (`crates/nono`) provides the sandbox primitive. Clients must construct a `CapabilitySet` and apply it.

```rust
use nono::{CapabilitySet, AccessMode, Sandbox};

fn main() -> nono::Result<()> {
    // Build capability set - client must add ALL paths
    let caps = CapabilitySet::new()
        .allow_path("/usr", AccessMode::Read)?
        .allow_path("/project", AccessMode::ReadWrite)?
        .block_network();

    // Check platform support
    let support = Sandbox::support_info();
    if !support.is_supported {
        eprintln!("Warning: {}", support.details);
    }

    // Apply sandbox - this is irreversible
    Sandbox::apply(&caps)?;
    
    Ok(())
}
```

## Implementation Guidelines

### Library vs CLI
- **Library (`crates/nono`)**: Policy-free. Applies *only* what is in `CapabilitySet`.
- **CLI (`crates/nono-cli`)**: Defines policy (deny rules, sensitive paths).

### Platform Specifics
- **Linux (Landlock)**: Strictly allow-list. Cannot express deny-within-allow.
- **macOS (Seatbelt)**: Scheme-like DSL. Supports explicit deny rules.
- **Cross-Platform**: Design abstractions that work securely on both. Test on both if possible.

### Common Pitfalls to Avoid
1. **Silent Fallbacks**: `unwrap_or_default()` on security config returns empty permissions (no protection). Fail hard instead.
2. **Broad Permissions**: Do not grant access to entire directories when specific paths suffice.
3. **Environment Variables**: Validate `HOME`, `TMPDIR`, etc. before use. Do not assume they are trustworthy.
4. **Dead Code**: Avoid `#[allow(dead_code)]`. Remove unused code or write tests for it.

## Testing Strategy
When writing tests for new capabilities:
1.  **Unit Tests**: Verify the logic of `CapabilitySet` construction.
2.  **Integration Tests**: Use `tests/` directory to run actual sandbox enforcement checks.
3.  **Platform Checks**: Use `#[cfg(target_os = "linux")]` or `#[cfg(target_os = "macos")]` if the test is platform-specific.

## Quick Reference
- **Check code quality**: `make clippy`
- **Fix formatting**: `make fmt`
- **Run all tests**: `make test`
