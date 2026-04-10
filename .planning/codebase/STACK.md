# Technology Stack

**Analysis Date:** 2026-04-04

## Languages

**Primary:**
- Rust 1.77 (Edition 2021) - Core library, CLI, and proxy implementation.

**Secondary:**
- Shell (Bash/Sh) - Integration tests and build scripts (`scripts/test-linux.sh`, `tests/run_integration_tests.sh`).
- PowerShell - Windows-specific build and test automation (`scripts/build-windows-msi.ps1`, `tests/windows-test-harness.ps1`).
- C - FFI bindings for the core library (`bindings/c/src/lib.rs`).

## Runtime

**Environment:**
- Native binary (compiled for Linux, macOS, Windows).
- Minimum Rust version: 1.77 (bumped in Phase 04 plan 02 for safer Windows service/WFP handle bindings).

**Package Manager:**
- Cargo - Rust's package manager.
- Lockfile: `Cargo.lock` present.

## Frameworks

**Core:**
- `nono` - Internal capability-based sandboxing library.

**Testing:**
- Rust's built-in test runner.
- `tempfile` - Temporary file management for tests.
- `proptest` - Property-based testing in `nono-cli`.
- `jsonschema` - Schema validation for manifests and capability files.

**Build/Dev:**
- `cbindgen` - C header generation from Rust code.
- `typify` - Rust type generation from JSON schema.
- `prettyplease` - Code formatting for generated code.

## Key Dependencies

**Critical:**
- `tokio` (v1) - Asynchronous runtime for CLI and proxy.
- `hyper` (v1) - HTTP implementation for network filtering and update checks.
- `landlock` (v0.4) - Linux Landlock LSM bindings.
- `windows-sys` (v0.59) - Low-level Windows API bindings.
- `sigstore-rs` (`sigstore-verify`, `sigstore-sign`) - Attestation and verification.

**Infrastructure:**
- `serde` / `serde_json` / `toml` - Serialization and configuration handling.
- `tracing` / `tracing-subscriber` - Structured logging and diagnostics.
- `clap` (v4) - CLI argument parsing.
- `keyring` (v3) - Cross-platform system keystore access.
- `zeroize` - Secure memory clearing for sensitive data.

## Configuration

**Environment:**
- Configured via environment variables (e.g., `NONO_LOG`, `NONO_NO_UPDATE_CHECK`, `NONO_UPDATE_URL`).
- Supports `env://` URI scheme for credentials in `crates/nono/src/keystore.rs`.

**Build:**
- `Cargo.toml` (workspace and crate-level).
- `Makefile` for high-level build orchestration.
- `Cross.toml` for cross-compilation.

## Platform Requirements

**Development:**
- Rust toolchain (1.74+).
- Platform-specific headers (libc, etc.).
- Linux: Kernel with Landlock support (5.13+).
- macOS: Recent macOS version (Seatbelt support).
- Windows: Windows 10/11 (WFP and Job Objects support).

**Production:**
- Standalone binaries for Linux (x86_64, aarch64), macOS (Intel/Apple Silicon), and Windows (x64).

---

*Stack analysis: 2026-04-04*
